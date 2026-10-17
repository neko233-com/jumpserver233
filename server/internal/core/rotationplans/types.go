package rotationplans

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid  = errors.New("invalid credential rotation plan")
	ErrNotFound = errors.New("credential rotation plan not found")
	ErrConflict = errors.New("credential rotation plan changed")
	ErrDenied   = errors.New("credential rotation permission denied")
	ErrCapacity = errors.New("credential rotation capacity reached")
	ErrBusy     = errors.New("credential rotation is active")
)

const MaxTargets = 500
const MaxPlans = 256
const MaxRuns = 512
const MaxAudit = 10000
const maxStateBytes = 64 << 20

var IDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Selection struct {
	AccountID   string `json:"account_id"`
	CollectorID string `json:"collector_id,omitempty"`
}
type Ref struct {
	AssetID           string `json:"asset_id"`
	AccountID         string `json:"account_id"`
	AssetName         string `json:"asset_name"`
	Username          string `json:"username"`
	CredentialType    string `json:"credential_type"`
	CollectorID       string `json:"collector_id,omitempty"`
	CollectorUsername string `json:"collector_username,omitempty"`
}

// Prepared never crosses an HTTP or CLI boundary. Its group and binding are
// opaque, organization-keyed markers; it contains no target credentials.
type Prepared struct {
	Ref
	Version   string
	Revision  uint64
	Binding   string
	Group     string
	RotatedAt time.Time
}
type Intent struct {
	Origin    accesspolicies.Origin `json:"origin,omitempty"`
	RequestID string                `json:"request_id"`
	Actor     Actor                 `json:"actor"`
	Target    Prepared              `json:"target"`
}
type Outcome struct {
	State    string    `json:"state"` // succeeded, failed, recovery_required, not_started, changed
	Code     string    `json:"error_code,omitempty"`
	Revision uint64    `json:"revision,omitempty"`
	At       time.Time `json:"at,omitzero"`
}
type PlanInput struct {
	Origin        accesspolicies.Origin `json:"-"`
	Name          string                `json:"name"`
	Targets       []Selection           `json:"targets,omitempty"`
	Kind          string                `json:"kind"` // manual, once, interval
	Enabled       bool                  `json:"enabled"`
	RunAt         time.Time             `json:"run_at,omitzero"`
	IntervalHours int                   `json:"interval_hours,omitempty"`
	OnlyDue       bool                  `json:"only_due"`
	Revision      int                   `json:"revision"`
}
type Plan struct {
	TargetCount  int                   `json:"target_count"`
	AccessOrigin accesspolicies.Origin `json:"access_origin,omitempty"`
	ID           string                `json:"id"`
	Actor        Actor                 `json:"owner"`
	PlanInput
	Refs      []Ref     `json:"accounts"`
	NextRun   time.Time `json:"next_run,omitzero"`
	LastRunID string    `json:"last_run_id,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Item struct {
	Ref
	ID             string    `json:"id"`
	State          string    `json:"state"`
	ErrorCode      string    `json:"error_code,omitempty"`
	LinkedTo       string    `json:"linked_to,omitempty"`
	BeforeRevision uint64    `json:"before_revision"`
	AfterRevision  uint64    `json:"after_revision,omitempty"`
	StartedAt      time.Time `json:"started_at,omitzero"`
	FinishedAt     time.Time `json:"finished_at,omitzero"`
}
type Run struct {
	AccessOrigin accesspolicies.Origin `json:"access_origin,omitempty"`
	ID           string                `json:"id"`
	PlanID       string                `json:"plan_id"`
	PlanRevision int                   `json:"plan_revision"`
	Name         string                `json:"name"`
	Actor        Actor                 `json:"owner"`
	RequestID    string                `json:"request_id"`
	Scheduled    bool                  `json:"scheduled"`
	Cancelled    bool                  `json:"cancelled"`
	State        string                `json:"state"`
	CreatedAt    time.Time             `json:"created_at"`
	FinishedAt   time.Time             `json:"finished_at,omitzero"`
	Items        []Item                `json:"items"`
}
type Audit struct {
	Origin   accesspolicies.Origin `json:"access_origin,omitempty"`
	At       time.Time             `json:"at"`
	Actor    Actor                 `json:"actor"`
	Action   string                `json:"action"`
	PlanID   string                `json:"plan_id"`
	RunID    string                `json:"run_id,omitempty"`
	Revision int                   `json:"revision,omitempty"`
}
type RunSummary struct {
	Run
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
}
type Runner struct {
	Prepare   func(context.Context, Actor, []Selection) ([]Prepared, error)
	Execute   func(context.Context, Intent, func() error) (Outcome, error)
	Inspect   func(context.Context, Intent) (Outcome, error)
	Authorize func(Actor) error
	Recover   func(context.Context, Intent, Actor, func() error) (Outcome, error)
}

func ValidActor(a Actor) bool {
	return IDPattern.MatchString(a.ID) && validText(a.Name, 128) && a.Name != ""
}
func validText(s string, n int) bool {
	if len(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func (in PlanInput) Validate() error {
	if !validText(in.Name, 240) || in.Name == "" || in.Revision < 0 || in.Revision > 1<<53-1 || len(in.Targets) < 1 || len(in.Targets) > MaxTargets {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, v := range in.Targets {
		if !IDPattern.MatchString(v.AccountID) || v.CollectorID != "" && !IDPattern.MatchString(v.CollectorID) || seen[v.AccountID] {
			return ErrInvalid
		}
		seen[v.AccountID] = true
	}
	switch in.Kind {
	case "manual":
		if in.Enabled || !in.RunAt.IsZero() || in.IntervalHours != 0 || in.OnlyDue {
			return ErrInvalid
		}
	case "once":
		if in.RunAt.IsZero() || in.IntervalHours != 0 || in.OnlyDue {
			return ErrInvalid
		}
	case "interval":
		if !in.RunAt.IsZero() || in.IntervalHours < 1 || in.IntervalHours > 8760 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
