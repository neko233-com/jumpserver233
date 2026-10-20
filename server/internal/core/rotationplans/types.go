package rotationplans

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
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
const MaxSaveReceipts = 10000
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
	Protocol          string `json:"protocol,omitempty"`
	Platform          string `json:"platform,omitempty"`
	AccountHost       string `json:"account_host,omitempty"`
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
	FixedPassword  string                 `json:"-"` // supplied only to the trusted executor, never persisted here
	FixedSecretID  string                 `json:"fixed_secret_id,omitempty"`
	PasswordPolicy credentialpolicy.Rules `json:"password_policy,omitzero"`
	Origin         accesspolicies.Origin  `json:"origin,omitempty"`
	RequestID      string                 `json:"request_id"`
	Actor          Actor                  `json:"actor"`
	Target         Prepared               `json:"target"`
}
type Outcome struct {
	CheckDurationMS int64     `json:"check_duration_ms,omitempty"`
	State           string    `json:"state"` // succeeded, failed, recovery_required, not_started, changed
	Code            string    `json:"error_code,omitempty"`
	Revision        uint64    `json:"revision,omitempty"`
	At              time.Time `json:"at,omitzero"`
}
type PlanInput struct {
	CheckEnabled       bool                   `json:"check_enabled,omitempty"`
	CheckIntervalHours int                    `json:"check_interval_hours,omitempty"`
	PasswordMode       string                 `json:"password_mode,omitempty"` // generated (default), fixed
	PasswordPolicy     credentialpolicy.Rules `json:"password_policy,omitzero"`
	Origin             accesspolicies.Origin  `json:"-"`
	Name               string                 `json:"name"`
	Targets            []Selection            `json:"targets,omitempty"`
	Kind               string                 `json:"kind"` // manual, once, interval
	Enabled            bool                   `json:"enabled"`
	RunAt              time.Time              `json:"run_at,omitzero"`
	IntervalHours      int                    `json:"interval_hours,omitempty"`
	OnlyDue            bool                   `json:"only_due"`
	Revision           int                    `json:"revision"`
}

// SaveInput is request-only. Public Plan/Run DTOs never embed this type.
type SaveInput struct {
	PlanInput
	RequestID     string `json:"request_id,omitempty"`
	FixedPassword string `json:"fixed_password,omitempty"`
}
type Plan struct {
	NextCheck      time.Time             `json:"next_check,omitzero"`
	LastCheckRunID string                `json:"last_check_run_id,omitempty"`
	CheckErrorCode string                `json:"check_error_code,omitempty"`
	SaveRequestID  string                `json:"save_request_id,omitempty"`
	TargetCount    int                   `json:"target_count"`
	AccessOrigin   accesspolicies.Origin `json:"access_origin,omitempty"`
	ID             string                `json:"id"`
	Actor          Actor                 `json:"owner"`
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
	CheckDurationMS int64     `json:"check_duration_ms,omitempty"`
	SourceItemID    string    `json:"source_item_id,omitempty"`
	RetryRunID      string    `json:"retry_run_id,omitempty"`
	ID              string    `json:"id"`
	State           string    `json:"state"`
	ErrorCode       string    `json:"error_code,omitempty"`
	LinkedTo        string    `json:"linked_to,omitempty"`
	BeforeRevision  uint64    `json:"before_revision"`
	AfterRevision   uint64    `json:"after_revision,omitempty"`
	StartedAt       time.Time `json:"started_at,omitzero"`
	FinishedAt      time.Time `json:"finished_at,omitzero"`
}
type Run struct {
	Operation      string                 `json:"operation,omitempty"` // empty means rotation; check authenticates only
	ParentRunID    string                 `json:"parent_run_id,omitempty"`
	RetryItemIDs   []string               `json:"retry_item_ids,omitempty"`
	RetryAll       bool                   `json:"retry_all,omitempty"`
	PasswordMode   string                 `json:"password_mode,omitempty"`
	PasswordPolicy credentialpolicy.Rules `json:"password_policy,omitzero"`
	AccessOrigin   accesspolicies.Origin  `json:"access_origin,omitempty"`
	ID             string                 `json:"id"`
	PlanID         string                 `json:"plan_id"`
	PlanRevision   int                    `json:"plan_revision"`
	Name           string                 `json:"name"`
	Actor          Actor                  `json:"owner"`
	RequestID      string                 `json:"request_id"`
	Scheduled      bool                   `json:"scheduled"`
	Cancelled      bool                   `json:"cancelled"`
	State          string                 `json:"state"`
	CreatedAt      time.Time              `json:"created_at"`
	FinishedAt     time.Time              `json:"finished_at,omitzero"`
	Items          []Item                 `json:"items"`
}
type Audit struct {
	ParentRunID string                `json:"parent_run_id,omitempty"`
	RequestID   string                `json:"request_id,omitempty"`
	Origin      accesspolicies.Origin `json:"access_origin,omitempty"`
	At          time.Time             `json:"at"`
	Actor       Actor                 `json:"actor"`
	Action      string                `json:"action"`
	PlanID      string                `json:"plan_id"`
	RunID       string                `json:"run_id,omitempty"`
	Revision    int                   `json:"revision,omitempty"`
}

// RetryInput starts a new, linked run using an explicitly observed plan revision.
// Empty ItemIDs selects every remaining retryable item; aliases expand together.
type RetryInput struct {
	RequestID    string   `json:"request_id"`
	PlanRevision int      `json:"plan_revision"`
	ItemIDs      []string `json:"item_ids,omitempty"`
}

func RetryableItem(state string) bool {
	return state == "failed" || state == "denied" || state == "changed" || state == "cancelled" || state == "interrupted"
}

type RunSummary struct {
	Run
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
	Skipped   int `json:"skipped"`
}
type Runner struct {
	Check            func(context.Context, Intent, func() error) (Outcome, error)
	AuthorizeCheck   func(Actor) error
	AuthorizeTargets func(Actor, []Selection) error
	AuthorizeFixed   func(Actor) error
	Prepare          func(context.Context, Actor, []Selection) ([]Prepared, error)
	Execute          func(context.Context, Intent, func() error) (Outcome, error)
	Inspect          func(context.Context, Intent) (Outcome, error)
	Authorize        func(Actor) error
	Recover          func(context.Context, Intent, Actor, func() error) (Outcome, error)
}

func (r Runner) authorizeTargets(a Actor, selected []Selection) error {
	if r.AuthorizeTargets != nil {
		return r.AuthorizeTargets(a, selected)
	}
	return nil
}

func (r Runner) authorizeMode(a Actor, mode string) error {
	if r.Authorize == nil {
		return ErrBusy
	}
	if e := r.Authorize(a); e != nil {
		return e
	}
	if mode == "fixed" {
		if r.AuthorizeFixed == nil {
			return ErrDenied
		}
		return r.AuthorizeFixed(a)
	}
	return nil
}

func validPasswordMode(mode string) bool { return mode == "" || mode == "generated" || mode == "fixed" }

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
	if in.CheckIntervalHours < 0 || in.CheckIntervalHours > 720 || in.CheckEnabled && in.CheckIntervalHours < 1 {
		return ErrInvalid
	}
	if !validPasswordMode(in.PasswordMode) {
		return ErrInvalid
	}
	if !in.PasswordPolicy.OptionalValid() {
		return ErrInvalid
	}
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
