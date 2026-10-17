package accountrisks

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid  = errors.New("invalid account risk input")
	ErrConflict = errors.New("account risk state changed")
	ErrNotFound = errors.New("account risk record not found")
	ErrDenied   = errors.New("account risk access denied")
	ErrBusy     = errors.New("account risk scan is busy")
	ErrCapacity = errors.New("account risk capacity reached")
)

const MaxAccounts = 10000
const maxFindings = 70000
const maxScans = 256
const maxAudit = 10000
const maxStateBytes = 64 << 20

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var kinds = []string{"weak_password", "duplicate_password", "reused_key", "stale_credential", "unused_account", "rotation_disabled", "pending_credential"}

type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Policy struct {
	Revision              int       `json:"revision"`
	Enabled               bool      `json:"enabled"`
	IntervalHours         int       `json:"interval_hours"`
	MinPasswordLength     int       `json:"min_password_length"`
	MaxCredentialAgeDays  int       `json:"max_credential_age_days"`
	UnusedAccountDays     int       `json:"unused_account_days"`
	ResolvedRetentionDays int       `json:"resolved_retention_days"`
	AuditRetentionDays    int       `json:"audit_retention_days"`
	IncludeDisabled       bool      `json:"include_disabled"`
	Checks                []string  `json:"checks"`
	Owner                 Actor     `json:"owner"`
	NextRun               time.Time `json:"next_run,omitzero"`
	LastError             string    `json:"last_error,omitempty"`
}

func DefaultPolicy() Policy {
	return Policy{Revision: 1, IntervalHours: 24, MinPasswordLength: 14, MaxCredentialAgeDays: 7, UnusedAccountDays: 90, ResolvedRetentionDays: 90, AuditRetentionDays: 365, Checks: append([]string(nil), kinds...)}
}
func (p Policy) Validate() error {
	if p.ResolvedRetentionDays < 1 || p.ResolvedRetentionDays > 3650 || p.AuditRetentionDays < 30 || p.AuditRetentionDays > 3650 {
		return ErrInvalid
	}
	if p.Revision < 1 || p.Revision > 1<<53-1 || p.IntervalHours < 1 || p.IntervalHours > 720 || p.MinPasswordLength < 8 || p.MinPasswordLength > 128 || p.MaxCredentialAgeDays < 1 || p.MaxCredentialAgeDays > 3650 || p.UnusedAccountDays < 1 || p.UnusedAccountDays > 3650 || len(p.Checks) == 0 || len(p.Checks) > len(kinds) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, k := range p.Checks {
		if !slices.Contains(kinds, k) || seen[k] {
			return ErrInvalid
		}
		seen[k] = true
	}
	if p.Enabled && !validActor(p.Owner) {
		return ErrInvalid
	}
	return nil
}
func (p Policy) Has(kind string) bool { return slices.Contains(p.Checks, kind) }

type Ref struct {
	AssetID   string `json:"asset_id"`
	AccountID string `json:"account_id"`
	AssetName string `json:"asset_name"`
	Username  string `json:"username"`
}

// Observations stay inside the server; credential bytes never cross this boundary.
// Opaque group markers are encrypted at rest and omitted from public findings.
type Check struct {
	Kind     string   `json:"kind"`
	Severity string   `json:"severity"`
	Reasons  []string `json:"reasons"`
	GroupID  string   `json:"group_id,omitempty"`
}
type Observation struct {
	Ref
	Identity       string    `json:"identity"`
	CredentialType string    `json:"credential_type"`
	Active         bool      `json:"active"`
	CreatedAt      time.Time `json:"created_at"`
	RotatedAt      time.Time `json:"rotated_at"`
	LastUsedAt     time.Time `json:"last_used_at,omitzero"`
	SourceVersion  string    `json:"source_version"`
	Binding        string    `json:"binding"`
	Checks         []Check   `json:"checks"`
}
type Member struct {
	Ref
	Identity string `json:"identity"`
}
type Usage struct {
	Identity string    `json:"identity"`
	At       time.Time `json:"at"`
}
type Snapshot struct {
	Accounts []Observation
	Groups   map[string][]Member
}

// Collector holds its source read lock until commit finishes, so a scan cannot
// publish findings for a credential replaced during evaluation.
type Collector func(context.Context, Actor, Policy, time.Time, func(Snapshot) error) error

// Authority locks current permission publication until the returned release
// function is called. It never trusts a persisted role snapshot.
type Authority func(Actor) (func(), error)
type Finding struct {
	Ref
	ID             string    `json:"id"`
	Kind           string    `json:"kind"`
	Severity       string    `json:"severity"`
	Reasons        []string  `json:"reasons"`
	CredentialType string    `json:"credential_type"`
	Active         bool      `json:"active"`
	SourceVersion  string    `json:"source_version"`
	PolicyRevision int       `json:"policy_revision"`
	Revision       int       `json:"revision"`
	State          string    `json:"state"`
	Note           string    `json:"note"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	ResolvedAt     time.Time `json:"resolved_at,omitzero"`
	LastUsedAt     time.Time `json:"last_used_at,omitzero"`
	RotatedAt      time.Time `json:"rotated_at"`
	Occurrences    int       `json:"occurrences"`
	PeerCount      int       `json:"peer_count"`
	Peers          []Ref     `json:"peers"`
	Outdated       bool      `json:"outdated"`
}
type entry struct {
	Finding
	Identity string `json:"identity"`
	Binding  string `json:"binding"`
	GroupID  string `json:"group_id,omitempty"`
}
type Scan struct {
	ID             string    `json:"id"`
	RequestID      string    `json:"request_id"`
	Actor          Actor     `json:"actor"`
	PolicyRevision int       `json:"policy_revision"`
	State          string    `json:"state"`
	ErrorCode      string    `json:"error_code,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at,omitzero"`
	Accounts       int       `json:"accounts"`
	Open           int       `json:"open"`
	Resolved       int       `json:"resolved"`
}
type Audit struct {
	At        time.Time `json:"at"`
	Actor     Actor     `json:"actor"`
	Action    string    `json:"action"`
	FindingID string    `json:"finding_id,omitempty"`
	Before    string    `json:"before,omitempty"`
	After     string    `json:"after,omitempty"`
	ScanID    string    `json:"scan_id,omitempty"`
}
type Query struct {
	State, Kind, AssetID, Search string
	Offset, Limit                int
}
type Page struct {
	Results []Finding `json:"results"`
	Total   int       `json:"total"`
}

func validText(s string, n int) bool {
	if len(s) > n || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return false
		}
	}
	return true
}
func validActor(a Actor) bool {
	return idPattern.MatchString(a.ID) && a.Name != "" && validText(a.Name, 128)
}
func validRef(r Ref) bool {
	return idPattern.MatchString(r.AssetID) && idPattern.MatchString(r.AccountID) && r.Username != "" && validText(r.Username, 128) && validText(r.AssetName, 480)
}
