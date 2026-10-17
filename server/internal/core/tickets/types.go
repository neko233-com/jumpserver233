package tickets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("invalid access ticket")
	ErrNotFound    = errors.New("access ticket not found")
	ErrConflict    = errors.New("access ticket revision changed")
	ErrDenied      = errors.New("access ticket permission denied")
	ErrCapacity    = errors.New("access ticket capacity reached")
	ErrUnavailable = errors.New("access ticket service unavailable")
	ErrStale       = errors.New("access ticket source changed")
	ErrReviewers   = errors.New("no distinct reviewers are currently available")
)

const (
	MaxPolicies   = 256
	MaxTickets    = 2000
	MaxAudit      = 20000
	MaxTargets    = 50
	maxStateBytes = 64 << 20
)

var IDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Subject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}
type Principal struct {
	Actor
	Subjects                                     []Subject
	CanPublish, CanReview, CanViewAll, CanRevoke bool
}
type Stage struct {
	Name     string    `json:"name"`
	Subjects []Subject `json:"subjects"`
}
type Scope struct {
	Kind     string   `json:"kind"`
	ID       string   `json:"id"`
	Accounts []string `json:"accounts"`
	Actions  []string `json:"actions"`
}
type PolicyInput struct {
	Name               string    `json:"name"`
	Description        string    `json:"description"`
	Enabled            bool      `json:"enabled"`
	AllMembers         bool      `json:"all_members"`
	Requesters         []Subject `json:"requesters"`
	CC                 []Subject `json:"cc"`
	Stages             []Stage   `json:"stages"`
	Scopes             []Scope   `json:"scopes"`
	MaxDurationMinutes int       `json:"max_duration_minutes"`
	ApprovalTTLMinutes int       `json:"approval_ttl_minutes"`
	Revision           int       `json:"revision"`
}
type Policy struct {
	PolicyInput
	ID        string    `json:"id"`
	Publisher Actor     `json:"publisher"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Target struct {
	Kind    string   `json:"kind"`
	ID      string   `json:"id"`
	Account string   `json:"account"`
	Actions []string `json:"actions"`
}
type Ref struct {
	Target
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}
type Prepared struct {
	Ref
	Binding string
	Nodes   []string
}
type SubmitInput struct {
	PolicyRevision int       `json:"policy_revision"`
	Name           string    `json:"name"`
	PolicyID       string    `json:"policy_id"`
	RequestID      string    `json:"request_id"`
	Reason         string    `json:"reason"`
	Targets        []Target  `json:"targets"`
	StartsAt       time.Time `json:"starts_at"`
	EndsAt         time.Time `json:"ends_at"`
}
type Amendment struct {
	Revision int       `json:"revision"`
	Reason   string    `json:"reason"`
	Targets  []Target  `json:"targets"`
	StartsAt time.Time `json:"starts_at"`
	EndsAt   time.Time `json:"ends_at"`
}
type Approval struct {
	Stage   int       `json:"stage"`
	Actor   Actor     `json:"actor"`
	At      time.Time `json:"at"`
	Comment string    `json:"comment"`
}
type Comment struct {
	Actor Actor     `json:"actor"`
	At    time.Time `json:"at"`
	Text  string    `json:"text"`
}
type Ticket struct {
	Outdated          bool       `json:"outdated"`
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Owner             Actor      `json:"owner"`
	Publisher         Actor      `json:"publisher"`
	PolicyID          string     `json:"policy_id"`
	PolicyRevision    int        `json:"policy_revision"`
	PolicyName        string     `json:"policy_name"`
	Stages            []Stage    `json:"stages"`
	CC                []Subject  `json:"cc"`
	Reason            string     `json:"reason"`
	Targets           []Ref      `json:"targets"`
	StartsAt          time.Time  `json:"starts_at"`
	EndsAt            time.Time  `json:"ends_at"`
	ApprovalExpiresAt time.Time  `json:"approval_expires_at"`
	State             string     `json:"state"`
	Revision          int        `json:"revision"`
	CurrentStage      int        `json:"current_stage"`
	Approvals         []Approval `json:"approvals"`
	Comments          []Comment  `json:"comments"`
	GrantIDs          []string   `json:"grant_ids"`
	ErrorCode         string     `json:"error_code,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	ClosedAt          time.Time  `json:"closed_at,omitzero"`
	CanReview         bool       `json:"can_review"`
	CanAmend          bool       `json:"can_amend"`
	CanRevoke         bool       `json:"can_revoke"`
}
type Decision struct {
	Revision  int    `json:"revision"`
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Comment   string `json:"comment"`
}
type Audit struct {
	At       time.Time `json:"at"`
	Actor    Actor     `json:"actor"`
	Action   string    `json:"action"`
	PolicyID string    `json:"policy_id,omitempty"`
	TicketID string    `json:"ticket_id,omitempty"`
	Revision int       `json:"revision,omitempty"`
	Note     string    `json:"note,omitempty"`
}
type Query struct {
	View, State, Search string
	Offset, Limit       int
}
type Page[T any] struct {
	Results []T `json:"results"`
	Total   int `json:"total"`
}
type Intent struct {
	TicketID, Digest string
	Owner, Publisher Actor
	Targets          []Prepared
	StartsAt, EndsAt time.Time
}
type Runner struct {
	Principal      func(context.Context, string) (Principal, error)
	People         func(context.Context) ([]Principal, error)
	ValidatePolicy func(context.Context, PolicyInput) error
	Resolve        func(context.Context, []Target) ([]Prepared, error)
	Catalog        func(context.Context, Policy, string, int, int) (Page[Ref], error)
	Issue          func(context.Context, Intent, func() error, func(grants.TicketReceipt) error) (grants.TicketReceipt, error)
	Revoke         func(context.Context, Intent) (grants.TicketReceipt, error)
	Receipt        func(string) (grants.TicketReceipt, error)
	Prune          func(time.Time) error
}

func validText(v string, max int) bool {
	if len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, c := range v {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return false
		}
	}
	return true
}
func validActor(a Actor) bool {
	return IDPattern.MatchString(a.ID) && a.Name != "" && validText(a.Name, 128) && !strings.ContainsAny(a.Name, "\n\t")
}
func validSubjects(rows []Subject, max int) bool {
	if len(rows) > max {
		return false
	}
	seen := map[Subject]bool{}
	for _, s := range rows {
		if !IDPattern.MatchString(s.ID) || s.Kind != "user" && s.Kind != "group" && s.Kind != "role" || seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}
func matches(p Principal, subjects []Subject) bool {
	for _, s := range subjects {
		if s.Kind == "user" && s.ID == p.ID || slices.Contains(p.Subjects, s) {
			return true
		}
	}
	return false
}
func eligible(p Principal, t Ticket) bool {
	if !p.CanReview || p.ID == t.Owner.ID || t.State != "pending" || t.CurrentStage < 0 || t.CurrentStage >= len(t.Stages) {
		return false
	}
	for _, a := range t.Approvals {
		if a.Actor.ID == p.ID {
			return false
		}
	}
	return matches(p, t.Stages[t.CurrentStage].Subjects)
}
func normalizeActions(in []string) ([]string, error) {
	set := map[string]bool{}
	for _, v := range in {
		if v != "view" && v != "connect" && v != "sftp" {
			return nil, ErrInvalid
		}
		set[v] = true
	}
	if len(set) == 0 {
		return nil, ErrInvalid
	}
	if set["connect"] || set["sftp"] {
		set["view"] = true
	}
	out := []string{}
	for v := range set {
		out = append(out, v)
	}
	slices.Sort(out)
	return out, nil
}
func normalizeTargets(in []Target) ([]Target, error) {
	if len(in) < 1 || len(in) > MaxTargets {
		return nil, ErrInvalid
	}
	out := make([]Target, len(in))
	seen := map[string]bool{}
	for i, v := range in {
		if v.Kind != "asset" && v.Kind != "node" || !IDPattern.MatchString(v.ID) || v.Account == "" || len(v.Account) > 128 || !validText(v.Account, 128) || strings.ContainsAny(v.Account, "\n\t") || v.Account == "*" {
			return nil, ErrInvalid
		}
		var e error
		v.Actions, e = normalizeActions(v.Actions)
		if e != nil {
			return nil, e
		}
		key := targetKey(v)
		if seen[key] {
			return nil, ErrInvalid
		}
		seen[key] = true
		out[i] = v
	}
	return out, nil
}
func targetKey(v Target) string { return v.Kind + "\x00" + v.ID + "\x00" + v.Account }
func (p PolicyInput) Validate() error {
	if p.Name == "" || !validText(p.Name, 240) || strings.ContainsAny(p.Name, "\n\t") || !validText(p.Description, 2000) || p.Revision < 0 || p.Revision >= 1<<53 || p.MaxDurationMinutes < 1 || p.MaxDurationMinutes > 43200 || p.ApprovalTTLMinutes < 1 || p.ApprovalTTLMinutes > 10080 || len(p.Stages) < 1 || len(p.Stages) > 5 || !validSubjects(p.Requesters, 64) || !validSubjects(p.CC, 32) || p.AllMembers && len(p.Requesters) > 0 || p.Enabled && !p.AllMembers && len(p.Requesters) == 0 || len(p.Scopes) < 1 || len(p.Scopes) > 256 {
		return ErrInvalid
	}
	for _, s := range p.Stages {
		if s.Name == "" || !validText(s.Name, 120) || !validSubjects(s.Subjects, 32) || len(s.Subjects) == 0 {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, s := range p.Scopes {
		if s.Kind != "asset" && s.Kind != "node" || !IDPattern.MatchString(s.ID) || len(s.Accounts) < 1 || len(s.Accounts) > 16 || seen[s.Kind+"/"+s.ID] {
			return ErrInvalid
		}
		seen[s.Kind+"/"+s.ID] = true
		accounts := map[string]bool{}
		for _, a := range s.Accounts {
			if a == "" || a == "*" || !validText(a, 128) || strings.ContainsAny(a, "\n\t") || accounts[a] {
				return ErrInvalid
			}
			accounts[a] = true
		}
		if _, e := normalizeActions(s.Actions); e != nil {
			return e
		}
	}
	return nil
}
func allowed(p Policy, v Prepared) bool {
	permitted := map[string]bool{}
	for _, s := range p.Scopes {
		scope := s.Kind == v.Kind && s.ID == v.ID || s.Kind == "node" && v.Kind == "asset" && slices.Contains(v.Nodes, s.ID)
		if !scope || !slices.Contains(s.Accounts, v.Account) {
			continue
		}
		actions, e := normalizeActions(s.Actions)
		if e != nil {
			continue
		}
		for _, a := range actions {
			permitted[a] = true
		}
	}
	for _, a := range v.Actions {
		if !permitted[a] {
			return false
		}
	}
	return len(v.Actions) > 0
}
