// Package accesspolicies applies additional restrictions after identity and
// asset grants. A matching allow rule never grants access to an asset.
package accesspolicies

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	_ "time/tzdata"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid  = errors.New("invalid access policy")
	ErrNotFound = errors.New("access policy not found")
	ErrConflict = errors.New("access policy revision conflict")
	ErrLockout  = errors.New("access policy would deny the current administrator")
	ErrCapacity = errors.New("access policy capacity reached")
	ErrDenied   = errors.New("access policy denied")
)

const (
	Login    = "login"
	Asset    = "asset"
	Method   = "method"
	MaxRules = 500
	MaxAudit = 5000
)

// Origin is assigned by the API and retained with asynchronous work. It must
// never be decoded from a client-supplied execution payload.
type Origin struct {
	SourceIP string `json:"source_ip,omitempty"`
	Method   string `json:"method,omitempty"`
}
type sourceKey struct{}

func WithSourceIP(ctx context.Context, source string) context.Context {
	return context.WithValue(ctx, sourceKey{}, source)
}
func SourceIP(ctx context.Context) string {
	source, _ := ctx.Value(sourceKey{}).(string)
	return source
}

// Window uses Sunday=0 and an inclusive start/exclusive end in local minutes.
// Overnight periods are represented by two windows.
type Window struct {
	Days  []int `json:"days"`
	Start int   `json:"start"`
	End   int   `json:"end"`
}
type Input struct {
	ApproverIDs      []string `json:"approver_ids"`
	ApproverGroupIDs []string `json:"approver_group_ids"`
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	UserID           string   `json:"user_id,omitempty"`
	GroupID          string   `json:"group_id,omitempty"`
	AssetID          string   `json:"asset_id,omitempty"`
	NodeID           string   `json:"node_id,omitempty"`
	Account          string   `json:"account,omitempty"`
	Sources          []string `json:"sources"`
	Windows          []Window `json:"windows"`
	Timezone         string   `json:"timezone"`
	Methods          []string `json:"methods"`
	Action           string   `json:"action"`
	Priority         int      `json:"priority"`
	Enabled          bool     `json:"enabled"`
	Remark           string   `json:"remark"`
	Revision         int      `json:"revision"`
}
type Rule struct {
	ID string `json:"id"`
	Input
	UpdatedAt time.Time `json:"updated_at"`
}
type Scope struct {
	Kind     string   `json:"kind"`
	UserID   string   `json:"user_id"`
	GroupIDs []string `json:"-"`
	AssetID  string   `json:"asset_id,omitempty"`
	NodeIDs  []string `json:"-"`
	Account  string   `json:"account,omitempty"`
	Origin
}
type Decision struct {
	Action       string `json:"action,omitempty"`
	RuleRevision int    `json:"rule_revision,omitempty"`
	Allowed      bool   `json:"allowed"`
	RuleID       string `json:"rule_id,omitempty"`
	RuleName     string `json:"rule_name,omitempty"`
	Reason       string `json:"reason,omitempty"`
}
type Audit struct {
	Kind    string    `json:"kind,omitempty"`
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	Action  string    `json:"action"`
	ActorID string    `json:"actor_id"`
	RuleID  string    `json:"rule_id,omitempty"`
	AssetID string    `json:"asset_id,omitempty"`
	Origin
	Reason string `json:"reason,omitempty"`
	Before *Rule  `json:"before,omitempty"`
	After  *Rule  `json:"after,omitempty"`
}
type state struct {
	Rules map[string]Rule `json:"rules"`
	Audit []Audit         `json:"audit"`
}
type Store struct {
	mu        sync.RWMutex
	path      string
	documents *storage.Documents
	data      state
	denials   map[string]time.Time
}

func Open(path string, documents *storage.Documents) (*Store, error) {
	s := &Store{path: path, documents: documents, data: state{Rules: map[string]Rule{}, Audit: []Audit{}}, denials: map[string]time.Time{}}
	var data []byte
	var err error
	if documents != nil {
		data, err = documents.LoadOrImport("access-policies", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return s, nil
	}
	if json.Unmarshal(data, &s.data) != nil || s.data.Rules == nil || len(s.data.Rules) > MaxRules || len(s.data.Audit) > MaxAudit {
		return nil, ErrInvalid
	}
	for id, r := range s.data.Rules {
		normalized, e := normalize(r.Input)
		if e != nil || !validID(id) || r.ID != id || r.Revision < 1 || r.UpdatedAt.IsZero() {
			return nil, ErrInvalid
		}
		r.Input = normalized
		s.data.Rules[id] = r
	}
	for _, a := range s.data.Audit {
		if a.ID == "" || a.ActorID == "" || a.At.IsZero() || !slices.Contains([]string{"create", "update", "delete", "denied"}, a.Action) {
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func validID(id string) bool {
	if !strings.HasPrefix(id, "acl-") || len(id) != 36 {
		return false
	}
	_, e := hex.DecodeString(id[4:])
	return e == nil
}
func randomID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return "acl-" + hex.EncodeToString(b[:]), nil
}
func textOK(s string, n int) bool { return len(s) <= n && strings.IndexFunc(s, unicode.IsControl) < 0 }
func ValidMethod(method string) bool {
	return slices.Contains([]string{"ssh", "sftp", "exec", "scheduled_exec", "upload", "download", "delete", "mkdir", "database", "kubernetes", "telnet", "rdp", "rdp_input", "rdp_clipboard_read", "rdp_clipboard_write"}, method)
}
func normalize(in Input) (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Remark = strings.TrimSpace(in.Remark)
	if in.Name == "" || !textOK(in.Name, 100) || !textOK(in.Remark, 500) || !slices.Contains([]string{Login, Asset, Method}, in.Kind) || !(slices.Contains([]string{"allow", "deny"}, in.Action) || in.Kind == Login && slices.Contains([]string{"review", "notify"}, in.Action)) || in.Priority < 0 || in.Priority > 10000 || in.Revision < 0 || in.Revision > 1000000000 {
		return Input{}, ErrInvalid
	}
	if (in.Kind != Login || in.Action != "review") && (len(in.ApproverIDs) > 0 || len(in.ApproverGroupIDs) > 0) || len(in.ApproverIDs) > 50 || len(in.ApproverGroupIDs) > 50 {
		return Input{}, ErrInvalid
	}
	in.ApproverIDs = append([]string{}, in.ApproverIDs...)
	in.ApproverGroupIDs = append([]string{}, in.ApproverGroupIDs...)
	sort.Strings(in.ApproverIDs)
	sort.Strings(in.ApproverGroupIDs)
	for _, ids := range [][]string{in.ApproverIDs, in.ApproverGroupIDs} {
		for i, id := range ids {
			if id == "" || !textOK(id, 128) || strings.TrimSpace(id) != id || i > 0 && id == ids[i-1] {
				return Input{}, ErrInvalid
			}
		}
	}
	for _, v := range []string{in.UserID, in.GroupID, in.AssetID, in.NodeID, in.Account} {
		if !textOK(v, 128) || strings.TrimSpace(v) != v {
			return Input{}, ErrInvalid
		}
	}
	if in.UserID != "" && in.GroupID != "" || in.AssetID != "" && in.NodeID != "" {
		return Input{}, ErrInvalid
	}
	if in.Kind != Asset && (in.AssetID != "" || in.NodeID != "" || in.Account != "") {
		return Input{}, ErrInvalid
	}
	if in.Kind == Login && len(in.Methods) > 0 || in.Kind == Method && len(in.Methods) == 0 || len(in.Methods) > 15 {
		return Input{}, ErrInvalid
	}
	in.Methods = append([]string{}, in.Methods...)
	sort.Strings(in.Methods)
	for i, m := range in.Methods {
		if !ValidMethod(m) || i > 0 && m == in.Methods[i-1] {
			return Input{}, ErrInvalid
		}
	}
	if len(in.Sources) > 64 || len(in.Windows) > 32 {
		return Input{}, ErrInvalid
	}
	in.Sources = append([]string{}, in.Sources...)
	for i, v := range in.Sources {
		v = strings.TrimSpace(v)
		if !validSource(v) {
			return Input{}, ErrInvalid
		}
		in.Sources[i] = v
	}
	if in.Timezone == "" {
		in.Timezone = "UTC"
	}
	if !textOK(in.Timezone, 100) || strings.HasPrefix(in.Timezone, "/") || strings.Contains(in.Timezone, "..") || in.Timezone == "Local" {
		return Input{}, ErrInvalid
	}
	if _, e := time.LoadLocation(in.Timezone); e != nil {
		return Input{}, ErrInvalid
	}
	in.Windows = append([]Window{}, in.Windows...)
	for i, w := range in.Windows {
		if w.Start < 0 || w.End > 1440 || w.Start >= w.End || len(w.Days) == 0 || len(w.Days) > 7 {
			return Input{}, ErrInvalid
		}
		w.Days = append([]int{}, w.Days...)
		sort.Ints(w.Days)
		for j, d := range w.Days {
			if d < 0 || d > 6 || j > 0 && d == w.Days[j-1] {
				return Input{}, ErrInvalid
			}
		}
		in.Windows[i] = w
	}
	return in, nil
}
func parseAddr(value string) (netip.Addr, bool) {
	ip, e := netip.ParseAddr(value)
	if e != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
func validSource(v string) bool {
	if v == "*" {
		return true
	}
	if _, ok := parseAddr(v); ok {
		return true
	}
	if p, e := netip.ParsePrefix(v); e == nil {
		return p.Addr().Zone() == "" && !p.Addr().Is4In6()
	}
	a, b, ok := strings.Cut(v, "-")
	if !ok {
		return false
	}
	first, f := parseAddr(a)
	last, l := parseAddr(b)
	return f && l && first.BitLen() == last.BitLen() && first.Compare(last) <= 0
}
func sourceMatches(value string, ip netip.Addr) bool {
	if value == "*" {
		return true
	}
	if addr, ok := parseAddr(value); ok {
		return addr == ip
	}
	if p, e := netip.ParsePrefix(value); e == nil {
		return p.Contains(ip)
	}
	a, b, _ := strings.Cut(value, "-")
	first, f := parseAddr(a)
	last, l := parseAddr(b)
	return f && l && ip.BitLen() == first.BitLen() && ip.Compare(first) >= 0 && ip.Compare(last) <= 0
}
func matchesSubject(r Rule, s Scope) bool {
	return r.Enabled && r.Kind == s.Kind && (r.UserID == "" || r.UserID == s.UserID) && (r.GroupID == "" || slices.Contains(s.GroupIDs, r.GroupID)) && (r.AssetID == "" || r.AssetID == s.AssetID) && (r.NodeID == "" || slices.Contains(s.NodeIDs, r.NodeID)) && (r.Account == "" || r.Account == "*" || r.Account == s.Account) && (len(r.Methods) == 0 || slices.Contains(r.Methods, s.Method))
}
func sortedRules(data state) []Rule {
	out := make([]Rule, 0, len(data.Rules))
	for _, r := range data.Rules {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		if out[i].Action != out[j].Action {
			return out[i].Action == "deny"
		}
		return out[i].ID < out[j].ID
	})
	return out
}
func decide(data state, s Scope, at time.Time) Decision {
	ip, known := parseAddr(s.SourceIP)
	for _, r := range sortedRules(data) {
		if !matchesSubject(r, s) {
			continue
		}
		loc, e := time.LoadLocation(r.Timezone)
		if e != nil {
			return Decision{Reason: "invalid_timezone"}
		}
		if len(r.Windows) > 0 {
			local := at.In(loc)
			minute := local.Hour()*60 + local.Minute()
			found := false
			for _, w := range r.Windows {
				if slices.Contains(w.Days, int(local.Weekday())) && minute >= w.Start && minute < w.End {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if len(r.Sources) > 0 && !slices.Contains(r.Sources, "*") {
			if !known {
				return Decision{RuleID: r.ID, RuleName: r.Name, Reason: "unknown_source"}
			}
			found := false
			for _, source := range r.Sources {
				if sourceMatches(source, ip) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		return Decision{Allowed: r.Action != "deny", Action: r.Action, RuleRevision: r.Revision, RuleID: r.ID, RuleName: r.Name, Reason: r.Action}
	}
	return Decision{Allowed: true}
}
func clone[T any](value T) T {
	raw, _ := json.Marshal(value)
	var result T
	_ = json.Unmarshal(raw, &result)
	return result
}
func (s *Store) List() []Rule { s.mu.RLock(); defer s.mu.RUnlock(); return clone(sortedRules(s.data)) }
func (s *Store) Get(id string) (Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.data.Rules[id]
	if !ok {
		return Rule{}, ErrNotFound
	}
	return clone(r), nil
}
func (s *Store) Audit(limit int) []Audit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit < 1 || limit > 200 {
		limit = 100
	}
	start := len(s.data.Audit) - limit
	if start < 0 {
		start = 0
	}
	result := clone(s.data.Audit[start:])
	slices.Reverse(result)
	return result
}
func (s *Store) AuditPage(offset, limit int) ([]Audit, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.data.Audit)
	if offset < 0 {
		offset = 0
	}
	if limit < 1 || limit > 200 {
		limit = 25
	}
	result := []Audit{}
	for i := total - 1 - offset; i >= 0 && len(result) < limit; i-- {
		result = append(result, s.data.Audit[i])
	}
	return clone(result), total
}
func (s *Store) Decide(scope Scope, at time.Time) Decision {
	if s == nil {
		return Decision{Allowed: true}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return decide(s.data, scope, at)
}
func appendAudit(data *state, event Audit) {
	if len(data.Audit) >= MaxAudit {
		data.Audit = append([]Audit{}, data.Audit[len(data.Audit)-MaxAudit+1:]...)
	}
	data.Audit = append(data.Audit, event)
}

// Check records denied decisions before reporting a denial. Repeated identical
// denials are coalesced for one minute; retention is the latest MaxAudit events.
func (s *Store) Check(scope Scope, at time.Time) (Decision, error) {
	if s == nil {
		return Decision{Allowed: true}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := decide(s.data, scope, at)
	if d.Allowed {
		return d, nil
	}
	key := strings.Join([]string{scope.UserID, scope.Kind, scope.AssetID, scope.SourceIP, scope.Method, d.RuleID, d.Reason}, "\x00")
	if last, ok := s.denials[key]; ok && at.Sub(last) >= 0 && at.Sub(last) < time.Minute {
		return d, nil
	}
	id, e := randomID()
	if e != nil {
		return d, e
	}
	previous := s.data.Audit
	appendAudit(&s.data, Audit{Kind: scope.Kind, ID: id, At: at.UTC(), Action: "denied", ActorID: scope.UserID, RuleID: d.RuleID, AssetID: scope.AssetID, Origin: scope.Origin, Reason: d.Reason})
	if e = s.persistLocked(); e != nil {
		s.data.Audit = previous
		return d, e
	}
	if len(s.denials) >= 4096 {
		clear(s.denials)
	}
	s.denials[key] = at
	return d, nil
}
func (s *Store) Save(id string, in Input, actor string, guard *Scope) (Rule, error) {
	input, e := normalize(in)
	if e != nil || actor == "" {
		return Rule{}, ErrInvalid
	}
	creating := id == ""
	if creating {
		id, e = randomID()
		if e != nil {
			return Rule{}, e
		}
	} else if !validID(id) {
		return Rule{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.data.Rules[id]
	if !creating && !exists {
		return Rule{}, ErrNotFound
	}
	if exists && old.Revision != input.Revision || !exists && input.Revision != 0 {
		return Rule{}, ErrConflict
	}
	if exists && old.Revision >= 1000000000 {
		return Rule{}, ErrCapacity
	}
	if creating && len(s.data.Rules) >= MaxRules {
		return Rule{}, ErrCapacity
	}
	input.Revision++
	r := Rule{ID: id, Input: input, UpdatedAt: time.Now().UTC()}
	s.data.Rules[id] = r
	rollback := func() {
		if exists {
			s.data.Rules[id] = old
		} else {
			delete(s.data.Rules, id)
		}
	}
	if guard != nil && !decide(s.data, *guard, time.Now()).Allowed {
		rollback()
		return Rule{}, ErrLockout
	}
	auditID, e := randomID()
	if e != nil {
		rollback()
		return Rule{}, e
	}
	event := Audit{Kind: r.Kind, ID: auditID, At: r.UpdatedAt, Action: "create", ActorID: actor, RuleID: id, After: &r}
	if guard != nil {
		event.Origin = guard.Origin
	}
	if exists {
		event.Action = "update"
		event.Before = &old
	}
	priorAudit := s.data.Audit
	appendAudit(&s.data, event)
	if e = s.persistLocked(); e != nil {
		rollback()
		s.data.Audit = priorAudit
		return Rule{}, e
	}
	return clone(r), nil
}
func (s *Store) Delete(id string, revision int, actor string, guard *Scope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.data.Rules[id]
	if !ok {
		return ErrNotFound
	}
	if old.Revision != revision {
		return ErrConflict
	}
	if actor == "" {
		return ErrInvalid
	}
	delete(s.data.Rules, id)
	if guard != nil && !decide(s.data, *guard, time.Now()).Allowed {
		s.data.Rules[id] = old
		return ErrLockout
	}
	auditID, e := randomID()
	if e != nil {
		s.data.Rules[id] = old
		return e
	}
	priorAudit := s.data.Audit
	event := Audit{Kind: old.Kind, ID: auditID, At: time.Now().UTC(), Action: "delete", ActorID: actor, RuleID: id, Before: &old}
	if guard != nil {
		event.Origin = guard.Origin
	}
	appendAudit(&s.data, event)
	if e = s.persistLocked(); e != nil {
		s.data.Rules[id] = old
		s.data.Audit = priorAudit
		return e
	}
	return nil
}
func (s *Store) persistLocked() error {
	data, e := json.Marshal(s.data)
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("access-policies", data)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	file, e := os.CreateTemp(filepath.Dir(s.path), ".access-policies-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if e = file.Chmod(0600); e != nil {
		return e
	}
	if _, e = file.Write(data); e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	return os.Rename(file.Name(), s.path)
}

// AuditPageScope filters before pagination. Unknown legacy kinds are omitted
// from restricted views so a deleted platform policy cannot expose its audit.
func (s *Store) AuditPageScope(scope string, offset, limit int) ([]Audit, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Audit{}
	for i := len(s.data.Audit) - 1; i >= 0; i-- {
		a := s.data.Audit[i]
		kind := a.Kind
		if kind == "" {
			if a.After != nil {
				kind = a.After.Kind
			} else if a.Before != nil {
				kind = a.Before.Kind
			} else if rule, ok := s.data.Rules[a.RuleID]; ok {
				kind = rule.Kind
			}
		}
		if scope == "platform" && kind != Login || scope == "organization" && (kind != Asset && kind != Method) {
			continue
		}
		out = append(out, clone(a))
	}
	total := len(out)
	offset = min(max(offset, 0), total)
	return out[offset:min(total, offset+min(max(limit, 1), 200))], total
}
