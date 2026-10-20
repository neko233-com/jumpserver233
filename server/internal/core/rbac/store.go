package rbac

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid   = errors.New("invalid role or binding")
	ErrNotFound  = errors.New("role or binding not found")
	ErrConflict  = errors.New("role revision or binding conflicts")
	ErrProtected = errors.New("built-in role is immutable")
	ErrCapacity  = errors.New("RBAC audit or record capacity reached")
)

// System permissions are independent from account/asset grants. Every new
// permission must be explicitly added here; wildcards are never accepted.
var catalog = []string{
	"reports.export", "reports.audit",
	"announcements.manage",
	"labels.manage", "labels.assign", "labels.audit",
	"ssh_certificates.view", "ssh_certificates.manage", "ssh_certificates.assign", "ssh_certificates.audit",
	"replay_storage.view", "replay_storage.manage", "replay_storage.archive", "replay_storage.verify", "replay_storage.evict", "replay_storage.audit",
	"audit.logins.view_all", "audit.logins.export",
	"organizations.manage", "organizations.members.manage", "organizations.overview",
	"roles.manage", "users.manage", "users.credentials.manage", "groups.manage", "grants.manage", "nodes.manage",
	"assets.manage", "assets.probe", "assets.rotate", "assets.backups", "assets.view_all", "assets.connect_all", "assets.sftp_all",
	"assets.discovery.view", "assets.discovery.manage", "assets.discovery.execute", "assets.discovery.import", "assets.discovery.trust", "assets.discovery.export",
	"security.manage", "branding.manage", "command_filters.manage", "access_policies.manage", "reviews.login.manage", "reviews.platform_login.manage", "reviews.command.manage", "login_review.bypass",
	"audit.sessions.view_all", "audit.sessions.monitor_all", "audit.desktops.monitor_all", "audit.sessions.terminate_all", "audit.replays.view_all", "audit.commands.view_all", "audit.files.view_all", "audit.agents.view_all",
	"jobs.view_all", "jobs.cancel_all", "jobs.review", "plans.view_all", "plans.manage_all",
	"playbooks.publish",
	"sessions.share",
	"assistant.use", "assistant.manage", "assistant.audit",
	"tickets.manage", "tickets.review", "tickets.view_all", "tickets.revoke",
	"notifications.manage", "notifications.audit", "notifications.retry",
	"monitoring.view", "monitoring.manage", "monitoring.ack",
	"accounts.discover", "accounts.view", "accounts.review", "accounts.manage", "accounts.schedule",
	"accounts.remote.create", "accounts.remote.disable", "accounts.remote.enable", "accounts.remote.delete",
	"accounts.import",
	"accounts.password_policy.view", "accounts.password_policy.manage",
	"accounts.risks.view", "accounts.risks.scan", "accounts.risks.manage", "accounts.risks.export",
	"accounts.rotation.view", "accounts.rotation.manage", "accounts.rotation.execute", "accounts.rotation.manage_all", "accounts.rotation.privileged", "accounts.rotation.fixed_password",
	"accounts.rotation.check",
	"database.audit.view_all", "database.cancel_all",
	"plugins.inspect", "plugins.manage", "plugins.protect",
}

func Catalog() []string { out := append([]string(nil), catalog...); sort.Strings(out); return out }

type RoleInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	Revision    int      `json:"revision"`
}
type Role struct {
	ID string `json:"id"`
	RoleInput
	Builtin   bool      `json:"builtin"`
	UpdatedAt time.Time `json:"updated_at"`
}
type BindingInput struct {
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	RoleIDs     []string `json:"role_ids"`
	Revision    int      `json:"revision"`
}
type Binding struct {
	BindingInput
	UpdatedAt time.Time `json:"updated_at"`
}
type Audit struct {
	ID      string          `json:"id"`
	At      time.Time       `json:"at"`
	ActorID string          `json:"actor_id"`
	Actor   string          `json:"actor"`
	Action  string          `json:"action"`
	Target  string          `json:"target"`
	Before  json.RawMessage `json:"before,omitempty"`
	After   json.RawMessage `json:"after,omitempty"`
}
type Snapshot struct {
	RoleIDs     []string `json:"role_ids"`
	Permissions []string `json:"permissions"`
}

func (s Snapshot) Allows(permission string) bool { return slices.Contains(s.Permissions, permission) }

type state struct {
	Roles    map[string]Role    `json:"roles"`
	Bindings map[string]Binding `json:"bindings"`
	Audit    []Audit            `json:"audit"`
}
type Store struct {
	mu           sync.RWMutex
	path         string
	documents    *storage.Documents
	data         state
	organization bool
	inherited    func(string, string) Snapshot
}

// OrganizationCatalog excludes identity, authentication and system management.
// Identical permission names operate only on the selected organization's stores.
func OrganizationCatalog() []string {
	out := []string{}
	for _, p := range Catalog() {
		if !slices.Contains([]string{"users.manage", "security.manage", "branding.manage", "announcements.manage", "organizations.manage", "organizations.overview", "reviews.platform_login.manage", "audit.logins.view_all", "audit.logins.export"}, p) {
			out = append(out, p)
		}
	}
	return out
}
func (s *Store) Catalog() []string {
	if s != nil && s.organization {
		return OrganizationCatalog()
	}
	return Catalog()
}
func OpenOrganization(path string, documents *storage.Documents, inherited func(string, string) Snapshot) (*Store, error) {
	s, e := Open(path, documents)
	if e != nil {
		return nil, e
	}
	s.organization = true
	s.inherited = inherited
	for _, r := range s.data.Roles {
		for _, p := range r.Permissions {
			if !slices.Contains(OrganizationCatalog(), p) {
				return nil, ErrInvalid
			}
		}
	}
	return s, nil
}
func (s *Store) builtinRoles() []Role {
	out := builtins()
	if s != nil && s.organization {
		allowed := OrganizationCatalog()
		for i := range out {
			out[i].Permissions = slices.DeleteFunc(out[i].Permissions, func(p string) bool { return !slices.Contains(allowed, p) })
		}
	}
	return out
}
func Union(snapshots ...Snapshot) Snapshot {
	out := Snapshot{RoleIDs: []string{}, Permissions: []string{}}
	for _, s := range snapshots {
		out.RoleIDs = append(out.RoleIDs, s.RoleIDs...)
		out.Permissions = append(out.Permissions, s.Permissions...)
	}
	sort.Strings(out.RoleIDs)
	sort.Strings(out.Permissions)
	out.RoleIDs = slices.Compact(out.RoleIDs)
	out.Permissions = slices.Compact(out.Permissions)
	return out
}

func builtins() []Role {
	return []Role{
		{ID: "system-administrator", RoleInput: RoleInput{Name: "system-administrator", Permissions: Catalog(), Revision: 1}, Builtin: true},
		{ID: "auditor", RoleInput: RoleInput{Name: "auditor", Revision: 1, Permissions: []string{"assets.view_all", "audit.sessions.view_all", "audit.replays.view_all", "audit.commands.view_all", "audit.files.view_all", "audit.agents.view_all", "database.audit.view_all", "jobs.view_all", "plans.view_all"}}, Builtin: true},
		{ID: "asset-manager", RoleInput: RoleInput{Name: "asset-manager", Revision: 1, Permissions: []string{"assets.view_all", "assets.manage", "assets.probe", "nodes.manage"}}, Builtin: true},
		{ID: "access-reviewer", RoleInput: RoleInput{Name: "access-reviewer", Revision: 1, Permissions: []string{"reviews.login.manage", "reviews.platform_login.manage", "reviews.command.manage", "jobs.review", "jobs.view_all"}}, Builtin: true},
	}
}
func Open(path string, documents *storage.Documents) (*Store, error) {
	s := &Store{path: path, documents: documents, data: state{Roles: map[string]Role{}, Bindings: map[string]Binding{}, Audit: []Audit{}}}
	var data []byte
	var err error
	if documents != nil {
		data, err = documents.LoadOrImport("rbac", path)
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
	if json.Unmarshal(data, &s.data) != nil || s.data.Roles == nil || s.data.Bindings == nil || len(s.data.Roles) > 100 || len(s.data.Bindings) > 2000 || len(s.data.Audit) > 10000 {
		return nil, ErrInvalid
	}
	for id, r := range s.data.Roles {
		if id != r.ID || r.Builtin || isBuiltin(id) || r.Revision < 1 || validateRole(r.RoleInput) != nil {
			return nil, ErrInvalid
		}
	}
	for key, b := range s.data.Bindings {
		if key != bindingKey(b.SubjectType, b.SubjectID) || b.Revision < 1 || validateBinding(b.BindingInput, s.data) != nil {
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func isBuiltin(id string) bool {
	for _, r := range builtins() {
		if r.ID == id {
			return true
		}
	}
	return false
}
func validText(value string, max int) bool {
	return len(value) <= max && strings.IndexFunc(value, unicode.IsControl) < 0
}
func validateRole(in RoleInput) error {
	if strings.TrimSpace(in.Name) == "" || !validText(in.Name, 80) || !validText(in.Description, 500) || len(in.Permissions) > len(catalog) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, p := range in.Permissions {
		if !slices.Contains(catalog, p) || seen[p] {
			return ErrInvalid
		}
		seen[p] = true
	}
	return nil
}
func bindingKey(kind, id string) string { return kind + ":" + id }
func validateBinding(in BindingInput, data state) error {
	if (in.SubjectType != "user" && in.SubjectType != "group") || in.SubjectID == "" || !validText(in.SubjectID, 128) || len(in.RoleIDs) > 104 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range in.RoleIDs {
		_, ok := data.Roles[id]
		if (!ok && !isBuiltin(id)) || seen[id] {
			return ErrInvalid
		}
		seen[id] = true
	}
	return nil
}
func copyState(in state) state {
	data := state{Roles: map[string]Role{}, Bindings: map[string]Binding{}, Audit: append([]Audit(nil), in.Audit...)}
	for id, r := range in.Roles {
		r.Permissions = append([]string{}, r.Permissions...)
		data.Roles[id] = r
	}
	for id, b := range in.Bindings {
		b.RoleIDs = append([]string{}, b.RoleIDs...)
		data.Bindings[id] = b
	}
	return data
}
func (s *Store) mutate(actorID, actor, action, target string, fn func(*state) (any, any, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Audit) >= 10000 {
		return ErrCapacity
	}
	data := copyState(s.data)
	before, after, err := fn(&data)
	if err != nil {
		return err
	}
	var raw [16]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return err
	}
	event := Audit{ID: "rbac-audit-" + hex.EncodeToString(raw[:]), At: time.Now().UTC(), ActorID: actorID, Actor: actor, Action: action, Target: target}
	if before != nil {
		event.Before, err = json.Marshal(before)
		if err != nil {
			return err
		}
	}
	if after != nil {
		event.After, err = json.Marshal(after)
		if err != nil {
			return err
		}
	}
	data.Audit = append(data.Audit, event)
	if err = s.persist(data); err != nil {
		return err
	}
	s.data = data
	return nil
}
func (s *Store) SaveRole(id string, in RoleInput, actorID, actor string) (Role, error) {
	creating := id == ""
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.Permissions = append([]string{}, in.Permissions...)
	sort.Strings(in.Permissions)
	if err := validateRole(in); err != nil {
		return Role{}, err
	}
	if s.organization {
		for _, p := range in.Permissions {
			if !slices.Contains(OrganizationCatalog(), p) {
				return Role{}, ErrInvalid
			}
		}
	}
	if isBuiltin(id) {
		return Role{}, ErrProtected
	}
	if id == "" {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return Role{}, err
		}
		id = "role-" + hex.EncodeToString(raw[:])
	}
	var result Role
	err := s.mutate(actorID, actor, "role.save", id, func(data *state) (any, any, error) {
		old, exists := data.Roles[id]
		if !creating && !exists {
			return nil, nil, ErrNotFound
		}
		if !exists && in.Revision != 0 {
			return nil, nil, ErrNotFound
		}
		if exists && old.Revision != in.Revision {
			return nil, nil, ErrConflict
		}
		if !exists && len(data.Roles) >= 100 {
			return nil, nil, ErrCapacity
		}
		for other, r := range data.Roles {
			if other != id && strings.EqualFold(r.Name, in.Name) {
				return nil, nil, ErrConflict
			}
		}
		for _, r := range builtins() {
			if strings.EqualFold(r.Name, in.Name) {
				return nil, nil, ErrConflict
			}
		}
		in.Revision++
		result = Role{ID: id, RoleInput: in, UpdatedAt: time.Now().UTC()}
		data.Roles[id] = result
		if !exists {
			return nil, result, nil
		}
		return old, result, nil
	})
	result.Permissions = append([]string{}, result.Permissions...)
	return result, err
}
func (s *Store) DeleteRole(id string, revision int, actorID, actor string) error {
	if isBuiltin(id) {
		return ErrProtected
	}
	return s.mutate(actorID, actor, "role.delete", id, func(data *state) (any, any, error) {
		r, ok := data.Roles[id]
		if !ok {
			return nil, nil, ErrNotFound
		}
		if r.Revision != revision {
			return nil, nil, ErrConflict
		}
		for _, b := range data.Bindings {
			if slices.Contains(b.RoleIDs, id) {
				return nil, nil, ErrConflict
			}
		}
		delete(data.Roles, id)
		return r, nil, nil
	})
}
func (s *Store) SaveBinding(in BindingInput, actorID, actor string) (Binding, error) {
	in.RoleIDs = append([]string{}, in.RoleIDs...)
	sort.Strings(in.RoleIDs)
	var result Binding
	err := s.mutate(actorID, actor, "binding.save", bindingKey(in.SubjectType, in.SubjectID), func(data *state) (any, any, error) {
		if err := validateBinding(in, *data); err != nil {
			return nil, nil, err
		}
		key := bindingKey(in.SubjectType, in.SubjectID)
		old, ok := data.Bindings[key]
		if ok && old.Revision != in.Revision || !ok && in.Revision != 0 {
			return nil, nil, ErrConflict
		}
		if !ok && len(data.Bindings) >= 2000 {
			return nil, nil, ErrCapacity
		}
		in.Revision++
		result = Binding{BindingInput: in, UpdatedAt: time.Now().UTC()}
		data.Bindings[key] = result
		if !ok {
			return nil, result, nil
		}
		return old, result, nil
	})
	result.RoleIDs = append([]string{}, result.RoleIDs...)
	return result, err
}
func (s *Store) Roles() []Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.builtinRoles()
	for _, r := range s.data.Roles {
		r.Permissions = append([]string{}, r.Permissions...)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (s *Store) Bindings() []Binding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Binding{}
	for _, b := range s.data.Bindings {
		b.RoleIDs = append([]string{}, b.RoleIDs...)
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		return bindingKey(out[i].SubjectType, out[i].SubjectID) < bindingKey(out[j].SubjectType, out[j].SubjectID)
	})
	return out
}
func (s *Store) Effective(userID, legacyRole string, groups []string) Snapshot {
	out := s.localEffective(userID, legacyRole, groups)
	if s != nil && s.inherited != nil {
		out = Union(out, s.inherited(userID, legacyRole))
		out.Permissions = slices.DeleteFunc(out.Permissions, func(p string) bool { return !slices.Contains(s.Catalog(), p) })
	}
	return out
}
func (s *Store) localEffective(userID, legacyRole string, groups []string) Snapshot {
	if legacyRole == "admin" {
		return Snapshot{RoleIDs: []string{"system-administrator"}, Permissions: s.Catalog()}
	}
	result := Snapshot{RoleIDs: []string{}, Permissions: []string{}}
	if s == nil {
		return result
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	roleIDs := map[string]bool{}
	for key, b := range s.data.Bindings {
		if key == bindingKey("user", userID) || (b.SubjectType == "group" && slices.Contains(groups, b.SubjectID)) {
			for _, id := range b.RoleIDs {
				roleIDs[id] = true
			}
		}
	}
	permissions := map[string]bool{}
	built := s.builtinRoles()
	for id := range roleIDs {
		r, ok := s.data.Roles[id]
		if !ok {
			for _, b := range built {
				if b.ID == id {
					r = b
					ok = true
					break
				}
			}
		}
		if ok {
			result.RoleIDs = append(result.RoleIDs, id)
			for _, p := range r.Permissions {
				permissions[p] = true
			}
		}
	}
	for p := range permissions {
		result.Permissions = append(result.Permissions, p)
	}
	sort.Strings(result.RoleIDs)
	sort.Strings(result.Permissions)
	return result
}
func (s *Store) Audit(offset, limit int) ([]Audit, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.data.Audit)
	offset = min(max(offset, 0), total)
	out := []Audit{}
	for i := total - 1 - offset; i >= max(0, total-offset-limit); i-- {
		a := s.data.Audit[i]
		a.Before = append(json.RawMessage(nil), a.Before...)
		a.After = append(json.RawMessage(nil), a.After...)
		out = append(out, a)
	}
	return out, total
}
func (s *Store) persist(data state) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if s.documents != nil {
		return s.documents.Save("rbac", raw)
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".rbac-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), s.path); err != nil {
		return fmt.Errorf("replace RBAC state: %w", err)
	}
	return nil
}
