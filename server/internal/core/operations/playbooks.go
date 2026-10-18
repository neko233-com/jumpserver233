package operations

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"
)

type PlaybookInput struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Visibility  string            `json:"visibility"`
	Revision    int               `json:"revision"`
	Files       map[string]string `json:"files"`
}
type Playbook struct {
	ID          string    `json:"id"`
	OwnerID     string    `json:"owner_id"`
	Owner       string    `json:"owner"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Visibility  string    `json:"visibility"`
	Revision    int       `json:"revision"`
	ProgramID   string    `json:"program_id"`
	TaskCount   int       `json:"task_count"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type PlaybookDetail struct {
	Playbook
	Files map[string]string `json:"files"`
}
type PlaybookEvent struct {
	ID         string        `json:"id"`
	PlaybookID string        `json:"playbook_id"`
	At         time.Time     `json:"at"`
	Actor      ScheduleActor `json:"actor"`
	Action     string        `json:"action"`
	Revision   int           `json:"revision"`
	ProgramID  string        `json:"program_id"`
	Visibility string        `json:"visibility"`
}

func (s *Service) Playbook(id, user string) (PlaybookDetail, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data.Playbooks[id]
	if !ok || b.OwnerID != user && b.Visibility != "organization" {
		return PlaybookDetail{}, ErrNotFound
	}
	return PlaybookDetail{b, maps.Clone(s.data.Programs[b.ProgramID].Files)}, nil
}
func (s *Service) Playbooks(user string, offset, limit int) ([]Playbook, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := []Playbook{}
	for _, b := range s.data.Playbooks {
		if b.OwnerID == user || b.Visibility == "organization" {
			rows = append(rows, b)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].UpdatedAt.Equal(rows[j].UpdatedAt) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].UpdatedAt.After(rows[j].UpdatedAt)
	})
	n := len(rows)
	offset = min(offset, n)
	return rows[offset:min(offset+limit, n)], n, nil
}
func (s *Service) SavePlaybook(id, ownerID, owner string, in PlaybookInput, canPublish bool) (PlaybookDetail, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Visibility == "" {
		in.Visibility = "private"
	}
	if !validName(in.Name) || len(in.Description) > 2000 || strings.ContainsRune(in.Description, 0) || !slices.Contains([]string{"private", "organization"}, in.Visibility) {
		return PlaybookDetail{}, ErrInvalid
	}
	if in.Visibility == "organization" && !canPublish {
		return PlaybookDetail{}, ErrDenied
	}
	program, e := playbooks.Compile(playbooks.Workspace{Files: in.Files})
	if e != nil {
		return PlaybookDetail{}, e
	}
	digest := playbooks.WorkspaceID(program.Files)
	var out PlaybookDetail
	e = s.mutate(func(next *state) error {
		revision := 1
		action := "created"
		if id == "" {
			if len(next.Playbooks) >= 200 {
				return ErrBusy
			}
			var e error
			id, e = newID("playbook-")
			if e != nil {
				return e
			}
		} else {
			old, ok := next.Playbooks[id]
			if !ok || old.OwnerID != ownerID {
				return ErrNotFound
			}
			if old.Revision != in.Revision {
				return ErrConflict
			}
			revision = old.Revision + 1
			action = "updated"
		}
		next.Playbooks[id] = Playbook{ID: id, OwnerID: ownerID, Owner: owner, Name: in.Name, Description: in.Description, Visibility: in.Visibility, Revision: revision, ProgramID: digest, TaskCount: len(program.Tasks), UpdatedAt: s.now().UTC()}
		next.Programs[digest] = program
		prunePrograms(next)
		if !programCapacity(next) {
			return ErrBusy
		}
		if e := appendPlaybookEvent(next, next.Playbooks[id], action, ScheduleActor{ownerID, owner}, s.now()); e != nil {
			return e
		}
		out = PlaybookDetail{next.Playbooks[id], maps.Clone(program.Files)}
		return nil
	})
	return out, e
}
func (s *Service) DeletePlaybook(id, owner string, revision int) error {
	return s.mutate(func(next *state) error {
		b, ok := next.Playbooks[id]
		if !ok || b.OwnerID != owner {
			return ErrNotFound
		}
		if revision != b.Revision || revision < 1 {
			return ErrConflict
		}
		b.Revision++
		if e := appendPlaybookEvent(next, b, "deleted", ScheduleActor{owner, b.Owner}, s.now()); e != nil {
			return e
		}
		delete(next.Playbooks, id)
		prunePrograms(next)
		return nil
	})
}
func appendPlaybookEvent(next *state, b Playbook, action string, actor ScheduleActor, now time.Time) error {
	id, e := newID("playbook-event-")
	if e != nil {
		return e
	}
	next.PlaybookEvents = slices.DeleteFunc(next.PlaybookEvents, func(v PlaybookEvent) bool { return v.At.Before(now.AddDate(-1, 0, 0)) })
	if len(next.PlaybookEvents) >= 4000 {
		next.PlaybookEvents = next.PlaybookEvents[len(next.PlaybookEvents)-3999:]
	}
	next.PlaybookEvents = append(next.PlaybookEvents, PlaybookEvent{id, b.ID, now.UTC(), actor, action, b.Revision, b.ProgramID, b.Visibility})
	return nil
}
func (s *Service) PlaybookEvents(id, user string, offset, limit int) ([]PlaybookEvent, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.data.Playbooks[id]
	if !ok || b.OwnerID != user {
		return nil, 0, ErrNotFound
	}
	rows := []PlaybookEvent{}
	n := 0
	for i := len(s.data.PlaybookEvents) - 1; i >= 0; i-- {
		v := s.data.PlaybookEvents[i]
		if v.PlaybookID != id || v.At.Before(s.now().AddDate(-1, 0, 0)) {
			continue
		}
		if n >= offset && len(rows) < limit {
			rows = append(rows, v)
		}
		n++
	}
	return rows, n, nil
}
func prunePrograms(next *state) {
	used := map[string]bool{}
	for _, b := range next.Playbooks {
		used[b.ProgramID] = true
	}
	for _, p := range next.Plans {
		if p.ProgramID != "" {
			used[p.ProgramID] = true
		}
	}
	for _, r := range next.Runs {
		if r.ProgramID != "" {
			used[r.ProgramID] = true
		}
	}
	for id := range next.Programs {
		if !used[id] {
			delete(next.Programs, id)
		}
	}
}
func programCapacity(next *state) bool {
	if len(next.Programs) > 512 {
		return false
	}
	total := 0
	for _, p := range next.Programs {
		raw, e := json.Marshal(p)
		if e != nil {
			return false
		}
		total += len(raw)
		if total > 8<<20 {
			return false
		}
	}
	return true
}
func normalizedBindings(in map[string]any) (map[string]any, error) {
	if len(in) > 64 {
		return nil, ErrInvalid
	}
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > 8192 {
		return nil, ErrInvalid
	}
	for key := range in {
		if !playbooks.ValidVariable(key) {
			return nil, ErrInvalid
		}
	}
	return playbooks.CloneValues(in), nil
}
func (s *Service) preparePlaybook(owner string, in PlanInput) (PlanInput, error) {
	if in.Command != "" || in.TemplateID != "" {
		return in, ErrInvalid
	}
	s.mu.Lock()
	b, ok := s.data.Playbooks[in.PlaybookID]
	p := s.data.Programs[b.ProgramID]
	s.mu.Unlock()
	if !ok || b.OwnerID != owner && b.Visibility != "organization" {
		return in, ErrNotFound
	}
	variables, e := normalizedBindings(in.Variables)
	if e != nil {
		return in, e
	}
	in.Variables = variables
	if p.MaxSteps*len(in.AssetIDs) > 2000 {
		return in, ErrInvalid
	}
	if in.PlaybookTimeout == 0 {
		in.PlaybookTimeout = 3600
	}
	if in.PlaybookTimeout < 1 || in.PlaybookTimeout > 86400 {
		return in, ErrInvalid
	}
	in.ProgramID = b.ProgramID
	in.PlaybookRevision = b.Revision
	in.Command = "playbook " + b.ID + "@" + b.ProgramID
	return in, nil
}
func (s *Service) RunProgram(id, user string, canReadAll bool) (playbooks.Program, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Runs[id]
	if !ok || r.ProgramID == "" || r.OwnerID != user && !canReadAll {
		return playbooks.Program{}, ErrNotFound
	}
	p, ok := s.data.Programs[r.ProgramID]
	if !ok {
		return playbooks.Program{}, ErrNotFound
	}
	return playbooks.CloneProgram(p), nil
}
func (s *Service) SetPlaybookAuthorizer(fn func(string, string, accesspolicies.Origin) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.playbookAuthorize = fn
}
