package operations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid  = jobs.ErrInvalid
	ErrNotFound = jobs.ErrNotFound
	ErrConflict = jobs.ErrConflict
	ErrBusy     = jobs.ErrBusy
	ErrDenied   = errors.New("operation access denied")
)

type TemplateInput struct {
	WorkingDirectory string `json:"working_directory,omitempty"`
	Name             string `json:"name"`
	Command          string `json:"command"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	Revision         int    `json:"revision"`
}
type Template struct {
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	Owner   string `json:"owner"`
	TemplateInput
	UpdatedAt time.Time `json:"updated_at"`
}
type PlanInput struct {
	WorkingDirectory string                `json:"working_directory,omitempty"`
	ProgramID        string                `json:"-"`
	PlaybookRevision int                   `json:"-"`
	Inventory        map[string]string     `json:"-"`
	PlaybookID       string                `json:"playbook_id,omitempty"`
	Variables        map[string]any        `json:"variables,omitempty"`
	PlaybookTimeout  int                   `json:"playbook_timeout_seconds,omitempty"`
	Origin           accesspolicies.Origin `json:"-"`
	Name             string                `json:"name"`
	AssetIDs         []string              `json:"asset_ids"`
	Command          string                `json:"command"`
	TimeoutSeconds   int                   `json:"timeout_seconds"`
	TemplateID       string                `json:"template_id,omitempty"`
	Kind             string                `json:"kind"` // batch, once, interval, cron
	RunAt            time.Time             `json:"run_at,omitzero"`
	IntervalSeconds  int                   `json:"interval_seconds,omitempty"`
	CronExpression   string                `json:"cron_expression,omitempty"`
	Timezone         string                `json:"timezone,omitempty"`
	EndAt            time.Time             `json:"end_at,omitzero"`
	MisfirePolicy    string                `json:"misfire_policy,omitempty"`
	GraceSeconds     int                   `json:"grace_seconds,omitempty"`
	FoldPolicy       string                `json:"fold_policy,omitempty"`
	RequestID        string                `json:"request_id"`
}
type Plan struct {
	ProgramID           string                      `json:"program_id,omitempty"`
	PlaybookRevision    int                         `json:"playbook_revision,omitempty"`
	Inventory           map[string]string           `json:"inventory,omitempty"`
	CreationHash        string                      `json:"creation_hash,omitempty"`
	LastScheduledAt     time.Time                   `json:"last_scheduled_at,omitzero"`
	CalendarWatermark   string                      `json:"calendar_watermark,omitempty"`
	SkippedTriggers     uint64                      `json:"skipped_triggers,omitempty"`
	Discovery           *accountdiscovery.Operation `json:"account_discovery,omitempty"`
	ConfigRevision      int                         `json:"config_revision,omitempty"`
	HostPlugin          *hostplugins.Operation      `json:"host_plugin,omitempty"`
	CollectionSequence  uint64                      `json:"collection_sequence,omitempty"`
	CollectionAccount   string                      `json:"collection_account,omitempty"`
	CollectionAssetName string                      `json:"collection_asset_name,omitempty"`
	AccessOrigin        accesspolicies.Origin       `json:"access_origin,omitempty"`
	ID                  string                      `json:"id"`
	OwnerID             string                      `json:"owner_id"`
	Owner               string                      `json:"owner"`
	PlanInput
	TemplateRevision int       `json:"template_revision,omitempty"`
	Enabled          bool      `json:"enabled"`
	NextRun          time.Time `json:"next_run,omitzero"`
	LastRunID        string    `json:"last_run_id,omitempty"`
	ErrorCode        string    `json:"error_code,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}
type Item struct {
	LoopValues []any        `json:"loop_values,omitempty"`
	Steps      []StepResult `json:"steps,omitempty"`
	TaskCursor int          `json:"task_cursor,omitempty"`
	AssetID    string       `json:"asset_id"`
	JobID      string       `json:"job_id,omitempty"`
	State      string       `json:"state"`
	ReviewID   string       `json:"review_id,omitempty"`
	ErrorCode  string       `json:"error_code,omitempty"`
	RetryAt    time.Time    `json:"retry_at,omitzero"`
}
type Run struct {
	WorkingDirectory    string                      `json:"working_directory,omitempty"`
	ProgramID           string                      `json:"program_id,omitempty"`
	PlaybookID          string                      `json:"playbook_id,omitempty"`
	PlaybookRevision    int                         `json:"playbook_revision,omitempty"`
	Variables           map[string]any              `json:"variables,omitempty"`
	Inventory           map[string]string           `json:"inventory,omitempty"`
	Deadline            time.Time                   `json:"deadline,omitzero"`
	StepReservation     int                         `json:"step_reservation,omitempty"`
	Trigger             string                      `json:"trigger,omitempty"`
	TriggeredBy         ScheduleActor               `json:"triggered_by,omitempty"`
	RequestID           string                      `json:"request_id,omitempty"`
	ErrorCode           string                      `json:"error_code,omitempty"`
	ScheduledFor        time.Time                   `json:"scheduled_for,omitzero"`
	PlanRevision        int                         `json:"plan_revision,omitempty"`
	LatenessSeconds     int64                       `json:"lateness_seconds,omitempty"`
	Coalesced           bool                        `json:"coalesced,omitempty"`
	Owner               string                      `json:"owner,omitempty"`
	Discovery           *accountdiscovery.Operation `json:"account_discovery,omitempty"`
	HostPlugin          *hostplugins.Operation      `json:"host_plugin,omitempty"`
	CollectionSequence  uint64                      `json:"collection_sequence,omitempty"`
	CollectionAccount   string                      `json:"collection_account,omitempty"`
	CollectionAssetName string                      `json:"collection_asset_name,omitempty"`
	AccessOrigin        accesspolicies.Origin       `json:"access_origin,omitempty"`
	ID                  string                      `json:"id"`
	PlanID              string                      `json:"plan_id"`
	OwnerID             string                      `json:"owner_id"`
	Name                string                      `json:"name"`
	Command             string                      `json:"command"`
	TimeoutSeconds      int                         `json:"timeout_seconds"`
	CreatedAt           time.Time                   `json:"created_at"`
	Cancelled           bool                        `json:"cancelled"`
	Items               []Item                      `json:"items"`
	State               string                      `json:"state"`
}
type Submission struct {
	Job      jobs.Job
	ReviewID string
}
type SubmitFunc func(ownerID string, input jobs.Input, reviewID string) (Submission, error)
type state struct {
	Playbooks      map[string]Playbook          `json:"playbooks,omitempty"`
	Programs       map[string]playbooks.Program `json:"programs,omitempty"`
	PlaybookEvents []PlaybookEvent              `json:"playbook_events,omitempty"`
	ScheduleEvents []ScheduleEvent              `json:"schedule_events,omitempty"`
	Templates      map[string]Template          `json:"templates"`
	Plans          map[string]Plan              `json:"plans"`
	Runs           map[string]Run               `json:"runs"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Service struct {
	admission         *workgate.Gate
	mu                sync.Mutex
	tickMu            sync.Mutex
	path              string
	documents         *storage.Documents
	aead              cipher.AEAD
	data              state
	jobs              *jobs.Service
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	started           bool
	abandoned         bool
	archive           func(Run, *jobs.Job) error
	resolve           func(jobs.Input) (jobs.Input, error)
	submit            SubmitFunc
	playbookAuthorize func(string, string, accesspolicies.Origin) error
	now               func() time.Time
}

func Open(path string, key []byte, documents *storage.Documents, jobService *jobs.Service) (*Service, error) {
	if jobService == nil {
		return nil, fmt.Errorf("job service is required")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{path: path, documents: documents, aead: aead, jobs: jobService, ctx: ctx, cancel: cancel, now: time.Now, data: state{Templates: map[string]Template{}, Plans: map[string]Plan{}, Runs: map[string]Run{}, Playbooks: map[string]Playbook{}, Programs: map[string]playbooks.Program{}}}
	var data []byte
	if documents != nil {
		data, err = documents.LoadOrImport("operations", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		cancel()
		return nil, err
	}
	formatVersion := 1
	if len(data) > 0 {
		var e envelope
		if json.Unmarshal(data, &e) != nil || e.Version < 1 || e.Version > 5 || len(e.Nonce) != aead.NonceSize() {
			cancel()
			return nil, fmt.Errorf("invalid operations store")
		}
		formatVersion = e.Version
		plain, err := aead.Open(nil, e.Nonce, e.Ciphertext, []byte(fmt.Sprintf("jms233/operations/v%d", e.Version)))
		if err != nil {
			cancel()
			return nil, err
		}
		if json.Unmarshal(plain, &s.data) != nil || s.data.Templates == nil || s.data.Plans == nil || s.data.Runs == nil || len(s.data.Templates) > 500 || len(s.data.Plans) > 1000 || len(s.data.Runs) > 1000 || len(s.data.ScheduleEvents) > 4000 {
			cancel()
			return nil, fmt.Errorf("invalid operations records")
		}
	}
	changed := false
	if err := validateOperationDirectories(s.data, formatVersion); err != nil {
		cancel()
		return nil, err
	}
	if err := validatePrograms(&s.data, formatVersion); err != nil {
		cancel()
		return nil, err
	}
	for id, p := range s.data.Plans {
		if p.Discovery != nil && formatVersion < 2 {
			cancel()
			return nil, ErrInvalid
		}
		if p.Discovery != nil && (p.HostPlugin != nil || p.Discovery.Validate() != nil || p.Discovery.PlanID != p.ID || p.Discovery.Sequence != 0 || p.Discovery.Account != p.CollectionAccount || p.ConfigRevision < 1 || len(p.AssetIDs) != 1 || p.Kind != "interval" || p.Command != p.Discovery.Command()) {
			cancel()
			return nil, ErrInvalid
		}
		if p.HostPlugin != nil && (!collectorOperation(p.HostPlugin) || p.Command != p.HostPlugin.Command() || len(p.AssetIDs) != 1 || p.Kind != "interval") {
			cancel()
			return nil, ErrInvalid
		}
		if _, e := normalizeSchedule(scheduleOf(p.PlanInput), time.Now().UTC(), true); e != nil || p.Kind == "cron" && (formatVersion < 3 || p.ConfigRevision < 1 || p.Enabled && p.NextRun.IsZero()) {
			cancel()
			return nil, ErrInvalid
		}
		if p.ConfigRevision == 0 {
			p.ConfigRevision = 1
			changed = true
		}
		if p.HostPlugin == nil && p.Discovery == nil && p.CreationHash == "" {
			original := p.PlanInput
			original.Origin = p.AccessOrigin
			p.CreationHash = creationHash(original)
			changed = true
		}
		s.data.Plans[id] = p
	}
	// A persisted claim may have crossed the SSH boundary. Link an existing
	// idempotent job, otherwise mark interrupted; never submit the claim again.
	for id, run := range s.data.Runs {
		if run.ProgramID != "" {
			if err := s.recoverPlaybook(&run, formatVersion); err != nil {
				cancel()
				return nil, err
			}
			s.data.Runs[id] = run
			changed = true
			continue
		}
		if run.Discovery != nil && formatVersion < 2 {
			cancel()
			return nil, ErrInvalid
		}
		if run.Discovery != nil && (run.HostPlugin != nil || run.Discovery.Validate() != nil || run.Discovery.PlanID != run.PlanID || run.Discovery.Sequence == 0 || run.Discovery.Sequence != run.CollectionSequence || run.Discovery.Account != run.CollectionAccount || len(run.Items) != 1 || run.Command != run.Discovery.Command()) {
			cancel()
			return nil, ErrInvalid
		}
		if run.ID != id || run.OwnerID == "" || len(run.Items) > 50 || run.HostPlugin != nil && (!collectorOperation(run.HostPlugin) || run.CollectionSequence == 0 || len(run.Items) != 1) {
			cancel()
			return nil, fmt.Errorf("invalid operation run")
		}
		if run.AccessOrigin.Method == "" {
			run.AccessOrigin.Method = "scheduled_exec"
			if p, ok := s.data.Plans[run.PlanID]; ok && p.Kind == "batch" {
				run.AccessOrigin.Method = "exec"
			}
			changed = true
		}
		for i, item := range run.Items {
			if item.State != "dispatching" {
				continue
			}
			in := jobInput(run, item.AssetID)
			job, found, err := s.jobs.FindRequest(run.OwnerID, in)
			if err != nil {
				cancel()
				return nil, err
			}
			if found {
				item.JobID = job.ID
				item.State = job.State
			} else {
				item.State = "interrupted"
				item.ErrorCode = "dispatch_interrupted"
			}
			run.Items[i] = item
			changed = true
		}
		run.State = runState(run)
		s.data.Runs[id] = run
	}
	if changed {
		if err := s.persist(s.data); err != nil {
			cancel()
			return nil, err
		}
	}
	return s, nil
}
func clone(in state) state {
	out := state{Templates: map[string]Template{}, Plans: map[string]Plan{}, Runs: map[string]Run{}}
	clonePlaybookState(&out, in)
	for id, t := range in.Templates {
		out.Templates[id] = t
	}
	for id, p := range in.Plans {
		p.AssetIDs = append([]string(nil), p.AssetIDs...)
		p.Variables = playbooks.CloneValues(p.Variables)
		p.Inventory = cloneInventory(p.Inventory)
		p.HostPlugin = clonePlugin(p.HostPlugin)
		p.Discovery = cloneDiscovery(p.Discovery)
		out.Plans[id] = p
	}
	for id, r := range in.Runs {
		r = cloneWorkflowRun(r)
		r.Items = append([]Item(nil), r.Items...)
		r.HostPlugin = clonePlugin(r.HostPlugin)
		r.Discovery = cloneDiscovery(r.Discovery)
		out.Runs[id] = r
	}
	out.ScheduleEvents = append([]ScheduleEvent(nil), in.ScheduleEvents...)
	return out
}
func (s *Service) mutate(fn func(*state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.abandoned {
		return ErrBusy
	}
	next := clone(s.data)
	if err := fn(&next); err != nil {
		return err
	}
	if err := s.persist(next); err != nil {
		return err
	}
	s.data = next
	return nil
}
func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
func validName(name string) bool {
	return strings.TrimSpace(name) != "" && len(name) <= 100 && strings.IndexFunc(name, unicode.IsControl) < 0
}
func (s *Service) SaveTemplate(id, ownerID, owner string, in TemplateInput) (Template, error) {
	in.Name = strings.TrimSpace(in.Name)
	validated, err := jobs.Validate(jobs.Input{WorkingDirectory: in.WorkingDirectory, AssetID: "template", Command: in.Command, TimeoutSeconds: in.TimeoutSeconds})
	if err != nil || !validName(in.Name) {
		return Template{}, ErrInvalid
	}
	in.Command = validated.Command
	in.TimeoutSeconds = validated.TimeoutSeconds
	var result Template
	err = s.mutate(func(next *state) error {
		if id == "" {
			if len(next.Templates) >= 500 {
				return ErrBusy
			}
			var err error
			id, err = newID("template-")
			if err != nil {
				return err
			}
			in.Revision = 1
		} else {
			old, ok := next.Templates[id]
			if !ok || old.OwnerID != ownerID {
				return ErrNotFound
			}
			if old.Revision != in.Revision {
				return ErrConflict
			}
			in.Revision++
		}
		result = Template{ID: id, OwnerID: ownerID, Owner: owner, TemplateInput: in, UpdatedAt: s.now().UTC()}
		next.Templates[id] = result
		return nil
	})
	return result, err
}
func (s *Service) DeleteTemplate(id, owner string, revision int) error {
	return s.mutate(func(next *state) error {
		t, ok := next.Templates[id]
		if !ok || t.OwnerID != owner {
			return ErrNotFound
		}
		if t.Revision != revision {
			return ErrConflict
		}
		delete(next.Templates, id)
		return nil
	})
}
func (s *Service) Templates(owner string) []Template {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []Template{}
	for _, t := range s.data.Templates {
		if t.OwnerID == owner {
			items = append(items, t)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}
func (s *Service) Prepare(owner string, in PlanInput) (PlanInput, int, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.AssetIDs = append([]string(nil), in.AssetIDs...)
	sort.Strings(in.AssetIDs)
	if !validName(in.Name) || len(in.AssetIDs) < 1 || len(in.AssetIDs) > 50 || len(in.RequestID) < 1 || len(in.RequestID) > 100 || strings.IndexFunc(in.RequestID, unicode.IsControl) >= 0 {
		return in, 0, ErrInvalid
	}
	for i, id := range in.AssetIDs {
		if id == "" || len(id) > 128 || (i > 0 && id == in.AssetIDs[i-1]) {
			return in, 0, ErrInvalid
		}
	}
	revision := 0
	if in.PlaybookID != "" {
		var e error
		in, e = s.preparePlaybook(owner, in)
		if e != nil {
			return in, 0, e
		}
	} else if len(in.Variables) > 0 || in.PlaybookTimeout != 0 {
		return in, 0, ErrInvalid
	}
	if in.TemplateID != "" {
		if in.Command != "" {
			return in, 0, ErrInvalid
		}
		s.mu.Lock()
		t, ok := s.data.Templates[in.TemplateID]
		s.mu.Unlock()
		if !ok || t.OwnerID != owner {
			return in, 0, ErrNotFound
		}
		in.Command = t.Command
		in.TimeoutSeconds = t.TimeoutSeconds
		if in.WorkingDirectory != "" && in.WorkingDirectory != t.WorkingDirectory {
			return in, 0, ErrInvalid
		}
		in.WorkingDirectory = t.WorkingDirectory
		revision = t.Revision
	}
	validated, err := jobs.Validate(jobs.Input{WorkingDirectory: in.WorkingDirectory, AssetID: in.AssetIDs[0], Command: in.Command, TimeoutSeconds: in.TimeoutSeconds})
	if err != nil {
		return in, 0, err
	}
	in.Command = validated.Command
	in.TimeoutSeconds = validated.TimeoutSeconds
	c, e := normalizeSchedule(scheduleOf(in), s.now().UTC(), false)
	if e != nil {
		return in, 0, e
	}
	applySchedule(&in, c)
	return in, revision, nil
}

// CreatePlan accepts only a prepared snapshot; templates are resolved by the
// caller before authorization so template edits cannot alter approved payloads.
func (s *Service) CreatePlan(ownerID, owner string, in PlanInput, revision int) (Plan, error) {
	return s.createPlan(ownerID, owner, in, revision, nil, nil, "", "", "")
}
func (s *Service) createPlan(ownerID, owner string, in PlanInput, revision int, plugin *hostplugins.Operation, discovery *accountdiscovery.Operation, parent, account, assetName string) (Plan, error) {
	if !validOperationDirectory(in.WorkingDirectory, plugin != nil || discovery != nil) {
		return Plan{}, ErrInvalid
	}
	var result Plan
	err := s.mutate(func(next *state) error {
		for _, p := range next.Plans {
			if p.OwnerID == ownerID && p.RequestID == in.RequestID {
				previous := p.PlanInput
				previous.Origin = p.AccessOrigin
				expected := cloneDiscovery(discovery)
				if expected != nil {
					expected.PlanID = p.ID
					expected.ParentAssetID = parent
					expected.Account = account
				}
				same := reflect.DeepEqual(previous, in)
				if p.CreationHash != "" && plugin == nil && discovery == nil {
					same = p.CreationHash == creationHash(in)
				}
				if !same || !reflect.DeepEqual(p.HostPlugin, plugin) || !reflect.DeepEqual(p.Discovery, expected) {
					return ErrConflict
				}
				result = p
				return nil
			}
		}
		if plugin != nil {
			for _, p := range next.Plans {
				if p.HostPlugin != nil && p.Enabled && p.OwnerID == ownerID && p.AssetIDs[0] == in.AssetIDs[0] {
					return ErrConflict
				}
			}
		}
		if discovery != nil {
			for _, p := range next.Plans {
				if p.Discovery != nil && p.Enabled && p.OwnerID == ownerID && p.Discovery.ParentAssetID == parent {
					return ErrConflict
				}
			}
		}
		if len(next.Plans) >= 1000 {
			return ErrBusy
		}
		id, err := newID("plan-")
		if err != nil {
			return err
		}
		now := s.now().UTC()
		due, e := firstOccurrence(scheduleOf(in), now)
		if e != nil {
			return ErrInvalid
		}
		if discovery != nil && in.RunAt.IsZero() {
			due = now
		}
		result = Plan{HostPlugin: clonePlugin(plugin), CollectionAccount: account, CollectionAssetName: assetName, AccessOrigin: in.Origin, ID: id, OwnerID: ownerID, Owner: owner, PlanInput: in, TemplateRevision: revision, Enabled: true, NextRun: due, CreatedAt: now}
		result.ProgramID = in.ProgramID
		result.PlaybookRevision = in.PlaybookRevision
		result.Inventory = cloneInventory(in.Inventory)
		result.Variables = playbooks.CloneValues(in.Variables)
		result.PlanInput.ProgramID = ""
		result.PlanInput.PlaybookRevision = 0
		result.PlanInput.Inventory = nil
		result.ConfigRevision = 1
		if plugin == nil && discovery == nil {
			result.CreationHash = creationHash(in)
		}
		if discovery != nil {
			result.Discovery = cloneDiscovery(discovery)
			result.Discovery.PlanID = id
			result.Discovery.ParentAssetID = parent
			result.Discovery.Account = account
			result.ConfigRevision = 1
		}
		result.AssetIDs = append([]string(nil), in.AssetIDs...)
		next.Plans[id] = result
		if plugin == nil && discovery == nil {
			return appendScheduleEvent(next, result, Schedule{}, "created", ScheduleActor{ownerID, owner}, now)
		}
		return nil
	})
	result.HostPlugin = clonePlugin(result.HostPlugin)
	result.Discovery = cloneDiscovery(result.Discovery)
	result.AssetIDs = append([]string(nil), result.AssetIDs...)
	return cloneWorkflowPlan(result), err
}
func (s *Service) Plans(owner string) []Plan {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []Plan{}
	for _, p := range s.data.Plans {
		if owner == "" || p.OwnerID == owner {
			p.AssetIDs = append([]string(nil), p.AssetIDs...)
			p.HostPlugin = clonePlugin(p.HostPlugin)
			p.Discovery = cloneDiscovery(p.Discovery)
			items = append(items, cloneWorkflowPlan(p))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items
}
func (s *Service) Plan(id string) (Plan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.data.Plans[id]
	if !ok {
		return p, ErrNotFound
	}
	p.AssetIDs = append([]string(nil), p.AssetIDs...)
	p.HostPlugin = clonePlugin(p.HostPlugin)
	p.Discovery = cloneDiscovery(p.Discovery)
	return cloneWorkflowPlan(p), nil
}
func (s *Service) SetEnabled(id string, enabled bool) error {
	_, e := s.SetEnabledRevision(id, enabled, 0, ScheduleActor{})
	return e
}
func (s *Service) Runs(owner string, offset, limit int) ([]Run, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := []Run{}
	for _, r := range s.data.Runs {
		if owner == "" || r.OwnerID == owner {
			r.Items = append([]Item(nil), r.Items...)
			r.HostPlugin = clonePlugin(r.HostPlugin)
			r.Discovery = cloneDiscovery(r.Discovery)
			items = append(items, cloneWorkflowRun(r))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
	total := len(items)
	offset = min(max(offset, 0), total)
	return items[offset:min(total, offset+limit)], total
}
func (s *Service) Run(id string) (Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Runs[id]
	if !ok {
		return r, ErrNotFound
	}
	r.Items = append([]Item(nil), r.Items...)
	r.HostPlugin = clonePlugin(r.HostPlugin)
	r.Discovery = cloneDiscovery(r.Discovery)
	return cloneWorkflowRun(r), nil
}
func (s *Service) CancelRun(id string) error {
	var ids []string
	book := false
	err := s.mutate(func(next *state) error {
		r, ok := next.Runs[id]
		if !ok {
			return ErrNotFound
		}
		r.Cancelled = true
		book = r.ProgramID != ""
		for i, item := range r.Items {
			if item.JobID != "" {
				ids = append(ids, item.JobID)
			}
			if item.JobID == "" && item.State != "dispatching" {
				item.State = "cancelled"
				r.Items[i] = item
			}
		}
		r.State = runState(r)
		next.Runs[id] = r
		return nil
	})
	if err != nil {
		return err
	}
	for _, jobID := range ids {
		_ = s.jobs.Cancel(jobID)
	}
	if book {
		if r, e := s.Run(id); e == nil {
			s.finishPlaybook(r, s.now().UTC())
		}
	}
	return nil
}
func (s *Service) Start(submit SubmitFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started || s.ctx.Err() != nil {
		return
	}
	s.started = true
	s.submit = submit
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.Tick()
			}
		}
	}()
}
func (s *Service) Tick() {
	s.mu.Lock()
	admission := s.admission
	s.mu.Unlock()
	_, release, e := admission.Enter(s.ctx, "plan_dispatch")
	if e != nil {
		return
	}
	defer release()
	s.tickMu.Lock()
	defer s.tickMu.Unlock()
	if s.ctx.Err() != nil {
		return
	}
	s.archiveCollectors()
	s.mu.Lock()
	resolve := s.resolve
	s.mu.Unlock()
	now := s.now().UTC()
	_ = s.mutate(func(next *state) error {
		changed := false
		for id, p := range next.Plans {
			if !p.Enabled || p.NextRun.After(now) {
				continue
			}
			if !p.EndAt.IsZero() && !now.Before(p.EndAt) {
				if e := endSchedule(next, &p, now); e != nil {
					return e
				}
				next.Plans[id] = p
				changed = true
				continue
			}
			if p.Kind == "interval" || p.Kind == "cron" {
				overlaps := false
				for _, prior := range next.Runs {
					if prior.PlanID == p.ID && (prior.State == "running" || prior.State == "waiting_review") {
						overlaps = true
						break
					}
				}
				misfire := p.Kind == "cron" && p.MisfirePolicy == "skip" && now.Sub(p.NextRun) > time.Duration(p.GraceSeconds)*time.Second
				if overlaps || misfire {
					markOccurrence(&p)
					due, e := nextPlanOccurrence(p, now)
					p.NextRun = due
					p.SkippedTriggers++
					p.ErrorCode = "missed_skipped"
					if overlaps {
						p.ErrorCode = "previous_run_active"
					}
					if e != nil {
						if e := endSchedule(next, &p, now); e != nil {
							return e
						}
					}
					next.Plans[id] = p
					changed = true
					continue
				}
			}
			if len(next.Runs) >= 1000 {
				// Collectors retry after their receipt outbox recovers and frees hot runs.
				if p.HostPlugin == nil && p.Discovery == nil {
					p.Enabled = false
				}
				p.ErrorCode = "history_full"
				next.Plans[id] = p
				changed = true
				continue
			}
			if p.ProgramID != "" && !canReservePlaybook(next, p) {
				p.Enabled = false
				p.ErrorCode = "history_full"
				next.Plans[id] = p
				changed = true
				continue
			}
			runID, err := newID("run-")
			if err != nil {
				return err
			}
			origin := p.AccessOrigin
			origin.Method = "scheduled_exec"
			if p.Kind == "batch" {
				origin.Method = "exec"
			}
			if p.HostPlugin != nil || p.Discovery != nil {
				if p.CollectionSequence >= 1<<53-1 {
					p.Enabled = false
					p.ErrorCode = "history_full"
					next.Plans[id] = p
					changed = true
					continue
				}
				p.CollectionSequence++
			}
			r := Run{WorkingDirectory: p.WorkingDirectory, HostPlugin: clonePlugin(p.HostPlugin), CollectionSequence: p.CollectionSequence, CollectionAccount: p.CollectionAccount, CollectionAssetName: p.CollectionAssetName, AccessOrigin: origin, ID: runID, PlanID: p.ID, OwnerID: p.OwnerID, Name: p.Name, Command: p.Command, TimeoutSeconds: p.TimeoutSeconds, CreatedAt: now, State: "running", Items: []Item{}}
			initPlaybookRun(&r, p, next, now)
			r.Trigger = "schedule"
			r.TriggeredBy = ScheduleActor{"system", "system"}
			r.ScheduledFor = p.NextRun
			r.PlanRevision = p.ConfigRevision
			r.LatenessSeconds = max(0, int64(now.Sub(p.NextRun)/time.Second))
			r.Coalesced = p.Kind == "cron" && r.LatenessSeconds > int64(p.GraceSeconds)
			r.Owner = p.Owner
			r.Discovery = cloneDiscovery(p.Discovery)
			if r.Discovery != nil {
				r.Discovery.Sequence = r.CollectionSequence
			}
			for _, assetID := range p.AssetIDs {
				r.Items = append(r.Items, Item{AssetID: assetID, State: "pending"})
			}
			next.Runs[runID] = r
			p.LastRunID = runID
			p.ErrorCode = ""
			markOccurrence(&p)
			if p.Kind == "interval" || p.Kind == "cron" {
				p.NextRun, err = nextPlanOccurrence(p, now)
				if err != nil {
					if e := endSchedule(next, &p, now); e != nil {
						return e
					}
				}
			} else {
				p.Enabled = false
				p.NextRun = time.Time{}
			}
			next.Plans[id] = p
			changed = true
		}
		if !changed {
			return errNoChange
		}
		return nil
	})
	runs, _ := s.Runs("", 0, 1000)
	sort.Slice(runs, func(i, j int) bool { return runs[i].CreatedAt.Before(runs[j].CreatedAt) })
	for _, run := range runs {
		if run.ProgramID != "" {
			s.tickPlaybook(run, now)
			continue
		}
		for index, item := range run.Items {
			if s.ctx.Err() != nil {
				return
			}
			if item.JobID != "" {
				job, err := s.jobs.Get(item.JobID)
				if err == nil && job.State != item.State {
					_ = s.updateItem(run.ID, index, func(current *Item) { current.State = job.State; current.ErrorCode = job.ErrorCode })
					if run.Discovery != nil && (job.ErrorCode == "access_policy_denied" || job.State == "denied" || job.ErrorCode == "review_expired") {
						s.pauseDeniedDiscovery(run.PlanID)
					}
				}
				continue
			}
			if run.Cancelled || item.State != "pending" && item.State != "waiting_review" || item.RetryAt.After(now) {
				continue
			}
			if s.submit == nil {
				continue
			}
			if (run.HostPlugin != nil || run.Discovery != nil) && resolve != nil {
				input, e := resolve(jobInput(run, item.AssetID))
				if e != nil {
					_ = s.updateItem(run.ID, index, func(x *Item) { x.State = "denied"; x.ErrorCode = "access_denied" })
					if run.Discovery != nil {
						s.pauseDeniedDiscovery(run.PlanID)
					}
					continue
				}
				run.HostPlugin = clonePlugin(input.Plugin)
				run.Discovery = cloneDiscovery(input.Discovery)
				run.Command = input.Command
			}
			claimed := false
			err := s.mutate(func(next *state) error {
				r := next.Runs[run.ID]
				if r.Cancelled || r.Items[index].State != item.State {
					return errNoChange
				}
				r.Items[index].State = "dispatching"
				r.HostPlugin = clonePlugin(run.HostPlugin)
				r.Discovery = cloneDiscovery(run.Discovery)
				r.Command = run.Command
				next.Runs[run.ID] = r
				claimed = true
				return nil
			})
			if err != nil || !claimed {
				continue
			}
			result, err := s.submit(run.OwnerID, jobInput(run, item.AssetID), item.ReviewID)
			cancelJob := false
			_ = s.mutate(func(next *state) error {
				r := next.Runs[run.ID]
				target := r.Items[index]
				if r.Cancelled {
					target.State = "cancelled"
					target.JobID = result.Job.ID
					target.ReviewID = result.ReviewID
					cancelJob = result.Job.ID != ""
				} else {
					switch {
					case errors.Is(err, ErrBusy):
						target.State = "pending"
						target.ErrorCode = "capacity"
						target.RetryAt = now.Add(time.Second)
					case errors.Is(err, ErrDenied):
						target.State = "denied"
						target.ErrorCode = "access_denied"
					case err != nil:
						target.State = "failed"
						target.ErrorCode = "dispatch_failed"
					case result.ReviewID != "":
						target.State = "waiting_review"
						target.ReviewID = result.ReviewID
						target.ErrorCode = ""
						target.RetryAt = now.Add(time.Second)
					case result.Job.ID != "":
						target.State = result.Job.State
						target.JobID = result.Job.ID
						target.ErrorCode = result.Job.ErrorCode
					default:
						target.State = "failed"
						target.ErrorCode = "dispatch_failed"
					}
				}
				r.Items[index] = target
				r.State = runState(r)
				next.Runs[run.ID] = r
				return nil
			})
			if cancelJob {
				_ = s.jobs.Cancel(result.Job.ID)
			}
			if run.Discovery != nil && (errors.Is(err, ErrDenied) || result.Job.State == "denied") {
				s.pauseDeniedDiscovery(run.PlanID)
			}
		}
	}
}

var errNoChange = errors.New("no operations change")

func (s *Service) updateItem(id string, index int, fn func(*Item)) error {
	return s.mutate(func(next *state) error {
		r := next.Runs[id]
		fn(&r.Items[index])
		r.State = runState(r)
		next.Runs[id] = r
		return nil
	})
}
func jobInput(r Run, assetID string) jobs.Input {
	digest := sha256.Sum256([]byte(r.ID + ":" + assetID))
	return jobs.Input{WorkingDirectory: r.WorkingDirectory, Discovery: cloneDiscovery(r.Discovery), Plugin: clonePlugin(r.HostPlugin), Origin: r.AccessOrigin, AssetID: assetID, Command: r.Command, TimeoutSeconds: r.TimeoutSeconds, RequestID: "operation-" + hex.EncodeToString(digest[:])}
}
func runState(r Run) string {
	if r.Cancelled {
		return "cancelled"
	}
	success, pending, waiting := 0, 0, 0
	for _, i := range r.Items {
		switch i.State {
		case "succeeded":
			success++
		case "pending", "dispatching", "running":
			pending++
		case "waiting_review", "pending_review":
			waiting++
		}
	}
	if pending > 0 {
		return "running"
	}
	if waiting > 0 {
		return "waiting_review"
	}
	if success == len(r.Items) {
		return "succeeded"
	}
	if success > 0 {
		return "partial"
	}
	return "failed"
}
func (s *Service) Close()   { s.mu.Lock(); s.cancel(); s.mu.Unlock(); s.wg.Wait() }
func (s *Service) Abandon() { s.mu.Lock(); s.abandoned = true; s.cancel(); s.mu.Unlock() }
func (s *Service) persist(next state) error {
	if s.abandoned {
		return ErrBusy
	}
	if err := validateOperationDirectories(next, 5); err != nil {
		return err
	}
	plain, err := json.Marshal(next)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	version := 5
	data, err := json.Marshal(envelope{Version: version, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte(fmt.Sprintf("jms233/operations/v%d", version)))})
	if err != nil {
		return err
	}
	if s.documents != nil {
		return s.documents.Save("operations", data)
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".operations-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
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
	return os.Rename(f.Name(), s.path)
}

func clonePlugin(o *hostplugins.Operation) *hostplugins.Operation {
	if o == nil {
		return nil
	}
	c := o.Clone()
	return &c
}
func collectorOperation(o *hostplugins.Operation) bool {
	return o != nil && o.Plugin == "banhack233" && o.Action == "events_collect" && o.Validate() == nil
}
func (s *Service) CreateCollector(ownerID, owner string, in PlanInput, op hostplugins.Operation, account, assetName string) (Plan, error) {
	if !collectorOperation(&op) || len(in.AssetIDs) != 1 || in.Kind != "interval" || in.IntervalSeconds < 60 || in.IntervalSeconds > 86400 || in.TemplateID != "" || account == "" {
		return Plan{}, ErrInvalid
	}
	in.Command = op.Command()
	in.TimeoutSeconds = 60
	prepared, revision, e := s.Prepare(ownerID, in)
	if e != nil {
		return Plan{}, e
	}
	return s.createPlan(ownerID, owner, prepared, revision, &op, nil, "", account, assetName)
}
func (s *Service) SetCollectorHooks(resolve func(jobs.Input) (jobs.Input, error), archive func(Run, *jobs.Job) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolve = resolve
	s.archive = archive
}
func (s *Service) archiveCollectors() {
	s.mu.Lock()
	archive := s.archive
	s.mu.Unlock()
	if archive == nil {
		return
	}
	runs, _ := s.Runs("", 0, 1000)
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].PlanID == runs[j].PlanID {
			return runs[i].CollectionSequence < runs[j].CollectionSequence
		}
		return runs[i].PlanID < runs[j].PlanID
	})
	blocked := map[string]bool{}
	for _, r := range runs {
		if blocked[r.PlanID] {
			continue
		}
		if (!collectorOperation(r.HostPlugin) && r.Discovery == nil) || len(r.Items) != 1 || r.State == "running" || r.State == "waiting_review" {
			continue
		}
		var job *jobs.Job
		if r.Items[0].JobID != "" {
			j, e := s.jobs.Get(r.Items[0].JobID)
			if e == nil {
				if j.State == "running" || j.State == "pending_review" {
					continue
				}
				job = &j
			} else if !errors.Is(e, jobs.ErrNotFound) {
				continue
			}
		}
		if archive(r, job) != nil {
			blocked[r.PlanID] = true
			continue
		}
		if job != nil {
			if s.jobs.PruneCollector(job.ID) != nil {
				blocked[r.PlanID] = true
				continue
			}
		}
		_ = s.mutate(func(next *state) error {
			current, ok := next.Runs[r.ID]
			if !ok {
				return errNoChange
			}
			if current.State != r.State {
				return ErrConflict
			}
			delete(next.Runs, r.ID)
			return nil
		})
	}
}
