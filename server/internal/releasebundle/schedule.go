package releasebundle

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"io/fs"
	"os"
	"reflect"
	"runtime"
	"sort"
	"time"
)

const scheduleFile = ".jms233-schedule.json"

type ScheduleInput struct {
	Revision             int       `json:"revision"`
	RequestID            string    `json:"request_id"`
	InstallationRevision int       `json:"installation_revision"`
	ArchiveSHA256        string    `json:"archive_sha256"`
	NotBefore            time.Time `json:"not_before"`
	DrainTimeoutSeconds  int       `json:"drain_timeout_seconds"`
}
type CancelScheduleInput struct {
	Revision  int    `json:"revision"`
	RequestID string `json:"request_id"`
	PlanID    string `json:"plan_id"`
}
type InstallPlan struct {
	AutomaticRevision int           `json:"automatic_revision,omitempty"`
	ID                string        `json:"id"`
	Input             ScheduleInput `json:"input"`
	Target            Selection     `json:"target"`
	ActorID           string        `json:"actor_id"`
	Actor             string        `json:"actor"`
	Phase             string        `json:"phase"`
	Error             string        `json:"error,omitempty"`
	WorkerID          string        `json:"worker_id,omitempty"`
	ChangedAt         time.Time     `json:"changed_at"`
}
type ScheduleEvent struct {
	At     time.Time `json:"at"`
	PlanID string    `json:"plan_id"`
	Phase  string    `json:"phase"`
	Actor  string    `json:"actor"`
	Error  string    `json:"error,omitempty"`
}
type scheduleReceipt struct {
	Input   *ScheduleInput       `json:"input,omitempty"`
	Cancel  *CancelScheduleInput `json:"cancel,omitempty"`
	ActorID string               `json:"actor_id"`
}
type ScheduleStatus struct {
	Schema           int               `json:"schema"`
	RootID           string            `json:"root_id"`
	Revision         int               `json:"revision"`
	Plan             *InstallPlan      `json:"plan,omitempty"`
	Events           []ScheduleEvent   `json:"events"`
	Receipts         []scheduleReceipt `json:"receipts,omitempty"`
	SupervisorSeenAt time.Time         `json:"supervisor_seen_at"`
}

func activePlan(p *InstallPlan) bool {
	return p != nil && (p.Phase == "scheduled" || p.Phase == "draining" || p.Phase == "stopping" || p.Phase == "installing" || p.Phase == "awaiting_start")
}
func validPlanPhase(p string) bool {
	switch p {
	case "scheduled", "draining", "stopping", "installing", "awaiting_start", "succeeded", "failed", "cancelled":
		return true
	}
	return false
}
func (s *stagingRoot) readSchedule() (ScheduleStatus, error) {
	var v ScheduleStatus
	e := readStageJSON(s.root, scheduleFile, &v)
	if errors.Is(e, os.ErrNotExist) {
		return ScheduleStatus{Schema: 1, RootID: s.owner.ID, Revision: 1, Events: []ScheduleEvent{}}, nil
	}
	if e != nil {
		return v, e
	}
	if v.Schema != 1 || v.RootID != s.owner.ID || v.Revision < 1 || len(v.Events) > 100 || len(v.Receipts) > 100 {
		return v, ErrInstallConflict
	}
	if p := v.Plan; p != nil && (p.AutomaticRevision < 0 || !validID(p.ID) || !validPlanPhase(p.Phase) || !p.Target.valid() || p.Target.ArchiveSHA256 != p.Input.ArchiveSHA256 || !validScheduleInput(p.Input) || p.ActorID == "" || len(p.ActorID) > 128 || len(p.Actor) > 128 || p.WorkerID != "" && !validID(p.WorkerID)) {
		return v, ErrInstallConflict
	}
	ids := map[string]bool{}
	for _, r := range v.Receipts {
		id := ""
		if r.Input != nil && r.Cancel == nil && validScheduleInput(*r.Input) {
			id = r.Input.RequestID
		}
		if r.Cancel != nil && r.Input == nil && validCancelInput(*r.Cancel) {
			id = r.Cancel.RequestID
		}
		if id == "" || ids[id] || r.ActorID == "" || len(r.ActorID) > 128 {
			return v, ErrInstallConflict
		}
		ids[id] = true
	}
	for _, e := range v.Events {
		if !validID(e.PlanID) || !validPlanPhase(e.Phase) || len(e.Actor) > 128 || len(e.Error) > 80 || e.At.IsZero() {
			return v, ErrInstallConflict
		}
	}
	return v, nil
}
func validScheduleInput(v ScheduleInput) bool {
	return v.Revision > 0 && installRequestID.MatchString(v.RequestID) && v.InstallationRevision > 0 && digest.MatchString(v.ArchiveSHA256) && !v.NotBefore.IsZero() && v.DrainTimeoutSeconds >= 5 && v.DrainTimeoutSeconds <= 86400
}
func validCancelInput(v CancelScheduleInput) bool {
	return v.Revision > 0 && installRequestID.MatchString(v.RequestID) && validID(v.PlanID)
}
func (s *stagingRoot) saveSchedule(v ScheduleStatus) error {
	return writeStageJSON(s.root, scheduleFile, v, false)
}
func (s *stagingRoot) scheduleEvent(v *ScheduleStatus, actor string) {
	v.Revision++
	v.Plan.ChangedAt = time.Now().UTC()
	v.Events = append(v.Events, ScheduleEvent{At: v.Plan.ChangedAt, PlanID: v.Plan.ID, Phase: v.Plan.Phase, Actor: actor, Error: v.Plan.Error})
	if len(v.Events) > 100 {
		v.Events = v.Events[len(v.Events)-100:]
	}
}
func ScheduleState(ctx context.Context, path string) (ScheduleStatus, error) {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return ScheduleStatus{}, e
	}
	defer s.close()
	if e = ctx.Err(); e != nil {
		return ScheduleStatus{}, e
	}
	return s.readSchedule()
}

func SaveSchedule(ctx context.Context, path string, in ScheduleInput, actorID, actor string) (ScheduleStatus, error) {
	if !validScheduleInput(in) || actorID == "" || len(actorID) > 128 || len(actor) > 128 {
		return ScheduleStatus{}, ErrInvalid
	}
	in.NotBefore = in.NotBefore.UTC()
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return ScheduleStatus{}, e
	}
	defer s.close()
	v, e := s.readSchedule()
	if e != nil {
		return v, e
	}
	for _, r := range v.Receipts {
		id := ""
		if r.Input != nil {
			id = r.Input.RequestID
		}
		if r.Cancel != nil {
			id = r.Cancel.RequestID
		}
		if id != in.RequestID {
			continue
		}
		if r.Input == nil || !reflect.DeepEqual(*r.Input, in) || r.ActorID != actorID {
			return v, ErrInstallConflict
		}
		return v, nil
	}
	if in.Revision != v.Revision || activePlan(v.Plan) || in.NotBefore.Before(time.Now().Add(-time.Minute)) || in.NotBefore.After(time.Now().Add(366*24*time.Hour)) {
		return v, ErrInstallConflict
	}
	installed, e := s.installation()
	if e != nil {
		return v, e
	}
	if !installed.Current.valid() || in.InstallationRevision != installed.Revision || installed.DataDir == "" {
		return v, ErrInstallConflict
	}
	if _, e = s.readUpgrade(); !errors.Is(e, os.ErrNotExist) {
		return v, ErrInstallPending
	}
	m, e := s.inspect(ctx, "releases/"+in.ArchiveSHA256, in.ArchiveSHA256)
	if e != nil {
		return v, e
	}
	if !versionGreater(m.Version, installed.Current.Version) || m.PreflightProtocol != 1 || m.ActivationProtocol != 1 {
		return v, ErrInstallConflict
	}
	id, e := stageID()
	if e != nil {
		return v, e
	}
	v.Plan = &InstallPlan{ID: id, Input: in, Target: Selection{in.ArchiveSHA256, m.Version, m.Commit}, ActorID: actorID, Actor: actor, Phase: "scheduled"}
	v.Receipts = append(v.Receipts, scheduleReceipt{Input: &in, ActorID: actorID})
	if len(v.Receipts) > 100 {
		v.Receipts = v.Receipts[len(v.Receipts)-100:]
	}
	s.scheduleEvent(&v, actor)
	return v, s.saveSchedule(v)
}
func CancelSchedule(ctx context.Context, path string, in CancelScheduleInput, actorID, actor string) (ScheduleStatus, error) {
	if !validCancelInput(in) || actorID == "" || len(actorID) > 128 || len(actor) > 128 {
		return ScheduleStatus{}, ErrInvalid
	}
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return ScheduleStatus{}, e
	}
	defer s.close()
	if e = ctx.Err(); e != nil {
		return ScheduleStatus{}, e
	}
	v, e := s.readSchedule()
	if e != nil {
		return v, e
	}
	for _, r := range v.Receipts {
		id := ""
		if r.Input != nil {
			id = r.Input.RequestID
		}
		if r.Cancel != nil {
			id = r.Cancel.RequestID
		}
		if id != in.RequestID {
			continue
		}
		if r.Cancel == nil || *r.Cancel != in || r.ActorID != actorID {
			return v, ErrInstallConflict
		}
		return v, nil
	}
	if v.Revision != in.Revision || v.Plan == nil || v.Plan.ID != in.PlanID || (v.Plan.Phase != "scheduled" && v.Plan.Phase != "draining") {
		return v, ErrInstallConflict
	}
	v.Plan.Phase = "cancelled"
	v.Receipts = append(v.Receipts, scheduleReceipt{Cancel: &in, ActorID: actorID})
	if len(v.Receipts) > 100 {
		v.Receipts = v.Receipts[len(v.Receipts)-100:]
	}
	s.scheduleEvent(&v, actor)
	return v, s.saveSchedule(v)
}
func transitionSchedule(ctx context.Context, path, id, worker, from, to, code string) (ScheduleStatus, error) {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return ScheduleStatus{}, e
	}
	defer s.close()
	if e = ctx.Err(); e != nil {
		return ScheduleStatus{}, e
	}
	v, e := s.readSchedule()
	if e != nil {
		return v, e
	}
	if v.Plan == nil || v.Plan.ID != id || v.Plan.Phase != from || !validID(worker) || !validPlanPhase(to) || len(code) > 80 {
		return v, ErrInstallConflict
	}
	if v.Plan.AutomaticRevision > 0 && (to == "draining" || to == "stopping") {
		a, e := s.readAutomatic()
		if e != nil {
			return v, e
		}
		if a.Policy.Mode != "install" || a.Policy.Revision != v.Plan.AutomaticRevision || !automaticWindow(a.Policy, time.Now()) {
			v.Plan.Phase = "cancelled"
			s.scheduleEvent(&v, "local-update-supervisor")
			if e = s.saveSchedule(v); e != nil {
				return v, e
			}
			return v, ErrInstallConflict
		}
	}
	v.Plan.WorkerID = worker
	v.Plan.Phase = to
	v.Plan.Error = code
	s.scheduleEvent(&v, "local-update-supervisor")
	return v, s.saveSchedule(v)
}

// StagedCandidates fully verifies bytes only on explicit candidate refresh.
// The polling state endpoint never repeatedly hashes native executables.
func StagedCandidates(ctx context.Context, path string) ([]Selection, error) {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return nil, e
	}
	defer s.close()
	v, e := s.installation()
	if e != nil {
		return nil, e
	}
	rows, e := fs.ReadDir(s.root.FS(), "releases")
	if e != nil {
		return nil, e
	}
	if len(rows) > 200 {
		return nil, ErrInvalid
	}
	out := []Selection{}
	for _, r := range rows {
		if !digest.MatchString(r.Name()) || !r.IsDir() {
			return nil, ErrStageConflict
		}
		m, e := s.inspect(ctx, "releases/"+r.Name(), r.Name())
		if e != nil {
			return nil, e
		}
		if m.PreflightProtocol == 1 && m.ActivationProtocol == 1 && versionGreater(m.Version, v.Current.Version) {
			out = append(out, Selection{r.Name(), m.Version, m.Commit})
		}
	}
	sort.Slice(out, func(i, j int) bool { return versionGreater(out[i].Version, out[j].Version) })
	return out, nil
}

// Lock contention is retried only before any operation is dispatched.
func openScheduleRoot(ctx context.Context, path string) (*stagingRoot, error) {
	for attempt := 0; ; attempt++ {
		s, e := openStagingRoot(path, runtime.GOOS, runtime.GOARCH, false)
		if !errors.Is(e, maintenance.ErrBusy) || attempt >= 50 {
			return s, e
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
