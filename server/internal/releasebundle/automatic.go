package releasebundle

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
)

const automaticFile = ".jms233-automatic.json"

func formatRevision(v int) string { return strconv.Itoa(v) }

// AutomaticPolicy is opt-in. The maintenance window uses UTC to avoid silently
// changing installation time when a host timezone or daylight saving changes.
type AutomaticPolicy struct {
	Revision            int    `json:"revision"`
	Mode                string `json:"mode"`
	IntervalHours       int    `json:"interval_hours"`
	HourUTC             int    `json:"hour_utc"`
	MinuteUTC           int    `json:"minute_utc"`
	WindowMinutes       int    `json:"window_minutes"`
	DrainTimeoutSeconds int    `json:"drain_timeout_seconds"`
}
type AutomaticPolicyInput struct {
	RequestID string          `json:"request_id"`
	Policy    AutomaticPolicy `json:"policy"`
}
type automaticReceipt struct {
	Input   AutomaticPolicyInput `json:"input"`
	ActorID string               `json:"actor_id"`
}
type AutomaticEvent struct {
	At      time.Time `json:"at"`
	Action  string    `json:"action"`
	Actor   string    `json:"actor"`
	Code    string    `json:"code,omitempty"`
	Version string    `json:"version,omitempty"`
}
type AutomaticState struct {
	AttemptedDigests              []string           `json:"attempted_digests,omitempty"`
	Schema                        int                `json:"schema"`
	RootID                        string             `json:"root_id"`
	Policy                        AutomaticPolicy    `json:"policy"`
	Phase                         string             `json:"phase"`
	Error                         string             `json:"error,omitempty"`
	LastAttempt                   time.Time          `json:"last_attempt"`
	LastSuccess                   time.Time          `json:"last_success"`
	NextAttempt                   time.Time          `json:"next_attempt"`
	RunID                         string             `json:"run_id,omitempty"`
	RunRevision                   int                `json:"run_revision,omitempty"`
	Result                        updates.Result     `json:"result"`
	Candidate                     *Selection         `json:"candidate,omitempty"`
	CandidateInstallationRevision int                `json:"candidate_installation_revision,omitempty"`
	Receipts                      []automaticReceipt `json:"receipts,omitempty"`
	Events                        []AutomaticEvent   `json:"events"`
}

func validAutomaticPolicy(p AutomaticPolicy) bool {
	return p.Revision > 0 && (p.Mode == "off" || p.Mode == "prepare" || p.Mode == "install") && p.IntervalHours >= 1 && p.IntervalHours <= 168 && p.HourUTC >= 0 && p.HourUTC <= 23 && p.MinuteUTC >= 0 && p.MinuteUTC <= 59 && p.WindowMinutes >= 5 && p.WindowMinutes <= 180 && p.DrainTimeoutSeconds >= 5 && p.DrainTimeoutSeconds <= 86400
}
func validAutomaticPhase(p string) bool {
	switch p {
	case "idle", "checking", "downloading", "staging", "ready", "failed", "no_update", "attempted":
		return true
	}
	return false
}
func (s *stagingRoot) readAutomatic() (AutomaticState, error) {
	var v AutomaticState
	e := readStageJSON(s.root, automaticFile, &v)
	if errors.Is(e, os.ErrNotExist) {
		return AutomaticState{Schema: 1, RootID: s.owner.ID, Policy: AutomaticPolicy{Revision: 1, Mode: "off", IntervalHours: 24, HourUTC: 2, WindowMinutes: 30, DrainTimeoutSeconds: 600}, Phase: "idle", Result: updates.Result{Status: "not_checked"}, Events: []AutomaticEvent{}}, nil
	}
	if e != nil {
		return v, e
	}
	if v.Schema != 1 || v.RootID != s.owner.ID || !validAutomaticPolicy(v.Policy) || !validAutomaticPhase(v.Phase) || len(v.Error) > 80 || v.RunID != "" && !validID(v.RunID) || len(v.Receipts) > 100 || len(v.Events) > 100 || v.Candidate != nil && (!v.Candidate.valid() || v.CandidateInstallationRevision < 1) {
		return v, ErrInstallConflict
	}
	if !validAutomaticResult(v.Result, s.owner.Platform, s.owner.Architecture) || len(v.AttemptedDigests) > 100 {
		return v, ErrInstallConflict
	}
	tried := map[string]bool{}
	for _, sha := range v.AttemptedDigests {
		if !digest.MatchString(sha) || tried[sha] {
			return v, ErrInstallConflict
		}
		tried[sha] = true
	}
	seen := map[string]bool{}
	for _, r := range v.Receipts {
		if !installRequestID.MatchString(r.Input.RequestID) || seen[r.Input.RequestID] || !validAutomaticPolicy(r.Input.Policy) || r.ActorID == "" || len(r.ActorID) > 128 {
			return v, ErrInstallConflict
		}
		seen[r.Input.RequestID] = true
	}
	return v, nil
}
func (s *stagingRoot) automaticEvent(v *AutomaticState, action, actor, code, version string) {
	v.Events = append(v.Events, AutomaticEvent{At: time.Now().UTC(), Action: action, Actor: actor, Code: code, Version: version})
	if len(v.Events) > 100 {
		v.Events = v.Events[len(v.Events)-100:]
	}
}
func (s *stagingRoot) saveAutomatic(v AutomaticState) error {
	if e := writeStageJSON(s.root, automaticFile, v, false); e != nil {
		return e
	}
	return syncStageDirectory(s.path)
}
func AutomaticStatus(ctx context.Context, path string) (AutomaticState, error) {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return AutomaticState{}, e
	}
	defer s.close()
	return s.readAutomatic()
}

func SaveAutomaticPolicy(ctx context.Context, path string, in AutomaticPolicyInput, actorID, actor string) (AutomaticState, error) {
	if !installRequestID.MatchString(in.RequestID) || !validAutomaticPolicy(in.Policy) || actorID == "" || len(actorID) > 128 || len(actor) > 128 {
		return AutomaticState{}, ErrInvalid
	}
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return AutomaticState{}, e
	}
	defer s.close()
	v, e := s.readAutomatic()
	if e != nil {
		return v, e
	}
	for _, r := range v.Receipts {
		if r.Input.RequestID != in.RequestID {
			continue
		}
		if !reflect.DeepEqual(r.Input, in) || r.ActorID != actorID {
			return v, ErrInstallConflict
		}
		return v, nil
	}
	if in.Policy.Revision != v.Policy.Revision {
		return v, ErrInstallConflict
	}
	schedule, e := s.readSchedule()
	if e != nil {
		return v, e
	}
	if p := schedule.Plan; p != nil && p.AutomaticRevision > 0 && (p.Phase == "stopping" || p.Phase == "installing" || p.Phase == "awaiting_start") {
		return v, ErrInstallPending
	}
	v.Policy = in.Policy
	v.Policy.Revision++
	v.AttemptedDigests = nil
	v.RunID = ""
	v.RunRevision = 0
	v.Error = ""
	if v.Candidate == nil {
		v.Phase = "idle"
	} else {
		v.Phase = "ready"
	}
	v.NextAttempt = time.Now().UTC()
	if at := v.LastAttempt.Add(time.Minute); at.After(v.NextAttempt) {
		v.NextAttempt = at
	}
	v.Receipts = append(v.Receipts, automaticReceipt{Input: in, ActorID: actorID})
	if len(v.Receipts) > 100 {
		v.Receipts = v.Receipts[len(v.Receipts)-100:]
	}
	s.automaticEvent(&v, "policy", actor, "", "")
	return v, s.saveAutomatic(v)
}
func automaticWindow(p AutomaticPolicy, now time.Time) bool {
	now = now.UTC()
	minute := now.Hour()*60 + now.Minute()
	start := p.HourUTC*60 + p.MinuteUTC
	return (minute-start+1440)%1440 < p.WindowMinutes
}

func claimAutomatic(ctx context.Context, path string, now time.Time) (AutomaticState, Installation, error) {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return AutomaticState{}, Installation{}, e
	}
	defer s.close()
	v, e := s.readAutomatic()
	if e != nil {
		return v, Installation{}, e
	}
	if v.Policy.Mode == "off" || !v.NextAttempt.IsZero() && now.Before(v.NextAttempt) || v.RunID != "" {
		return v, Installation{}, updates.ErrBusy
	}
	schedule, e := s.readSchedule()
	if e != nil {
		return v, Installation{}, e
	}
	if activePlan(schedule.Plan) {
		return v, Installation{}, updates.ErrBusy
	}
	installed, e := s.installation()
	if e != nil || !installed.Current.valid() {
		return v, installed, ErrInstallConflict
	}
	if _, e = s.readUpgrade(); !errors.Is(e, os.ErrNotExist) {
		return v, installed, ErrInstallPending
	}
	id, e := stageID()
	if e != nil {
		return v, installed, e
	}
	v.RunID = id
	v.RunRevision = v.Policy.Revision
	v.LastAttempt = now.UTC()
	v.NextAttempt = now.Add(time.Duration(v.Policy.IntervalHours) * time.Hour).UTC()
	v.Phase = "checking"
	v.Error = ""
	s.automaticEvent(&v, "check", "local-update-supervisor", "", "")
	return v, installed, s.saveAutomatic(v)
}
func advanceAutomatic(ctx context.Context, path, run string, revision int, phase string) error {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return e
	}
	defer s.close()
	v, e := s.readAutomatic()
	if e != nil {
		return e
	}
	if v.RunID != run || v.Policy.Revision != revision || v.Policy.Mode == "off" {
		return context.Canceled
	}
	v.Phase = phase
	return s.saveAutomatic(v)
}
func finishAutomatic(ctx context.Context, path, run string, revision int, result updates.Result, candidate *Selection, installationRevision int, cause error) error {
	if result.Status == "" {
		result.Status = "not_checked"
	}
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return e
	}
	defer s.close()
	if !validAutomaticResult(result, s.owner.Platform, s.owner.Architecture) {
		result = updates.Result{Status: "not_checked"}
		if cause == nil {
			cause = updates.ErrFeed
		}
	}
	v, e := s.readAutomatic()
	if e != nil {
		return e
	}
	if v.RunID != run || v.Policy.Revision != revision {
		return nil
	}
	v.RunID = ""
	v.RunRevision = 0
	v.Candidate = nil
	v.CandidateInstallationRevision = 0
	v.Result = result
	v.Error = ""
	v.Phase = "no_update"
	if cause != nil {
		v.Phase = "failed"
		v.Error = updates.ErrorCode(cause)
	} else {
		v.LastSuccess = time.Now().UTC()
		if candidate != nil {
			v.Phase = "ready"
			v.Candidate = candidate
			v.CandidateInstallationRevision = installationRevision
		}
	}
	s.automaticEvent(&v, v.Phase, "local-update-supervisor", v.Error, result.Version)
	return s.saveAutomatic(v)
}
func recoverAutomatic(ctx context.Context, path string) error {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return e
	}
	defer s.close()
	v, e := s.readAutomatic()
	if e != nil {
		return e
	}
	if v.RunID == "" {
		return nil
	}
	v.RunID = ""
	v.RunRevision = 0
	v.Phase = "failed"
	v.Error = "interrupted"
	if v.NextAttempt.Before(time.Now().Add(time.Minute)) {
		v.NextAttempt = time.Now().Add(time.Minute)
	}
	s.automaticEvent(&v, "failed", "local-update-supervisor", "interrupted", "")
	return s.saveAutomatic(v)
}
func automaticAuthorizationFailure(ctx context.Context, path string) error {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return e
	}
	defer s.close()
	v, e := s.readAutomatic()
	if e != nil {
		return e
	}
	if v.Policy.Mode == "off" {
		return nil
	}
	v.Phase = "failed"
	v.Error = "authorization"
	v.NextAttempt = time.Now().Add(time.Minute)
	s.automaticEvent(&v, "failed", "local-update-supervisor", "authorization", "")
	return s.saveAutomatic(v)
}

// Queue and policy validation share one root lock. A policy edit before the
// stopping transition revokes the automatic plan; after stopping it conflicts.
func queueAutomatic(ctx context.Context, path string, now time.Time) (bool, error) {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return false, e
	}
	defer s.close()
	v, e := s.readAutomatic()
	if e != nil {
		return false, e
	}
	schedule, e := s.readSchedule()
	if e != nil {
		return false, e
	}
	if p := schedule.Plan; p != nil && p.AutomaticRevision > 0 && (p.Phase == "scheduled" || p.Phase == "draining") && (v.Policy.Mode != "install" || v.Policy.Revision != p.AutomaticRevision || !automaticWindow(v.Policy, now)) {
		p.Phase = "cancelled"
		s.scheduleEvent(&schedule, "local-update-supervisor")
		return false, s.saveSchedule(schedule)
	}
	if v.Policy.Mode != "install" || v.Phase != "ready" || v.Candidate == nil || !automaticWindow(v.Policy, now) || activePlan(schedule.Plan) {
		return false, nil
	}
	// A revision/digest pair is attempted once even after failed startup. An
	// explicit policy revision is required to authorize another attempt.
	id := "auto-" + formatRevision(v.Policy.Revision) + "-" + v.Candidate.ArchiveSHA256[:24]
	for _, r := range schedule.Receipts {
		if r.Input != nil && r.Input.RequestID == id {
			v.Phase = "attempted"
			s.automaticEvent(&v, "attempted", "local-update-supervisor", "", v.Candidate.Version)
			return false, s.saveAutomatic(v)
		}
	}
	for _, sha := range v.AttemptedDigests {
		if sha == v.Candidate.ArchiveSHA256 {
			v.Phase = "attempted"
			return false, s.saveAutomatic(v)
		}
	}
	if len(v.AttemptedDigests) >= 100 {
		v.Phase = "failed"
		v.Error = "attempt_limit"
		return false, s.saveAutomatic(v)
	}
	i, e := s.installation()
	if e != nil {
		return false, e
	}
	if !versionGreater(v.Candidate.Version, i.Current.Version) {
		v.Phase = "no_update"
		v.Candidate = nil
		v.CandidateInstallationRevision = 0
		return false, s.saveAutomatic(v)
	}
	if i.Revision != v.CandidateInstallationRevision {
		return false, nil
	}
	m, e := s.inspect(ctx, "releases/"+v.Candidate.ArchiveSHA256, v.Candidate.ArchiveSHA256)
	if e != nil {
		return false, e
	}
	if m.PreflightProtocol != 1 || m.ActivationProtocol != 1 || m.Version != v.Candidate.Version || m.Commit != v.Candidate.Commit {
		return false, ErrInstallConflict
	}
	planID, e := stageID()
	if e != nil {
		return false, e
	}
	in := ScheduleInput{Revision: schedule.Revision, RequestID: id, InstallationRevision: i.Revision, ArchiveSHA256: v.Candidate.ArchiveSHA256, NotBefore: now.UTC(), DrainTimeoutSeconds: v.Policy.DrainTimeoutSeconds}
	schedule.Plan = &InstallPlan{ID: planID, Input: in, Target: *v.Candidate, ActorID: "local-update-supervisor", Actor: "local-update-supervisor", Phase: "scheduled", AutomaticRevision: v.Policy.Revision}
	// Reserve before publishing the plan. A crash between the two private files
	// consumes the attempt rather than risking a repeated installation.
	v.AttemptedDigests = append(v.AttemptedDigests, v.Candidate.ArchiveSHA256)
	v.Phase = "attempted"
	if e = s.saveAutomatic(v); e != nil {
		return false, e
	}
	schedule.Receipts = append(schedule.Receipts, scheduleReceipt{Input: &in, ActorID: "local-update-supervisor"})
	if len(schedule.Receipts) > 100 {
		schedule.Receipts = schedule.Receipts[len(schedule.Receipts)-100:]
	}
	s.scheduleEvent(&schedule, "local-update-supervisor")
	return true, s.saveSchedule(schedule)
}
func validAutomaticResult(r updates.Result, platform, arch string) bool {
	if r.Status == "not_checked" || r.Status == "no_release" {
		return r.Version == "" && r.Artifact == nil && r.ReleaseURL == ""
	}
	v, ok := updates.Version(r.Version)
	return ok && v == r.Version && (r.Status == "update_available" || r.Status == "up_to_date" || r.Status == "current_unknown") && r.ReleaseURL == "https://github.com/"+updates.Repository+"/releases/tag/"+v && !r.PublishedAt.IsZero() && (r.Artifact == nil || updates.ValidateArtifactURL(*r.Artifact, v, platform, arch))
}
