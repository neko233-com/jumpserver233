package operations

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"maps"
	"slices"
	"strings"
	"time"
)

type LocalEvidence struct {
	Result playbooks.Result `json:"result"`
	Extra  map[string]any   `json:"extra,omitempty"`
}
type StepResult struct {
	ID             string         `json:"id"`
	TaskIndex      int            `json:"task_index"`
	Name           string         `json:"name"`
	Module         string         `json:"module"`
	Iteration      int            `json:"iteration"`
	Attempt        int            `json:"attempt"`
	State          string         `json:"state"`
	Final          bool           `json:"final"`
	Changed        bool           `json:"changed"`
	Failed         bool           `json:"failed"`
	Ignored        bool           `json:"ignored,omitempty"`
	JobID          string         `json:"job_id,omitempty"`
	ReviewID       string         `json:"review_id,omitempty"`
	ErrorCode      string         `json:"error_code,omitempty"`
	Command        string         `json:"pending_command,omitempty"`
	CommandSHA256  string         `json:"command_sha256,omitempty"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	CreatedAt      time.Time      `json:"created_at"`
	FinishedAt     time.Time      `json:"finished_at,omitzero"`
	RetryAt        time.Time      `json:"retry_at,omitzero"`
	Local          *LocalEvidence `json:"local,omitempty"`
}

func cloneInventory(in map[string]string) map[string]string { return maps.Clone(in) }
func cloneWorkflowPlan(p Plan) Plan {
	p.Variables = playbooks.CloneValues(p.Variables)
	p.Inventory = maps.Clone(p.Inventory)
	p.PlanInput.Inventory = nil
	p.PlanInput.ProgramID = ""
	p.PlanInput.PlaybookRevision = 0
	return p
}
func cloneWorkflowRun(r Run) Run {
	r.Variables = playbooks.CloneValues(r.Variables)
	r.Inventory = maps.Clone(r.Inventory)
	r.Items = slices.Clone(r.Items)
	for i := range r.Items {
		r.Items[i].Steps = slices.Clone(r.Items[i].Steps)
		if r.Items[i].LoopValues != nil {
			raw, _ := json.Marshal(r.Items[i].LoopValues)
			_ = json.Unmarshal(raw, &r.Items[i].LoopValues)
		}
		for j := range r.Items[i].Steps {
			step := &r.Items[i].Steps[j]
			if step.Local != nil {
				copy := *step.Local
				copy.Extra = playbooks.CloneValues(copy.Extra)
				step.Local = &copy
			}
		}
	}
	return r
}

// PublicRun omits controller-only loop values, local output and pending commands.
// Outputs are read through the separate job-output permission boundary.
func PublicRun(r Run) Run {
	r = cloneWorkflowRun(r)
	for i := range r.Items {
		r.Items[i].LoopValues = nil
		for j := range r.Items[i].Steps {
			r.Items[i].Steps[j].Local = nil
			r.Items[i].Steps[j].Command = ""
		}
	}
	return r
}
func clonePlaybookState(out *state, in state) {
	out.Playbooks = maps.Clone(in.Playbooks)
	out.Programs = maps.Clone(in.Programs)
	out.PlaybookEvents = slices.Clone(in.PlaybookEvents)
	if out.Playbooks == nil {
		out.Playbooks = map[string]Playbook{}
	}
	if out.Programs == nil {
		out.Programs = map[string]playbooks.Program{}
	}
}
func validatePrograms(st *state, format int) error {
	if st.Playbooks == nil {
		st.Playbooks = map[string]Playbook{}
	}
	if st.Programs == nil {
		st.Programs = map[string]playbooks.Program{}
	}
	if len(st.Playbooks) > 200 || len(st.PlaybookEvents) > 4000 || !programCapacity(st) || format < 4 && (len(st.Playbooks) > 0 || len(st.Programs) > 0 || len(st.PlaybookEvents) > 0) {
		return ErrInvalid
	}
	for id, p := range st.Programs {
		if len(id) != 64 || p.Version != 1 || playbooks.WorkspaceID(p.Files) != id {
			return ErrInvalid
		}
		compiled, e := playbooks.Compile(playbooks.Workspace{Files: p.Files})
		if e != nil {
			return e
		}
		a, _ := json.Marshal(compiled)
		b, _ := json.Marshal(p)
		if string(a) != string(b) {
			return ErrInvalid
		}
		st.Programs[id] = compiled
	}
	for id, b := range st.Playbooks {
		p, ok := st.Programs[b.ProgramID]
		if id != b.ID || !ok || b.OwnerID == "" || b.Revision < 1 || !validName(b.Name) || b.TaskCount != len(p.Tasks) || !slices.Contains([]string{"private", "organization"}, b.Visibility) {
			return ErrInvalid
		}
	}
	reserved := 0
	for _, p := range st.Plans {
		if p.ProgramID == "" {
			if p.PlaybookID != "" {
				return ErrInvalid
			}
			continue
		}
		program, ok := st.Programs[p.ProgramID]
		if format < 4 || !ok || p.PlaybookID == "" || p.PlaybookRevision < 1 || p.Discovery != nil || p.HostPlugin != nil || p.TemplateID != "" || p.Command != "playbook "+p.PlaybookID+"@"+p.ProgramID || program.MaxSteps*len(p.AssetIDs) > 2000 || p.PlaybookTimeout < 1 || p.PlaybookTimeout > 86400 {
			return ErrInvalid
		}
		if _, e := normalizedBindings(p.Variables); e != nil {
			return e
		}
	}
	for _, r := range st.Runs {
		reserved += r.StepReservation
		if r.ProgramID == "" && r.StepReservation != 0 {
			return ErrInvalid
		}
	}
	if reserved > 20000 {
		return ErrInvalid
	}
	return nil
}
func canReservePlaybook(st *state, p Plan) bool {
	program, ok := st.Programs[p.ProgramID]
	if !ok {
		return false
	}
	count := program.MaxSteps * len(p.AssetIDs)
	if count < 1 || count > 2000 {
		return false
	}
	for _, r := range st.Runs {
		count += r.StepReservation
	}
	return count <= 20000
}
func initPlaybookRun(r *Run, p Plan, st *state, now time.Time) {
	if p.ProgramID == "" {
		return
	}
	r.ProgramID = p.ProgramID
	r.PlaybookID = p.PlaybookID
	r.PlaybookRevision = p.PlaybookRevision
	r.Variables = playbooks.CloneValues(p.Variables)
	r.Inventory = maps.Clone(p.Inventory)
	r.Deadline = now.Add(time.Duration(p.PlaybookTimeout) * time.Second)
	r.StepReservation = st.Programs[p.ProgramID].MaxSteps * len(p.AssetIDs)
}
func stepInput(r Run, asset string, step StepResult) jobs.Input {
	sum := sha256.Sum256([]byte(r.ID + ":" + asset + ":" + step.ID))
	return jobs.Input{PlaybookStep: &playbooks.Execution{RunID: r.ID, StepID: step.ID, ProgramID: r.ProgramID, TaskIndex: step.TaskIndex}, Origin: r.AccessOrigin, AssetID: asset, Command: step.Command, TimeoutSeconds: step.TimeoutSeconds, RequestID: "operation-" + hex.EncodeToString(sum[:])}
}
func (s *Service) WorkflowJobAllowed(owner, asset string, meta playbooks.Execution, command string) bool {
	if meta.Validate() != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.data.Runs[meta.RunID]
	if !ok || r.OwnerID != owner || r.ProgramID != meta.ProgramID || r.Cancelled || terminalRun(r.State) || !s.now().Before(r.Deadline) {
		return false
	}
	sum := sha256.Sum256([]byte(command))
	digest := hex.EncodeToString(sum[:])
	for _, item := range r.Items {
		if item.AssetID != asset || terminalItem(item.State) || len(item.Steps) == 0 {
			continue
		}
		step := item.Steps[len(item.Steps)-1]
		return !step.Final && step.ID == meta.StepID && step.TaskIndex == meta.TaskIndex && step.CommandSHA256 == digest
	}
	return false
}
func terminalItem(s string) bool {
	return !slices.Contains([]string{"pending", "running", "waiting_review"}, s)
}
func (s *Service) recoverPlaybook(r *Run, format int) error {
	p, ok := s.data.Programs[r.ProgramID]
	if format < 4 || !ok || r.OwnerID == "" || len(r.Items) < 1 || len(r.Items) > 50 || r.Deadline.IsZero() || r.StepReservation != p.MaxSteps*len(r.Items) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for index := range r.Items {
		item := &r.Items[index]
		if item.TaskCursor < 0 || item.TaskCursor > len(p.Tasks) || len(item.Steps) > p.MaxSteps {
			return ErrInvalid
		}
		raw, e := json.Marshal(item.LoopValues)
		if e != nil || len(raw) > 8192 {
			return ErrInvalid
		}
		for i := range item.Steps {
			step := &item.Steps[i]
			if step.ID == "" || seen[step.ID] || step.TaskIndex < 0 || step.TaskIndex >= len(p.Tasks) || step.Iteration < 0 || step.Iteration >= 50 || step.Attempt < 0 || step.Attempt > p.Tasks[step.TaskIndex].Retries || step.Module != p.Tasks[step.TaskIndex].Module || step.TimeoutSeconds < 1 || step.TimeoutSeconds > 300 {
				return ErrInvalid
			}
			seen[step.ID] = true
			if step.State != "dispatching" || step.Final {
				continue
			}
			if step.Command == "" {
				return ErrInvalid
			}
			job, found, e := s.jobs.FindRequest(r.OwnerID, stepInput(*r, item.AssetID, *step))
			if e != nil {
				return e
			}
			if found {
				step.JobID = job.ID
				step.State = job.State
				item.JobID = job.ID
				if terminalJob(job.State) {
					step.State = "running"
				}
			} else {
				step.Final = true
				step.State = "interrupted"
				step.ErrorCode = "dispatch_interrupted"
				step.FinishedAt = s.now().UTC()
				item.State = "interrupted"
				item.ErrorCode = step.ErrorCode
			}
		}
	}
	r.State = runState(*r)
	return nil
}
func terminalJob(s string) bool { return s != "running" && s != "pending_review" }
func (s *Service) workflowEnvironment(r Run, item Item, p playbooks.Program) (map[string]any, error) {
	name := r.Inventory[item.AssetID]
	if name == "" {
		name = item.AssetID
	}
	env := map[string]any{"jms_asset_id": item.AssetID, "inventory_hostname": name}
	loops := map[string][]any{}
	for _, step := range item.Steps {
		if !step.Final || step.State == "retried" {
			continue
		}
		task := p.Tasks[step.TaskIndex]
		result, extra, e := s.stepEvidence(step)
		if e != nil {
			return nil, e
		}
		vars := playbooks.Overlay(result.Variables(), extra)
		if facts, ok := extra["ansible_facts"]; ok {
			env["ansible_facts"] = facts
		}
		if facts, ok := extra["facts"].(map[string]any); ok {
			env = playbooks.Overlay(env, facts)
		}
		if task.Register != "" {
			if task.Loop == nil {
				env[task.Register] = vars
			} else {
				key := fmt.Sprintf("%d:%s", step.TaskIndex, task.Register)
				loops[key] = append(loops[key], vars)
				env[task.Register] = map[string]any{"results": loops[key]}
			}
		}
		raw, e := json.Marshal(env)
		if e != nil || len(raw) > 64<<10 {
			return nil, ErrInvalid
		}
	}
	return env, nil
}
func (s *Service) stepEvidence(step StepResult) (playbooks.Result, map[string]any, error) {
	if step.Local != nil {
		return step.Local.Result, playbooks.CloneValues(step.Local.Extra), nil
	}
	if step.State == "skipped" && step.JobID == "" {
		return playbooks.Result{Skipped: true}, nil, nil
	}
	job, e := s.jobs.Get(step.JobID)
	if e != nil || job.State != "succeeded" && job.ErrorCode != "remote_exit" {
		return playbooks.Result{}, nil, ErrInvalid
	}
	result, extra, e := playbooks.Output(step.Module, job.Stdout, job.Stderr, job.ExitCode)
	if e != nil {
		return result, nil, e
	}
	result.Changed = step.Changed
	result.Failed = step.Failed
	return result, extra, nil
}
func (s *Service) StepOutput(runID, assetID, stepID string) (LocalEvidence, error) {
	r, e := s.Run(runID)
	if e != nil {
		return LocalEvidence{}, e
	}
	for _, item := range r.Items {
		if item.AssetID != assetID {
			continue
		}
		for _, step := range item.Steps {
			if step.ID != stepID {
				continue
			}
			if !step.Final {
				return LocalEvidence{}, ErrConflict
			}
			result, extra, e := s.stepEvidence(step)
			return LocalEvidence{result, extra}, e
		}
	}
	return LocalEvidence{}, ErrNotFound
}
func (s *Service) tickPlaybook(r Run, now time.Time) {
	if terminalRun(r.State) {
		return
	}
	if r.Cancelled || !now.Before(r.Deadline) {
		s.finishPlaybook(r, now)
		return
	}
	s.mu.Lock()
	p, ok := s.data.Programs[r.ProgramID]
	authorize := s.playbookAuthorize
	s.mu.Unlock()
	if !ok {
		return
	}
	for index, item := range r.Items {
		if terminalItem(item.State) {
			continue
		}
		if authorize == nil || authorize(r.OwnerID, item.AssetID, r.AccessOrigin) != nil {
			s.denyPlaybookItem(r.ID, index, "access_denied", now)
			continue
		}
		if len(item.Steps) > 0 {
			last := item.Steps[len(item.Steps)-1]
			if !last.Final {
				s.tickPlaybookStep(r, index, item, last, p, now)
				continue
			}
		}
		if item.TaskCursor >= len(p.Tasks) {
			_ = s.updateItem(r.ID, index, func(i *Item) { i.State = "succeeded"; i.ErrorCode = ""; i.LoopValues = nil })
			continue
		}
		task := p.Tasks[item.TaskCursor]
		base, e := s.workflowEnvironment(r, item, p)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "variables_unavailable", now)
			continue
		}
		env, e := playbooks.ResolveVariables(base, task.Vars, r.Variables, true)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "variables_invalid", now)
			continue
		}
		loop := item.LoopValues
		unnotified := task.Handler && !notified(item, p, task)
		if loop == nil {
			if unnotified {
				loop = []any{nil}
			} else {
				loop, e = playbooks.LoopValues(task.Loop, env)
				if e != nil {
					s.denyPlaybookItem(r.ID, index, "variables_invalid", now)
					continue
				}
			}
		}
		emptyLoop := len(loop) == 0
		if emptyLoop {
			loop = []any{nil}
		}
		iteration := 0
		if len(item.Steps) > 0 {
			last := item.Steps[len(item.Steps)-1]
			if last.TaskIndex == item.TaskCursor {
				iteration = last.Iteration + 1
			}
		}
		if iteration >= len(loop) {
			_ = s.updateItem(r.ID, index, func(i *Item) { i.TaskCursor++; i.LoopValues = nil })
			continue
		}
		base["item"] = loop[iteration]
		allowed := !emptyLoop && !unnotified
		if allowed {
			env, e = playbooks.ResolveVariables(base, task.Vars, r.Variables, true)
			if e != nil {
				s.denyPlaybookItem(r.ID, index, "variables_invalid", now)
				continue
			}
			allowed, e = playbooks.All(task.When, env)
			if e != nil {
				s.denyPlaybookItem(r.ID, index, "condition_invalid", now)
				continue
			}
		}
		if allowed {
			env, e = playbooks.ResolveVariables(base, task.Vars, r.Variables, false)
			if e != nil {
				s.denyPlaybookItem(r.ID, index, "variables_invalid", now)
				continue
			}
		}
		var action playbooks.Action
		if allowed {
			action, e = playbooks.Prepare(p, task, env)
			if e != nil {
				s.denyPlaybookItem(r.ID, index, "module_invalid", now)
				continue
			}
		} else {
			action.Local = "skipped"
		}
		step, e := makeStep(task, item.TaskCursor, iteration, 0, action, r.TimeoutSeconds, now)
		if e != nil {
			continue
		}
		if !allowed {
			step.State = "skipping"
		}
		if !s.appendWorkflowStep(r.ID, index, item, step, loop) {
			continue
		}
		fresh, _ := s.Run(r.ID)
		s.tickPlaybookStep(fresh, index, fresh.Items[index], step, p, now)
	}
}
func terminalRun(state string) bool {
	return !slices.Contains([]string{"running", "waiting_review"}, state)
}
func notified(item Item, p playbooks.Program, handler playbooks.Task) bool {
	for _, step := range item.Steps {
		if !step.Final || step.State != "succeeded" || !step.Changed {
			continue
		}
		t := p.Tasks[step.TaskIndex]
		if t.Play == handler.Play && slices.Contains(t.Notify, handler.Name) {
			return true
		}
	}
	return false
}
func makeStep(task playbooks.Task, index, iteration, attempt int, action playbooks.Action, timeout int, now time.Time) (StepResult, error) {
	id, e := newID("step-")
	if e != nil {
		return StepResult{}, e
	}
	if task.Timeout > 0 {
		timeout = task.Timeout
	}
	step := StepResult{ID: id, TaskIndex: index, Name: task.Name, Module: task.Module, Iteration: iteration, Attempt: attempt, State: "pending", Command: action.Command, TimeoutSeconds: timeout, CreatedAt: now}
	if action.Command != "" {
		sum := sha256.Sum256([]byte(action.Command))
		step.CommandSHA256 = hex.EncodeToString(sum[:])
	}
	if action.Local != "" {
		step.State = "local"
	}
	return step, nil
}
func (s *Service) appendWorkflowStep(id string, index int, expected Item, step StepResult, loop []any) bool {
	ok := false
	_ = s.mutate(func(st *state) error {
		r, exists := st.Runs[id]
		if !exists || r.Cancelled || terminalItem(r.Items[index].State) || r.Items[index].TaskCursor != expected.TaskCursor || len(r.Items[index].Steps) != len(expected.Steps) {
			return errNoChange
		}
		r.Items[index].Steps = append(r.Items[index].Steps, step)
		r.Items[index].LoopValues = loop
		r.Items[index].State = "running"
		r.Items[index].ErrorCode = ""
		r.Items[index].JobID = ""
		r.State = runState(r)
		st.Runs[id] = r
		ok = true
		return nil
	})
	return ok
}
func (s *Service) mutateStep(id string, index int, stepID string, fn func(*StepResult, *Item, *Run) error) error {
	return s.mutate(func(st *state) error {
		r, ok := st.Runs[id]
		if !ok || index >= len(r.Items) || len(r.Items[index].Steps) == 0 {
			return ErrNotFound
		}
		item := &r.Items[index]
		step := &item.Steps[len(item.Steps)-1]
		if step.ID != stepID || step.Final || r.Cancelled {
			return errNoChange
		}
		if e := fn(step, item, &r); e != nil {
			return e
		}
		r.State = runState(r)
		st.Runs[id] = r
		return nil
	})
}
func (s *Service) tickPlaybookStep(r Run, index int, item Item, step StepResult, p playbooks.Program, now time.Time) {
	if step.Final || step.RetryAt.After(now) {
		return
	}
	task := p.Tasks[step.TaskIndex]
	if step.State == "skipping" {
		s.completeEvidence(r, index, item, step, p, playbooks.Result{Skipped: true}, nil, now)
		return
	}
	if step.State == "retrying" {
		s.retryPlaybookStep(r, index, item, step, p, now)
		return
	}
	if step.State == "dispatching" {
		job, found, e := s.jobs.FindRequest(r.OwnerID, stepInput(r, item.AssetID, step))
		if e != nil || !found {
			s.denyPlaybookItem(r.ID, index, "dispatch_interrupted", now)
			return
		}
		_ = s.mutateStep(r.ID, index, step.ID, func(current *StepResult, i *Item, _ *Run) error {
			current.JobID = job.ID
			current.State = "running"
			i.JobID = job.ID
			i.State = "running"
			return nil
		})
		return
	}
	if step.JobID != "" {
		job, e := s.jobs.Get(step.JobID)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "result_unavailable", now)
			return
		}
		if !terminalJob(job.State) {
			if step.State != job.State {
				_ = s.mutateStep(r.ID, index, step.ID, func(c *StepResult, i *Item, _ *Run) error {
					c.State = job.State
					i.State = "running"
					if job.State == "pending_review" {
						i.State = "waiting_review"
					}
					return nil
				})
			}
			return
		}
		s.completeRemoteStep(r, index, item, step, p, job, now)
		return
	}
	if step.State == "local" || step.State == "waiting" {
		base, e := s.workflowEnvironment(r, item, p)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "variables_unavailable", now)
			return
		}
		if step.Iteration < len(item.LoopValues) {
			base["item"] = item.LoopValues[step.Iteration]
		}
		env, e := playbooks.ResolveVariables(base, task.Vars, r.Variables, false)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "variables_invalid", now)
			return
		}
		allowed, e := playbooks.All(task.When, env)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "condition_invalid", now)
			return
		}
		if task.Handler {
			allowed = allowed && notified(item, p, task)
		}
		if !allowed {
			s.completeEvidence(r, index, item, step, p, playbooks.Result{Skipped: true}, nil, now)
			return
		}
		action, e := playbooks.Prepare(p, task, env)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "module_invalid", now)
			return
		}
		if action.Local == "pause" && step.State != "waiting" {
			_ = s.mutateStep(r.ID, index, step.ID, func(c *StepResult, _ *Item, _ *Run) error {
				c.State = "waiting"
				c.RetryAt = now.Add(time.Duration(action.PauseSeconds) * time.Second)
				return nil
			})
			return
		}
		result, extra, e := playbooks.LocalResult(action)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "module_invalid", now)
			return
		}
		s.completeEvidence(r, index, item, step, p, result, extra, now)
		return
	}
	if s.submit == nil {
		return
	}
	claimed := false
	if e := s.mutateStep(r.ID, index, step.ID, func(c *StepResult, i *Item, _ *Run) error {
		if c.State != "pending" && c.State != "waiting_review" {
			return errNoChange
		}
		c.State = "dispatching"
		i.State = "running"
		claimed = true
		return nil
	}); e != nil || !claimed {
		return
	}
	out, e := s.submit(r.OwnerID, stepInput(r, item.AssetID, step), step.ReviewID)
	persisted := s.mutateStep(r.ID, index, step.ID, func(c *StepResult, i *Item, _ *Run) error {
		switch {
		case errors.Is(e, ErrBusy):
			c.State = "pending"
			c.ErrorCode = "capacity"
			c.RetryAt = now.Add(time.Second)
		case errors.Is(e, ErrDenied):
			c.State = "denied"
			c.Final = true
			c.Command = ""
			c.ErrorCode = "access_denied"
			c.FinishedAt = now
			i.State = "denied"
			i.ErrorCode = c.ErrorCode
		case e != nil:
			c.State = "failed"
			c.Final = true
			c.Command = ""
			c.ErrorCode = "dispatch_failed"
			c.FinishedAt = now
			i.State = "failed"
			i.ErrorCode = c.ErrorCode
		case out.ReviewID != "":
			c.State = "waiting_review"
			c.ReviewID = out.ReviewID
			c.RetryAt = now.Add(time.Second)
			i.State = "waiting_review"
		case out.Job.ID != "":
			c.State = "running"
			c.JobID = out.Job.ID
			c.Command = ""
			i.JobID = out.Job.ID
			i.State = "running"
		default:
			c.State = "failed"
			c.Final = true
			c.ErrorCode = "dispatch_failed"
			c.FinishedAt = now
			i.State = "failed"
			i.ErrorCode = c.ErrorCode
		}
		return nil
	})
	if persisted != nil && out.Job.ID != "" {
		fresh, e := s.Run(r.ID)
		if e == nil && fresh.Cancelled {
			_ = s.jobs.Cancel(out.Job.ID)
		}
	}
}
func (s *Service) completeRemoteStep(r Run, index int, item Item, step StepResult, p playbooks.Program, job jobs.Job, now time.Time) {
	if job.State != "succeeded" && job.ErrorCode != "remote_exit" {
		s.denyPlaybookItem(r.ID, index, job.ErrorCode, now)
		return
	}
	result, extra, e := playbooks.Output(step.Module, job.Stdout, job.Stderr, job.ExitCode)
	if e != nil || job.Truncated && (step.Module == "stat" || step.Module == "setup") {
		s.denyPlaybookItem(r.ID, index, "invalid_module_result", now)
		return
	}
	s.completeEvidence(r, index, item, step, p, result, extra, now)
}
func (s *Service) completeEvidence(r Run, index int, item Item, step StepResult, p playbooks.Program, result playbooks.Result, extra map[string]any, now time.Time) {
	if result.Skipped {
		_ = s.mutateStep(r.ID, index, step.ID, func(c *StepResult, i *Item, _ *Run) error {
			c.Final = true
			c.State = "skipped"
			c.FinishedAt = now
			c.Command = ""
			if c.JobID == "" {
				c.Local = &LocalEvidence{Result: result}
			}
			i.State = "running"
			advanceWorkflowCursor(i, *c)
			return nil
		})
		return
	}
	task := p.Tasks[step.TaskIndex]
	base, e := s.workflowEnvironment(r, item, p)
	if e != nil {
		s.denyPlaybookItem(r.ID, index, "variables_unavailable", now)
		return
	}
	if step.Iteration < len(item.LoopValues) {
		base["item"] = item.LoopValues[step.Iteration]
	}
	env, e := playbooks.ResolveVariables(base, task.Vars, r.Variables, false)
	if e != nil {
		s.denyPlaybookItem(r.ID, index, "variables_invalid", now)
		return
	}
	variables := playbooks.Overlay(result.Variables(), extra)
	env["result"] = variables
	if task.Register != "" {
		env[task.Register] = variables
	}
	if !result.Skipped && len(task.ChangedWhen) > 0 {
		result.Changed, e = playbooks.All(task.ChangedWhen, env)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "condition_invalid", now)
			return
		}
	}
	if !result.Skipped && len(task.FailedWhen) > 0 {
		result.Failed, e = playbooks.All(task.FailedWhen, env)
		if e != nil {
			s.denyPlaybookItem(r.ID, index, "condition_invalid", now)
			return
		}
	}
	until, e := playbooks.All(task.Until, env)
	if e != nil {
		s.denyPlaybookItem(r.ID, index, "condition_invalid", now)
		return
	}
	retry := !result.Skipped && len(task.Until) > 0 && (!until || result.Failed) && step.Attempt < task.Retries
	if !until && !retry {
		result.Failed = true
	}
	_ = s.mutateStep(r.ID, index, step.ID, func(c *StepResult, i *Item, _ *Run) error {
		c.Changed = result.Changed
		c.Failed = result.Failed
		c.FinishedAt = now
		c.Command = ""
		if c.JobID == "" {
			c.Local = &LocalEvidence{result, playbooks.CloneValues(extra)}
		}
		if retry {
			c.State = "retrying"
			c.ErrorCode = "condition_unmet"
			c.RetryAt = now.Add(time.Duration(task.Delay) * time.Second)
			i.State = "running"
			return nil
		}
		c.Final = true
		c.State = "succeeded"
		c.ErrorCode = ""
		if result.Skipped {
			c.State = "skipped"
		}
		if result.Failed {
			c.State = "failed"
			c.ErrorCode = "task_failed"
			if !until {
				c.ErrorCode = "condition_unmet"
			}
			c.Ignored = task.IgnoreErrors
		}
		if result.Failed && !c.Ignored {
			i.State = "failed"
			i.ErrorCode = c.ErrorCode
		} else {
			i.State = "running"
			i.ErrorCode = ""
			advanceWorkflowCursor(i, *c)
		}
		return nil
	})
}
func (s *Service) retryPlaybookStep(r Run, index int, item Item, last StepResult, p playbooks.Program, now time.Time) {
	task := p.Tasks[last.TaskIndex]
	base, e := s.workflowEnvironment(r, item, p)
	if e != nil {
		s.denyPlaybookItem(r.ID, index, "variables_unavailable", now)
		return
	}
	if last.Iteration < len(item.LoopValues) {
		base["item"] = item.LoopValues[last.Iteration]
	}
	env, e := playbooks.ResolveVariables(base, task.Vars, r.Variables, false)
	if e != nil {
		s.denyPlaybookItem(r.ID, index, "variables_invalid", now)
		return
	}
	action, e := playbooks.Prepare(p, task, env)
	if e != nil {
		s.denyPlaybookItem(r.ID, index, "module_invalid", now)
		return
	}
	step, e := makeStep(task, last.TaskIndex, last.Iteration, last.Attempt+1, action, r.TimeoutSeconds, now)
	if e != nil {
		return
	}
	_ = s.mutateStep(r.ID, index, last.ID, func(current *StepResult, i *Item, _ *Run) error {
		if current.State != "retrying" {
			return errNoChange
		}
		current.State = "retried"
		current.Final = true
		i.Steps = append(i.Steps, step)
		i.JobID = ""
		i.State = "running"
		return nil
	})
}
func (s *Service) denyPlaybookItem(id string, index int, code string, now time.Time) {
	var job string
	_ = s.updateItem(id, index, func(i *Item) {
		i.State = "failed"
		i.ErrorCode = code
		i.LoopValues = nil
		if len(i.Steps) > 0 {
			step := &i.Steps[len(i.Steps)-1]
			if !step.Final {
				job = step.JobID
				step.State = "failed"
				step.Final = true
				step.Failed = true
				step.Command = ""
				step.ErrorCode = code
				step.FinishedAt = now
			}
		}
	})
	if job != "" {
		_ = s.jobs.Cancel(job)
	}
}
func (s *Service) finishPlaybook(r Run, now time.Time) {
	var ids []string
	_ = s.mutate(func(st *state) error {
		current, ok := st.Runs[r.ID]
		if !ok {
			return ErrNotFound
		}
		code := "cancelled"
		if !current.Cancelled {
			code = "deadline_exceeded"
			current.ErrorCode = code
		}
		for i := range current.Items {
			item := &current.Items[i]
			if terminalItem(item.State) && item.State != "cancelled" {
				continue
			}
			item.State = "cancelled"
			if !current.Cancelled {
				item.State = "timed_out"
			}
			item.ErrorCode = code
			item.LoopValues = nil
			if len(item.Steps) > 0 {
				step := &item.Steps[len(item.Steps)-1]
				if !step.Final {
					if step.JobID != "" {
						ids = append(ids, step.JobID)
					}
					step.State = item.State
					step.Command = ""
					step.ErrorCode = code
					step.Final = true
					step.FinishedAt = now
				}
			}
		}
		current.State = runState(current)
		st.Runs[r.ID] = current
		return nil
	})
	for _, id := range ids {
		_ = s.jobs.Cancel(id)
	}
}
func advanceWorkflowCursor(item *Item, step StepResult) {
	if step.Iteration+1 >= len(item.LoopValues) {
		item.TaskCursor++
		item.LoopValues = nil
	}
}
func (s *Service) TriggerPlan(id, requestID string, actor ScheduleActor, origin accesspolicies.Origin) (Run, error) {
	if requestID == "" || len(requestID) > 100 || strings.ContainsAny(requestID, "\x00\r\n") || actor.ID == "" {
		return Run{}, ErrInvalid
	}
	var out Run
	e := s.mutate(func(st *state) error {
		for _, r := range st.Runs {
			if r.RequestID == requestID && r.TriggeredBy.ID == actor.ID {
				if r.PlanID != id || r.AccessOrigin != origin {
					return ErrConflict
				}
				out = r
				return nil
			}
		}
		p, ok := st.Plans[id]
		if !ok {
			return ErrNotFound
		}
		if p.HostPlugin != nil || p.Discovery != nil {
			return ErrConflict
		}
		if len(st.Runs) >= 1000 || p.ProgramID != "" && !canReservePlaybook(st, p) {
			return ErrBusy
		}
		for _, r := range st.Runs {
			if r.PlanID == id && !terminalRun(r.State) {
				return ErrConflict
			}
		}
		runID, e := newID("run-")
		if e != nil {
			return e
		}
		now := s.now().UTC()
		r := Run{ID: runID, PlanID: p.ID, PlanRevision: p.ConfigRevision, OwnerID: p.OwnerID, Owner: p.Owner, Name: p.Name, Command: p.Command, TimeoutSeconds: p.TimeoutSeconds, CreatedAt: now, ScheduledFor: now, State: "running", Items: []Item{}, Trigger: "manual", TriggeredBy: actor, RequestID: requestID, AccessOrigin: origin}
		initPlaybookRun(&r, p, st, now)
		for _, asset := range p.AssetIDs {
			r.Items = append(r.Items, Item{AssetID: asset, State: "pending"})
		}
		st.Runs[r.ID] = r
		p.LastRunID = r.ID
		st.Plans[p.ID] = p
		out = r
		return nil
	})
	return cloneWorkflowRun(out), e
}
