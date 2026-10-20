package operations

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/neko233-com/jumpserver233/server/internal/core/executionhistory"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
)

type historicalRun struct {
	Run     Run                `json:"run"`
	Program *playbooks.Program `json:"program,omitempty"`
}

func settledRun(r Run) bool {
	if r.State != "succeeded" && r.State != "failed" && r.State != "partial" && r.State != "cancelled" {
		return false
	}
	for _, item := range r.Items {
		if item.State == "dispatching" || item.State == "pending_review" {
			return false
		}
		if !terminalItem(item.State) {
			return false
		}
		for _, step := range item.Steps {
			if !step.Final {
				return false
			}
		}
	}
	return true
}

func decodeHistoricalRun(record executionhistory.Record, full bool) (historicalRun, error) {
	var out historicalRun
	raw := record.Summary
	if full {
		raw = record.Payload
	}
	if json.Unmarshal(raw, &out) != nil {
		return out, executionhistory.ErrInvalid
	}
	r := out.Run
	if r.ID != record.ID || r.OwnerID != record.Owner || !r.CreatedAt.Equal(record.CreatedAt) || !settledRun(r) || !validOperationDirectory(r.WorkingDirectory, false) || r.HostPlugin != nil || r.Discovery != nil || len(r.Items) > 50 || r.RequestID != record.RequestID || r.RequestID != "" && r.TriggeredBy.ID != record.RequestOwner {
		return historicalRun{}, executionhistory.ErrInvalid
	}
	if full && r.ProgramID != "" && (out.Program == nil || out.Program.Version != 1 || playbooks.WorkspaceID(out.Program.Files) != r.ProgramID) {
		return historicalRun{}, executionhistory.ErrInvalid
	}
	return out, nil
}

// compactHistory serializes with dispatch so no in-flight tick can rewrite a
// snapshot after it becomes immutable. It never acquires the jobs mutex.
func (s *Service) compactHistory() error {
	s.tickMu.Lock()
	defer s.tickMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.history == nil {
		return nil
	}
	if s.ctx.Err() != nil || s.abandoned {
		return ErrBusy
	}
	return s.compactHistoryLocked()
}

func (s *Service) compactHistoryLocked() error {
	if s.history == nil {
		return nil
	}
	reserved := 0
	for _, r := range s.data.Runs {
		reserved += r.StepReservation
	}
	if len(s.data.Runs) < 800 && reserved < 18000 {
		return nil
	}
	eligible := []Run{}
	for _, r := range s.data.Runs {
		if !r.CreatedAt.IsZero() && r.HostPlugin == nil && r.Discovery == nil && settledRun(r) {
			eligible = append(eligible, r)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].CreatedAt.Equal(eligible[j].CreatedAt) {
			return eligible[i].ID < eligible[j].ID
		}
		return eligible[i].CreatedAt.Before(eligible[j].CreatedAt)
	})
	if len(eligible) == 0 {
		return nil
	}
	eligible = eligible[:min(64, len(eligible))]
	records := make([]executionhistory.Record, 0, len(eligible))
	for _, r := range eligible {
		payload := historicalRun{Run: cloneWorkflowRun(r)}
		if r.ProgramID != "" {
			p, ok := s.data.Programs[r.ProgramID]
			if !ok {
				return executionhistory.ErrInvalid
			}
			p = playbooks.CloneProgram(p)
			payload.Program = &p
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		summary := historicalRun{Run: PublicRun(r)}
		summary.Run.Variables = nil
		summary.Run.Inventory = nil
		for i := range summary.Run.Items {
			summary.Run.Items[i].Steps = nil
		}
		short, err := json.Marshal(summary)
		if err != nil {
			return err
		}
		records = append(records, executionhistory.Record{Kind: "run", ID: r.ID, Owner: r.OwnerID, RequestOwner: r.TriggeredBy.ID, RequestID: r.RequestID, CreatedAt: r.CreatedAt, Summary: short, Payload: body})
	}
	if err := s.history.Put(context.Background(), records...); err != nil {
		return err
	}
	next := clone(s.data)
	for _, r := range eligible {
		delete(next.Runs, r.ID)
	}
	prunePrograms(&next)
	if err := s.persist(next); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *Service) historicalRunLocked(id string) (historicalRun, error) {
	if s.history == nil {
		return historicalRun{}, ErrNotFound
	}
	record, err := s.history.Get(context.Background(), "run", id)
	if errors.Is(err, executionhistory.ErrNotFound) {
		return historicalRun{}, ErrNotFound
	}
	if err != nil {
		return historicalRun{}, err
	}
	return decodeHistoricalRun(record, true)
}

func (s *Service) historicalRequestLocked(plan, request, actor string) (Run, bool, error) {
	if s.history == nil {
		return Run{}, false, nil
	}
	record, err := s.history.FindRequest(context.Background(), "run", actor, request)
	if errors.Is(err, executionhistory.ErrNotFound) {
		return Run{}, false, nil
	}
	if err != nil {
		return Run{}, false, err
	}
	value, err := decodeHistoricalRun(record, true)
	if err != nil {
		return Run{}, false, err
	}
	if value.Run.PlanID != plan {
		return Run{}, false, ErrConflict
	}
	return value.Run, true, nil
}

// ListRuns includes durable history. Runs remains the bounded dispatch window.
func (s *Service) ListRuns(owner string, offset, limit int) ([]Run, int, error) {
	if offset < 0 || limit < 1 || limit > 1000 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hot := []Run{}
	excluded := make([]string, 0, len(s.data.Runs))
	for id, r := range s.data.Runs {
		excluded = append(excluded, id)
		if owner == "" || r.OwnerID == owner {
			hot = append(hot, cloneWorkflowRun(r))
		}
	}
	start := max(0, offset-len(hot))
	total := len(hot)
	if s.history != nil {
		records, count, err := s.history.Query(context.Background(), executionhistory.Query{Kind: "run", Owner: owner, Offset: start, Limit: limit + len(hot), Exclude: excluded})
		if err != nil {
			return nil, 0, err
		}
		total += count
		for _, record := range records {
			value, err := decodeHistoricalRun(record, false)
			if err != nil {
				return nil, 0, err
			}
			value.Run.Archived = true
			hot = append(hot, value.Run)
		}
	} else {
		start = 0
	}
	sort.Slice(hot, func(i, j int) bool {
		if hot[i].CreatedAt.Equal(hot[j].CreatedAt) {
			return hot[i].ID > hot[j].ID
		}
		return hot[i].CreatedAt.After(hot[j].CreatedAt)
	})
	position := min(offset-start, len(hot))
	return hot[position:min(position+limit, len(hot))], total, nil
}
