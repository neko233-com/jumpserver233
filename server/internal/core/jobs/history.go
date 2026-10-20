package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/neko233-com/jumpserver233/server/internal/core/executionhistory"
)

const hotHistoryTarget = 800

func (s *Service) jobMatches(j Job, in Input) bool {
	return j.InputDigest == s.inputDigest(in.Stdin) && j.AssetID == in.AssetID && j.Command == in.Command && j.TimeoutSeconds == in.TimeoutSeconds && j.WorkingDirectory == in.WorkingDirectory && samePlugin(j.Plugin, in.Plugin) && sameDiscovery(j.Discovery, in.Discovery) && sameRemoteAccount(j.RemoteAccount, in.RemoteAccount) && samePlaybookStep(j.PlaybookStep, in.PlaybookStep)
}
func decodeHistoryJob(record executionhistory.Record, full bool) (Job, error) {
	var j Job
	raw := record.Summary
	if full {
		raw = record.Payload
	}
	if json.Unmarshal(raw, &j) != nil || j.ID != record.ID || j.OperatorID != record.Owner || j.CreatedAt.UnixNano() != record.CreatedAt.UnixNano() || j.State == "running" || j.State == "pending_review" || !validState(j.State) || !validJobDirectory(j, 7) || !validJobInput(j, 7) {
		return Job{}, executionhistory.ErrInvalid
	}
	return cloneJob(j), nil
}
func (s *Service) historyRequestLocked(owner string, in Input) (Job, bool, error) {
	if s.history == nil || in.RequestID == "" {
		return Job{}, false, nil
	}
	record, e := s.history.FindRequest(context.Background(), "job", owner, in.RequestID)
	if errors.Is(e, executionhistory.ErrNotFound) {
		return Job{}, false, nil
	}
	if e != nil {
		return Job{}, false, e
	}
	job, e := decodeHistoryJob(record, true)
	if e != nil {
		return Job{}, false, e
	}
	if !s.jobMatches(job, in) {
		return Job{}, false, ErrConflict
	}
	return job, true, nil
}

// Archive immutable terminal jobs before removing their hot copies. A crash or
// failed hot save leaves a harmless duplicate; ID/request checks remain durable.
func (s *Service) archiveHistoryLocked() error {
	if s.history == nil || len(s.jobs) < hotHistoryTarget {
		return nil
	}
	eligible := []Job{}
	for id, j := range s.jobs {
		if j.State == "running" || j.State == "pending_review" || j.Plugin != nil || j.Discovery != nil || j.RemoteAccount != nil || j.CreatedAt.IsZero() {
			continue
		}
		if _, running := s.running[id]; running {
			continue
		}
		eligible = append(eligible, j)
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
	if len(eligible) > 64 {
		eligible = eligible[:64]
	}
	records := make([]executionhistory.Record, 0, len(eligible))
	for _, j := range eligible {
		raw, e := json.Marshal(j)
		if e != nil {
			return e
		}
		summary := cloneJob(j)
		summary.Stdout = ""
		summary.Stderr = ""
		short, e := json.Marshal(summary)
		if e != nil {
			return e
		}
		records = append(records, executionhistory.Record{Kind: "job", ID: j.ID, Owner: j.OperatorID, RequestOwner: j.OperatorID, RequestID: j.RequestID, CreatedAt: j.CreatedAt, Payload: raw, Summary: short})
	}
	if e := s.history.Put(context.Background(), records...); e != nil {
		return e
	}
	for _, j := range eligible {
		delete(s.jobs, j.ID)
	}
	if e := s.persistLocked(); e != nil {
		for _, j := range eligible {
			s.jobs[j.ID] = j
		}
		return e
	}
	return nil
}
func (s *Service) historyListLocked(owner string, offset, limit int, hot []Job) ([]Job, int, error) {
	if s.history == nil {
		return nil, 0, nil
	}
	excluded := make([]string, 0, len(s.jobs))
	for id := range s.jobs {
		excluded = append(excluded, id)
	}
	start := max(0, offset-len(hot))
	records, count, e := s.history.Query(context.Background(), executionhistory.Query{Kind: "job", Owner: owner, Offset: start, Limit: limit + len(hot), Exclude: excluded})
	if e != nil {
		return nil, 0, e
	}
	all := append([]Job{}, hot...)
	for _, record := range records {
		j, e := decodeHistoryJob(record, false)
		if e != nil {
			return nil, 0, e
		}
		j.Archived = true
		all = append(all, j)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].ID > all[j].ID
		}
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})
	position := min(max(0, offset-start), len(all))
	return all[position:min(position+limit, len(all))], count + len(hot), nil
}
func (s *Service) HistoryHealth() executionhistory.Health {
	if s.history == nil {
		return executionhistory.Health{ErrorCode: "history_unavailable"}
	}
	return s.history.Health()
}
