package jobs

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"sort"
	"time"
)

func (s *Service) SecurityNotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil {
		return eventfeed.Batch{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.expireLocked(); e != nil {
		return eventfeed.Batch{}, e
	}
	rows := []eventfeed.Event{}
	for _, j := range s.jobs {
		if j.ErrorCode == "audit_unavailable" {
			continue
		}
		add := func(state string, at time.Time) {
			if at.IsZero() {
				return
			}
			rows = append(rows, eventfeed.Event{ID: eventfeed.Digest([]any{j.ID, state, at}), Kind: "job-security", ResourceID: j.ID, OwnerID: j.OperatorID, Name: eventfeed.MetadataText(j.AssetName, 480), State: state, At: at})
		}
		if j.State == "pending_review" || j.ReviewedBy != "" || j.ErrorCode == "review_expired" {
			add("job_review_pending", j.CreatedAt)
		}
		if j.ReviewedBy != "" {
			if !j.StartedAt.IsZero() {
				add("job_review_approved", j.StartedAt)
			} else if j.State == "denied" {
				add("job_review_denied", j.FinishedAt)
			}
		} else if j.State == "denied" {
			add("job_command_denied", j.FinishedAt)
		}
		if j.ErrorCode == "review_expired" {
			add("job_review_expired", j.FinishedAt)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return eventfeed.Snapshot(rows, after, since, limit), nil
}

type SecurityNotificationInfo struct{ OwnerID, State string }

func (s *Service) SecurityNotificationInfo(id string) (SecurityNotificationInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.expireLocked(); e != nil {
		return SecurityNotificationInfo{}, e
	}
	j, ok := s.jobs[id]
	if !ok {
		return SecurityNotificationInfo{}, ErrNotFound
	}
	return SecurityNotificationInfo{j.OperatorID, j.State}, nil
}
