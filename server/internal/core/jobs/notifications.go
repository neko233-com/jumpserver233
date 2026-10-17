package jobs

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"sort"
	"time"
)

// Notification metadata excludes commands, outputs and plugin payloads.
func (s *Service) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if e := ctx.Err(); e != nil {
		return eventfeed.Batch{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.expireLocked(); e != nil {
		return eventfeed.Batch{}, e
	}
	rows := []eventfeed.Event{}
	for _, j := range s.jobs {
		if j.FinishedAt.IsZero() || j.ErrorCode == "audit_unavailable" {
			continue
		}
		rows = append(rows, eventfeed.Event{ID: eventfeed.Digest([]string{j.ID, j.State}), Kind: "jobs", ResourceID: j.ID, OwnerID: j.OperatorID, Name: j.AssetName, State: j.State, At: j.FinishedAt})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].At.Equal(rows[j].At) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].At.Before(rows[j].At)
	})
	return eventfeed.Read(rows, after, since, limit), nil
}
func (s *Service) NotificationOwner(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return "", ErrNotFound
	}
	return j.OperatorID, nil
}
