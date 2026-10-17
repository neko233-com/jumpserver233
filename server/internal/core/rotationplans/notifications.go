package rotationplans

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"sort"
	"time"
)

func (s *Service) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if e := ctx.Err(); e != nil {
		return eventfeed.Batch{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := []eventfeed.Event{}
	for _, r := range s.data.Runs {
		if r.FinishedAt.IsZero() {
			continue
		}
		rows = append(rows, eventfeed.Event{ID: eventfeed.Digest([]string{r.ID, r.State}), Kind: "rotation", ResourceID: r.ID, OwnerID: r.Actor.ID, Name: r.Name, State: r.State, At: r.FinishedAt})
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
	r, ok := s.data.Runs[id]
	if !ok {
		return "", ErrNotFound
	}
	return r.Actor.ID, nil
}
