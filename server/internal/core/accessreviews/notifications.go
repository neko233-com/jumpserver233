package accessreviews

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"sort"
	"time"
)

// NotificationFeed reconstructs retained lifecycle facts without copying
// account scopes or exposing one-use permits. Pending tasks are revisited.
func (s *Store) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil {
		return eventfeed.Batch{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	candidate := cloneRecords(s.records)
	if expireAndPrune(candidate, time.Now().UTC()) {
		if e := s.persistLocked(candidate); e != nil {
			return eventfeed.Batch{}, e
		}
		s.records = candidate
	}
	rows := []eventfeed.Event{}
	for _, r := range s.records {
		add := func(state string, at time.Time) {
			rows = append(rows, eventfeed.Event{ID: eventfeed.Digest([]any{r.ID, state, at}), Kind: "access-reviews", ResourceID: r.ID, OwnerID: r.UserID, Name: eventfeed.MetadataText(r.AssetName, 480), State: state, At: at})
		}
		add("asset_review_pending", r.RequestedAt)
		if r.ReviewedAt != nil {
			state := "asset_review_approved"
			if r.State == StateDenied {
				state = "asset_review_denied"
			}
			add(state, *r.ReviewedAt)
		}
		if r.State == StateExpired {
			at := r.ExpiresAt
			if r.ReviewedAt != nil && r.ExpiresAt.Equal(r.RequestedAt.Add(requestLifetime)) {
				at = r.ReviewedAt.Add(permitLifetime)
			}
			add("asset_review_expired", at)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return eventfeed.Snapshot(rows, after, since, limit), nil
}

type NotificationInfo struct{ OwnerID, State string }

func (s *Store) NotificationInfo(id string) (NotificationInfo, error) {
	r, e := s.Get(id)
	if e != nil {
		return NotificationInfo{}, e
	}
	return NotificationInfo{r.UserID, r.State}, nil
}
