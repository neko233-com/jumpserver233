package gateway

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"sort"
	"time"
)

func (b *Broker) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil {
		return eventfeed.Batch{}, ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	rows := []eventfeed.Event{}
	now := time.Now().UTC()
	for _, s := range b.sessions {
		p := s.pendingReview
		if p == nil || p.resolving || s.closing || !now.Before(p.request.ExpiresAt) {
			continue
		}
		r := p.request
		owner := r.ActorID
		if owner == "" {
			owner = s.operatorID
		}
		rows = append(rows, eventfeed.Event{ID: eventfeed.Digest([]string{r.ID, "pending"}), Kind: "command-reviews", ResourceID: "command-review-" + r.ID, OwnerID: owner, Name: eventfeed.MetadataText(r.AssetName, 480), State: "command_review_pending", At: r.RequestedAt})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	return eventfeed.Snapshot(rows, after, since, limit), nil
}
func (b *Broker) NotificationPending(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	for _, s := range b.sessions {
		p := s.pendingReview
		if p != nil && "command-review-"+p.request.ID == id && !p.resolving && !s.closing && now.Before(p.request.ExpiresAt) {
			return true
		}
	}
	return false
}
