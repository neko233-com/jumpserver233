package accountrisks

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"sort"
	"time"
)

// Scan summaries omit findings, password groups, peers and private bindings.
func (s *Service) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil {
		return eventfeed.Batch{}, ctx.Err()
	}
	if s.ctx.Err() != nil {
		return eventfeed.Batch{}, s.ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := []eventfeed.Event{}
	for _, r := range s.data.Scans {
		if r.FinishedAt.IsZero() {
			continue
		}
		state := "risk_scan_failed"
		if r.State == "succeeded" {
			state = "risk_scan_clear"
			if r.Open > 0 {
				state = "risk_scan_findings"
			}
		} else if r.State == "cancelled" {
			state = "risk_scan_cancelled"
		} else if r.State == "interrupted" {
			state = "risk_scan_interrupted"
		}
		rows = append(rows, eventfeed.Event{ID: eventfeed.Digest([]any{r.ID, state, r.FinishedAt}), Kind: "account-risks", ResourceID: r.ID, OwnerID: r.Actor.ID, State: state, At: r.FinishedAt})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].At.Equal(rows[j].At) {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].At.Before(rows[j].At)
	})
	return eventfeed.Read(rows, after, since, limit), nil
}
