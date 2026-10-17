package tickets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"slices"
	"time"
)

type NotificationRecipient struct{ UserID, Topic string }

func (s *Service) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil || s.ctx.Err() != nil {
		return eventfeed.Batch{}, ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := []eventfeed.Event{}
	for _, a := range s.data.Audit {
		if a.TicketID == "" {
			continue
		}
		r, ok := s.data.Tickets[a.TicketID]
		if !ok {
			continue
		}
		rows = append(rows, eventfeed.Event{ID: eventfeed.Digest(a), Kind: "tickets", ResourceID: r.ID, OwnerID: r.Owner.ID, ActorID: a.Actor.ID, Name: r.Name, State: a.Action, Revision: a.Revision, At: a.At})
	}
	return eventfeed.Read(rows, after, since, limit), nil
}
func (s *Service) NotificationRecipients(ctx context.Context, event eventfeed.Event) ([]NotificationRecipient, error) {
	s.mu.Lock()
	r, ok := s.data.Tickets[event.ResourceID]
	s.mu.Unlock()
	if !ok {
		return nil, nil
	}
	runner := s.runnerSnapshot()
	if runner.People == nil {
		return nil, ErrUnavailable
	}
	people, e := runner.People(ctx)
	if e != nil {
		return nil, e
	}
	out := []NotificationRecipient{{r.Owner.ID, "tickets"}}
	for _, p := range people {
		if matches(p, r.CC) && p.ID != r.Owner.ID {
			out = append(out, NotificationRecipient{p.ID, "tickets"})
		}
		if r.State == "pending" && r.Revision == event.Revision && slices.Contains([]string{"submitted", "amended_approvals_reset", "approve"}, event.State) && eligible(p, r.Ticket) && s.now().Before(r.ApprovalExpiresAt) {
			out = append(out, NotificationRecipient{p.ID, "approvals"})
		}
	}
	return out, nil
}
func (s *Service) NotificationAllowed(ctx context.Context, user, id string, revision int, review bool) (bool, error) {
	p, e := s.principal(ctx, user)
	if e != nil {
		return false, e
	}
	s.mu.Lock()
	r, ok := s.data.Tickets[id]
	s.mu.Unlock()
	if !ok {
		return false, ErrNotFound
	}
	if review {
		return r.Revision == revision && eligible(p, r.Ticket) && s.now().Before(r.ApprovalExpiresAt), nil
	}
	return s.canRead(r, p), nil
}
