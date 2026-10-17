package notifications

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"
)

func (s *Service) Inbox(ctx context.Context, id string, unread bool, offset, limit int) (Page[Message], int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return Page[Message]{}, 0, ErrInvalid
	}
	if _, e := s.principal(ctx, id); e != nil {
		return Page[Message]{}, 0, e
	}
	s.mu.Lock()
	matching := 0
	for _, v := range s.data.Messages {
		if v.UserID == id && v.Inbox {
			matching++
		}
	}
	rows := make([]Message, 0, matching)
	for _, v := range s.data.Messages {
		if v.UserID == id && v.Inbox {
			rows = append(rows, cloneMessage(v))
		}
	}
	s.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].At.Equal(rows[j].At) {
			return rows[i].ID > rows[j].ID
		}
		return rows[i].At.After(rows[j].At)
	})
	// Filter in place; a badge only needs one result but must count all unread
	// messages. Avoid growing a second full mailbox on every header refresh.
	visible := rows[:0]
	count := 0
	for _, v := range rows {
		ok, e := s.allowed(ctx, id, v)
		if e != nil {
			return Page[Message]{}, 0, e
		}
		if !ok {
			continue
		}
		if v.ReadAt == nil {
			count++
		}
		if !unread || v.ReadAt == nil {
			visible = append(visible, v)
		}
	}
	total := len(visible)
	offset = min(offset, total)
	end := min(total, offset+limit)
	return Page[Message]{Results: visible[offset:end:end], Total: total}, count, nil
}
func (s *Service) Read(ctx context.Context, id, message string, all bool) error {
	if _, e := s.principal(ctx, id); e != nil {
		return e
	}
	s.mu.Lock()
	rows := []Message{}
	for _, v := range s.data.Messages {
		if v.UserID == id && (all || v.ID == message) && v.ReadAt == nil {
			rows = append(rows, v)
		}
	}
	s.mu.Unlock()
	ids := []string{}
	for _, v := range rows {
		ok, e := s.allowed(ctx, id, v)
		if e != nil {
			return e
		}
		if ok {
			ids = append(ids, v.ID)
		}
	}
	if !all && len(ids) == 0 {
		s.mu.Lock()
		m, ok := s.data.Messages[message]
		s.mu.Unlock()
		if !ok || m.UserID != id {
			return ErrNotFound
		}
		allowed, e := s.allowed(ctx, id, m)
		if e != nil {
			return e
		}
		if !allowed {
			return ErrNotFound
		}
		return nil
	}
	return s.mutate(func(d *state) error {
		at := s.now().UTC()
		for _, key := range ids {
			v, ok := d.Messages[key]
			if ok && v.UserID == id && v.ReadAt == nil {
				v.ReadAt = &at
				d.Messages[key] = v
			}
		}
		return nil
	})
}
func masked(v, channel string) string {
	if channel == "webhook" {
		return "organization-webhook"
	}
	if channel == "sms" {
		if len(v) > 4 {
			return "***" + v[len(v)-4:]
		}
		return "***"
	}
	if at := strings.LastIndex(v, "@"); at > 0 {
		return v[:1] + "***" + v[at:]
	}
	return "***"
}
func publicDelivery(v delivery) Delivery {
	out := v.Delivery
	out.CanRetry = v.ChallengeHash == "" && (v.State == "failed" || v.State == "uncertain")
	out.Destination = masked(v.Address, v.Channel)
	return out
}
func (s *Service) Deliveries(ctx context.Context, id, stateFilter string, offset, limit int) (Page[Delivery], error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Page[Delivery]{}, e
	}
	if offset < 0 || limit < 1 || limit > 100 {
		return Page[Delivery]{}, ErrInvalid
	}
	s.mu.Lock()
	rows := []delivery{}
	for _, v := range s.data.Deliveries {
		if (p.CanAudit || v.UserID == id) && (stateFilter == "" || v.State == stateFilter) {
			rows = append(rows, v)
		}
	}
	s.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].ID > rows[j].ID
		}
		return rows[i].CreatedAt.After(rows[j].CreatedAt)
	})
	visible := []Delivery{}
	for _, v := range rows {
		if v.ChallengeHash == "" {
			ok, e := s.allowed(ctx, v.UserID, v.Message)
			if e != nil {
				return Page[Delivery]{}, e
			}
			if !ok {
				continue
			}
		}
		visible = append(visible, publicDelivery(v))
	}
	total := len(visible)
	offset = min(offset, total)
	return Page[Delivery]{Results: visible[offset:min(total, offset+limit)], Total: total}, nil
}
func (s *Service) Audit(ctx context.Context, id string, offset, limit int) (Page[Audit], error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Page[Audit]{}, e
	}
	if !p.CanAudit {
		return Page[Audit]{}, ErrDenied
	}
	if offset < 0 || limit < 1 || limit > 100 {
		return Page[Audit]{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	total := len(s.data.Audit)
	offset = min(offset, total)
	out := []Audit{}
	for i := total - 1 - offset; i >= max(0, total-offset-limit); i-- {
		out = append(out, s.data.Audit[i])
	}
	return Page[Audit]{Results: out, Total: total}, nil
}
func (s *Service) Health(ctx context.Context, id string) (Health, error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Health{}, e
	}
	if !p.CanAudit && !p.CanManage {
		return Health{}, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Health{CreatedAt: s.data.CreatedAt, SourceGaps: []string{}}
	out.SourceErrors = []string{}
	for name, failed := range s.sourceErrors {
		if failed {
			out.SourceErrors = append(out.SourceErrors, name)
		}
	}
	slices.Sort(out.SourceErrors)
	for name, c := range s.data.Cursors {
		if c.Gap {
			out.SourceGaps = append(out.SourceGaps, name)
		}
	}
	slices.Sort(out.SourceGaps)
	for _, v := range s.data.Deliveries {
		switch v.State {
		case "queued", "retry", "sending":
			out.Pending++
		case "uncertain":
			out.Uncertain++
		case "failed":
			out.Failed++
		}
	}
	return out, nil
}
func (s *Service) Retry(ctx context.Context, id, deliveryID string, revision int, acknowledgeUncertain bool) (Delivery, error) {
	p, e := s.principal(ctx, id)
	if e != nil {
		return Delivery{}, e
	}
	s.mu.Lock()
	v, ok := s.data.Deliveries[deliveryID]
	s.mu.Unlock()
	if !ok || v.UserID != id && !p.CanRetry {
		return Delivery{}, ErrNotFound
	}
	if v.Revision != revision || v.State != "failed" && v.State != "uncertain" {
		return Delivery{}, ErrConflict
	}
	if v.State == "uncertain" && !acknowledgeUncertain {
		return Delivery{}, ErrConflict
	}
	if v.ChallengeHash != "" {
		return Delivery{}, ErrInvalid
	}
	allowed, e := s.allowed(ctx, v.UserID, v.Message)
	if e != nil {
		return Delivery{}, e
	}
	if !allowed {
		return Delivery{}, ErrDenied
	}
	var out Delivery
	e = s.mutate(func(d *state) error {
		current, ok := d.Deliveries[deliveryID]
		if !ok || current.Revision != revision {
			return ErrConflict
		}
		current.State = "queued"
		current.Attempts = 0
		current.ErrorCode = ""
		current.Receipt = ""
		current.ConfigRevision = d.Config.Revision
		current.NextAttempt = time.Time{}
		current.Revision++
		current.UpdatedAt = s.now().UTC()
		d.Deliveries[deliveryID] = current
		out = publicDelivery(current)
		audit(d, Audit{At: current.UpdatedAt, Actor: p.Actor, Action: "retry_requested", DeliveryID: deliveryID, UserID: current.UserID})
		return nil
	})
	return out, e
}
