package loginaudit

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"slices"
	"strings"
	"time"
)

func validFilter(f Filter, max int) bool {
	return f.Offset >= 0 && f.Limit >= 1 && f.Limit <= max && (f.Method == "" || slices.Contains(methods, f.Method)) && (f.Outcome == "" || slices.Contains(outcomes, f.Outcome)) && len(f.Query) <= 200 && (f.SourceIP == "" || validIP(f.SourceIP)) && optionalID(f.UserID) && (f.From.IsZero() || f.To.IsZero() || !f.From.After(f.To))
}
func match(r Record, f Filter) bool {
	return (f.Method == "" || r.Method == f.Method) && (f.Outcome == "" || r.Outcome == f.Outcome) && (f.UserID == "" || r.UserID == f.UserID) && (f.SourceIP == "" || r.SourceIP == f.SourceIP) && (f.From.IsZero() || !r.At.Before(f.From)) && (f.To.IsZero() || r.At.Before(f.To)) && (f.Query == "" || strings.Contains(strings.ToLower(r.ID+" "+r.Username+" "+r.AttemptedName+" "+r.ReviewID), strings.ToLower(f.Query)))
}
func (s *Store) Get(id string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byID[id]
	if !ok || r.At.Before(s.now().Add(-Retention)) {
		return Record{}, ErrNotFound
	}
	return r, nil
}
func (s *Store) List(f Filter, visible func(Record) bool) (Page, error) {
	return s.list(f, visible, 200)
}
func (s *Store) Export(f Filter, visible func(Record) bool) (Page, error) {
	return s.list(f, visible, MaxRecords)
}
func (s *Store) list(f Filter, visible func(Record) bool, max int) (Page, error) {
	if !validFilter(f, max) {
		return Page{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Page{Results: []Record{}}
	for i := len(s.rows) - 1; i >= 0; i-- {
		r := s.rows[i]
		if r.At.Before(s.now().Add(-Retention)) || !match(r, f) || visible != nil && !visible(r) {
			continue
		}
		if out.Total >= f.Offset && len(out.Results) < f.Limit {
			out.Results = append(out.Results, r)
		}
		out.Total++
	}
	return out, nil
}
func (s *Store) Summary(f Filter, visible func(Record) bool) (Summary, error) {
	f.Offset = 0
	f.Limit = 1
	if !validFilter(f, 200) {
		return Summary{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := Summary{}
	for _, r := range s.rows {
		if r.At.Before(s.now().Add(-Retention)) || !match(r, f) || visible != nil && !visible(r) {
			continue
		}
		out.Total++
		switch r.Outcome {
		case "succeeded":
			out.Succeeded++
		case "failed":
			out.Failed++
		case "denied", "throttled":
			out.Denied++
		case "challenge":
			out.Challenges++
		}
	}
	return out, nil
}
func (s *Store) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.health
	h.ReviewGap = s.data.ReviewGap
	h.Records = len(s.rows)
	h.FirstSequence = s.data.Floor
	h.LastSequence = s.data.Total
	return h
}
func (s *Store) NotificationFeed(ctx context.Context, after string, since time.Time, limit int) (eventfeed.Batch, error) {
	if ctx.Err() != nil {
		return eventfeed.Batch{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return eventfeed.Batch{}, ErrClosed
	}
	if len(s.events) > 0 && s.events[len(s.events)-1].ID == after {
		return eventfeed.Batch{Events: []eventfeed.Event{}, Cursor: after}, nil
	}
	return eventfeed.Read(s.events, after, since, limit), nil
}
