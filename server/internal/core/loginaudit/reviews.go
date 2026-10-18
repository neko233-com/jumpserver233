package loginaudit

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/core/loginreviews"
	"time"
)

func ReviewSource(store *loginreviews.Store) Source {
	return func(ctx context.Context, after string) (SourceBatch, error) {
		if ctx.Err() != nil {
			return SourceBatch{}, ctx.Err()
		}
		if store == nil {
			return SourceBatch{}, ErrInvalid
		}
		rows, cursor, gap, e := store.AuditMetadataAfter(after)
		if e != nil {
			return SourceBatch{}, e
		}
		b := SourceBatch{Cursor: cursor, Gap: gap, Events: make([]Input, 0, len(rows))}
		for _, r := range rows {
			outcome := "review_" + r.Action
			if r.Action == loginreviews.Notified {
				outcome = "policy_notified"
			}
			b.Events = append(b.Events, Input{ID: "login-" + eventfeed.Digest([]string{"review", r.ID}), At: r.At, Method: r.AuthSource, Stage: "review", Outcome: outcome, UserID: r.UserID, Username: eventfeed.MetadataText(r.Username, 128), ActorID: r.ActorID, SourceIP: r.SourceIP, Client: "unknown", ReviewID: r.ReviewID})
		}
		return b, nil
	}
}
func (s *Store) Import(batch SourceBatch) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrClosed
	}
	if len(batch.Events) > loginreviews.MaxAudit || !optionalID(batch.Cursor) {
		return ErrInvalid
	}
	if len(batch.Events) == 0 && batch.Cursor == s.data.ReviewCursor && !batch.Gap {
		s.health.ReviewErrorCode = ""
		s.health.LastReviewSync = s.now().UTC()
		return nil
	}
	defer func() {
		if err != nil {
			s.health.ReviewErrorCode = "unavailable"
		} else {
			s.health.ReviewErrorCode = ""
			s.health.LastReviewSync = s.now().UTC()
		}
	}()
	rows := make([]Record, 0, len(batch.Events)+1)
	seen := map[string]bool{}
	for _, in := range batch.Events {
		if _, ok := s.byID[in.ID]; ok {
			continue
		}
		if seen[in.ID] {
			continue
		}
		seen[in.ID] = true
		if in.Stage != "review" || in.ReviewID == "" || in.UserID == "" || in.At.IsZero() || in.ID == "" {
			return ErrInvalid
		}
		r := Record{ID: in.ID, At: in.At.UTC(), Sequence: s.data.Total + uint64(len(rows)) + 1, Method: in.Method, Stage: "review", Outcome: in.Outcome, UserID: in.UserID, Username: in.Username, ActorID: in.ActorID, Actor: in.Actor, SourceIP: in.SourceIP, Client: "unknown", ReviewID: in.ReviewID}
		switch in.Outcome {
		case "review_pending", "review_approved", "review_denied", "review_expired", "review_cancelled", "review_consumed", "review_invalidated":
			r.Notification = "platform_" + in.Outcome
		case "policy_notified":
			r.Notification = "platform_policy_notified"
		default:
			return ErrInvalid
		}
		if !valid(r) {
			return ErrInvalid
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 && batch.Cursor == s.data.ReviewCursor && !batch.Gap {
		return nil
	}
	if s.data.Total+uint64(len(rows)) > 1<<60 {
		return ErrInvalid
	}
	return s.commitRows(rows, &batch)
}
func (s *Store) reviewCursor() string { s.mu.Lock(); defer s.mu.Unlock(); return s.data.ReviewCursor }
func (s *Store) startSource(owner context.Context, source Source) {
	s.mu.Lock()
	if s.started || s.closed || s.ctx.Err() != nil || source == nil {
		s.mu.Unlock()
		return
	}
	s.started = true
	stop := context.AfterFunc(owner, s.cancel)
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer stop()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if s.ctx.Err() != nil {
				return
			}
			batch, e := source(s.ctx, s.reviewCursor())
			if e == nil {
				e = s.Import(batch)
			}
			if e != nil {
				s.mu.Lock()
				s.health.ReviewErrorCode = "unavailable"
				s.health.LastFailure = s.now().UTC()
				s.mu.Unlock()
			}
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
