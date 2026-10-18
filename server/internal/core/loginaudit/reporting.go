package loginaudit

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
)

func (s *Store) ReportMetadata(ctx context.Context, owner string, all bool, emit func(reporting.Entry) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for _, v := range s.rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if (!all && v.UserID != owner) || v.At.Before(s.now().Add(-Retention)) {
			continue
		}
		if e := emit(reporting.Entry{At: v.At, State: v.Outcome}); e != nil {
			return e
		}
	}
	return nil
}
