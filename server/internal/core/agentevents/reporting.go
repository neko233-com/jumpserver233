package agentevents

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
)

// ReportMetadata reads the bounded observation index, never raw collection output.
func (s *Store) ReportMetadata(ctx context.Context, allow func(Source) bool, emit func(reporting.Entry) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.active(); e != nil {
		return e
	}
	if s.data.Notifications == nil {
		return ErrInvalid
	}
	for _, v := range s.data.Notifications.Alerts {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if allow == nil || !allow(v.Source) {
			continue
		}
		if e := emit(reporting.Entry{At: v.At, State: v.State}); e != nil {
			return e
		}
	}
	return nil
}
