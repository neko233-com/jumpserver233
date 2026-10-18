package monitoralerts

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
)

func (s *Service) ReportMetadata(ctx context.Context, visible func(Alert) bool, emit func(reporting.Entry) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	for _, v := range s.data.Alerts {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if visible == nil || !visible(v) {
			continue
		}
		if e := emit(reporting.Entry{At: v.StartedAt, State: v.State}); e != nil {
			return e
		}
	}
	return nil
}
