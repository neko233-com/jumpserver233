package tickets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
)

func (s *Service) ReportMetadata(ctx context.Context, id string, emit func(reporting.Entry) error) error {
	actor, e := s.principal(ctx, id)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.data.Tickets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !s.canRead(v, actor) {
			continue
		}
		if e := emit(reporting.Entry{At: v.CreatedAt, State: v.State}); e != nil {
			return e
		}
	}
	return nil
}
