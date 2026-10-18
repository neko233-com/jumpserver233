package databasequery

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
)

func (s *Service) ReportMetadata(ctx context.Context, owner string, all bool, emit func(reporting.Entry) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.jobs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !all && v.OperatorID != owner {
			continue
		}
		if e := emit(reporting.Entry{At: v.CreatedAt, State: v.State}); e != nil {
			return e
		}
	}
	return nil
}
