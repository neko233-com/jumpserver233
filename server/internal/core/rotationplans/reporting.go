package rotationplans

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
)

func (s *Service) ReportMetadata(ctx context.Context, emit func(reporting.Entry) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.data.Runs {
		if v.Operation == "check" {
			continue
		} // Authentication checks never count as credential changes.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e := emit(reporting.Entry{At: v.CreatedAt, State: v.State}); e != nil {
			return e
		}
	}
	return nil
}
