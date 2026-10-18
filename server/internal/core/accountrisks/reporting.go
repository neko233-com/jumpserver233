package accountrisks

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
)

func (s *Service) ReportMetadata(ctx context.Context, visible func(Ref) bool, current func(Finding) bool, emit func(reporting.Entry) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrInvalid
	}
	for _, v := range s.data.Findings {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if visible == nil || !visible(v.Ref) {
			continue
		}
		state := v.State
		if current == nil || !current(v.Finding) {
			state = "outdated"
		}
		if e := emit(reporting.Entry{At: v.FirstSeen, State: state}); e != nil {
			return e
		}
	}
	return nil
}
