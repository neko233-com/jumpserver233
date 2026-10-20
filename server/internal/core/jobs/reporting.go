package jobs

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/executionhistory"
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
	if s.history != nil {
		exclude := make([]string, 0, len(s.jobs))
		for id := range s.jobs {
			exclude = append(exclude, id)
		}
		filter := owner
		if all {
			filter = ""
		}
		return s.history.ReadSummaries(ctx, executionhistory.Query{Kind: "job", Owner: filter, Exclude: exclude}, func(row executionhistory.Record) error {
			v, e := decodeHistoryJob(row, false)
			if e != nil {
				return e
			}
			return emit(reporting.Entry{At: v.CreatedAt, State: v.State})
		})
	}
	return nil
}
