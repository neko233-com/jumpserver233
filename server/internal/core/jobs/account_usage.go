package jobs

import "time"

func (s *Service) AccountUsage(wanted map[string]bool) map[string]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]time.Time{}
	for _, j := range s.jobs {
		if wanted[j.AssetID] && !j.StartedAt.IsZero() && j.ExitCode >= 0 && (j.State == "succeeded" || j.State == "failed") && j.StartedAt.After(out[j.AssetID]) {
			out[j.AssetID] = j.StartedAt
		}
	}
	return out
}
