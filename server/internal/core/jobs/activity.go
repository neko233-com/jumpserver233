package jobs

import "github.com/neko233-com/jumpserver233/server/internal/workgate"

func (s *Service) SetAdmissionGate(g *workgate.Gate) { s.mu.Lock(); s.admission = g; s.mu.Unlock() }
func (s *Service) ActiveCount() int                  { s.mu.Lock(); defer s.mu.Unlock(); return len(s.running) }
