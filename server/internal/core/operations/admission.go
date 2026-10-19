package operations

import "github.com/neko233-com/jumpserver233/server/internal/workgate"

func (s *Service) SetAdmissionGate(g *workgate.Gate) { s.mu.Lock(); s.admission = g; s.mu.Unlock() }
