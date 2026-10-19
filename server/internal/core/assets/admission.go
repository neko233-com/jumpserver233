package assets

import "github.com/neko233-com/jumpserver233/server/internal/workgate"

func (s *Store) SetAdmissionGate(g *workgate.Gate) { s.mu.Lock(); s.admission = g; s.mu.Unlock() }
func (s *Store) admissionGate() *workgate.Gate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.admission
}
