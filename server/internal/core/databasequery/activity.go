package databasequery

func (s *Service) ActiveCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.running) }
