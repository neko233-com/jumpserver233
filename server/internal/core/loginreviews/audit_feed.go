package loginreviews

// AuditMetadata never includes a login proof, ticket hash or session hash.
type AuditMetadata struct {
	Audit
	AuthSource string
}

func (s *Store) AuditMetadataAfter(after string) ([]AuditMetadata, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return nil, "", false, e
	}
	n := len(s.data.Audit)
	if n == 0 {
		return []AuditMetadata{}, "", after != "", nil
	}
	anchor := s.data.Audit[n-1].ID
	if anchor == after {
		return []AuditMetadata{}, anchor, false, nil
	}
	start := 0
	gap := after != ""
	for i := n - 1; i >= 0; i-- {
		if s.data.Audit[i].ID == after {
			start = i + 1
			gap = false
			break
		}
	}
	out := make([]AuditMetadata, 0, n-start)
	for _, a := range s.data.Audit[start:] {
		source := s.data.Records[a.ReviewID].AuthSource
		if source == "" {
			source = "unknown"
		}
		out = append(out, AuditMetadata{Audit: a, AuthSource: source})
	}
	return out, anchor, gap, nil
}
