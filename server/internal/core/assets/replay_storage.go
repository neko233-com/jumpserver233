package assets

import "time"

// ReplayStorageTarget binds a persistent storage locator to its complete SSH
// route without invalidating it on password/key rotation. The second value is
// a short-lived connection binding checked atomically when credentials resolve.
func (s *Service) ReplayStorageTarget(id string) (string, string, error) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	route := []connectionSnapshot{}
	seen := map[string]bool{}
	for current := id; current != ""; {
		if seen[current] || len(route) > 3 {
			return "", "", ErrInvalidInput
		}
		seen[current] = true
		r, ok := s.store.assets[current]
		if !ok {
			return "", "", ErrNotFound
		}
		if !IsSSH(r.Asset) || r.AccountDisabled || remoteAccountPending(r.Asset) || r.HostKeyFingerprint == "" {
			return "", "", ErrConnectionChanged
		}
		v := snapshotConnection(r.Asset)
		v.CredentialRevision = 0
		v.UpdatedAt = time.Time{}
		v.Node = ""
		route = append(route, v)
		current = r.GatewayID
	}
	if len(route) == 0 {
		return "", "", ErrNotFound
	}
	binding, e := s.store.connectionBindingLocked(id)
	if e != nil {
		return "", "", e
	}
	return s.store.importMAC("replay-storage-target/v1", route), binding, nil
}
