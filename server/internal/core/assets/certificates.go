package assets

import "github.com/neko233-com/jumpserver233/server/internal/core/sshcertificates"

func (s *Service) SetSSHCertificates(policies *sshcertificates.Store) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	s.store.certificates = policies
}
func SSHCertificateTarget(a Asset) sshcertificates.Target {
	return sshcertificates.Target{AssetID: a.ID, ParentID: a.ParentAssetID, Host: a.Host, Port: a.Port, Username: a.Username, Fingerprint: a.HostKeyFingerprint, GatewayID: a.GatewayID}
}
func (s *Service) certificateRequired(id string) bool {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	return s.store.certificates != nil && s.store.certificates.Required(id)
}

// The coordinator lock protects alias membership and policy changes together.
func (c *PasswordCoordinator) certificateParticipant(identity string) bool {
	for _, st := range c.stores {
		for _, a := range st.List() {
			if passwordIdentity(a) != identity {
				continue
			}
			st.mu.RLock()
			policies := st.certificates
			st.mu.RUnlock()
			if policies != nil && policies.Required(a.ID) {
				return true
			}
		}
	}
	return false
}

func (s *Service) BindSSHCertificate(id, actor string, in sshcertificates.BindingInput) (sshcertificates.Binding, error) {
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.blocked(s.passwordScope, id) {
			return sshcertificates.Binding{}, sshcertificates.ErrConflict
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rotationRunning[id] || s.store.HasPendingPasswordRotation(id) || s.store.HasPendingSSHKeyChange(id) {
		return sshcertificates.Binding{}, sshcertificates.ErrConflict
	}
	a, e := s.Get(id)
	if e != nil || !IsSSH(a) || remoteAccountPending(a) {
		return sshcertificates.Binding{}, sshcertificates.ErrNotFound
	}
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	if s.store.certificates == nil {
		return sshcertificates.Binding{}, sshcertificates.ErrUnavailable
	}
	return s.store.certificates.Bind(SSHCertificateTarget(a), actor, in)
}
