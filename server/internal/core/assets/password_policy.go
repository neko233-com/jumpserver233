package assets

import "github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"

func (s *Store) SetPasswordPolicy(store *credentialpolicy.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwordPolicy = store
}
func (s *Service) PasswordPolicyStore() *credentialpolicy.Store {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	return s.store.passwordPolicy
}
func (s *Store) passwordRules() credentialpolicy.Rules {
	s.mu.RLock()
	store := s.passwordPolicy
	s.mu.RUnlock()
	if store == nil {
		return credentialpolicy.Defaults()
	}
	return store.Snapshot().Rules
}
func (s *Service) generatePassword() (string, error) {
	return credentialpolicy.Generate(s.store.passwordRules())
}
