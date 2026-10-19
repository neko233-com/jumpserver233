package assets

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
)

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
func planPasswordRules(ctx context.Context) credentialpolicy.Rules {
	if planned := managedContext(ctx); planned != nil {
		return planned.Intent.PasswordPolicy
	}
	return credentialpolicy.Rules{}
}
func (s *Service) generatePassword(ctx context.Context) (string, error) {
	rules := s.store.passwordRules()
	if plan := planPasswordRules(ctx); !plan.IsZero() {
		var err error
		rules, err = credentialpolicy.Merge(rules, plan)
		if err != nil {
			return "", err
		}
	}
	return credentialpolicy.Generate(rules)
}
