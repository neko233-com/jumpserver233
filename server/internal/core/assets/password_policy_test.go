package assets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
	"time"
)

func setTestPasswordPolicy(t *testing.T, s *Service, change func(*credentialpolicy.Rules)) credentialpolicy.Rules {
	t.Helper()
	policy, e := credentialpolicy.Open(filepath.Join(t.TempDir(), "policy.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	p := policy.Snapshot()
	change(&p.Rules)
	_, e = policy.Save(credentialpolicy.Input{RequestID: "test-policy", Policy: p}, "admin", "Admin")
	require.NoError(t, e)
	s.store.SetPasswordPolicy(policy)
	return p.Rules
}
func TestConfiguredPasswordPolicyAppliesToManualAndAutomaticRotations(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		t.Run(map[bool]string{false: "manual", true: "automatic"}[automatic], func(t *testing.T) {
			service, store, asset, _ := newRotationServiceTest(t)
			if automatic {
				a, _ := store.Get(asset.ID)
				a.PasswordRotatedAt = time.Now().UTC().Add(-8 * 24 * time.Hour)
				store.mu.Lock()
				v := store.assets[a.ID]
				v.PasswordRotatedAt = a.PasswordRotatedAt
				v.Asset.PasswordRotatedAt = a.PasswordRotatedAt
				store.assets[a.ID] = v
				store.mu.Unlock()
			}
			rules := setTestPasswordPolicy(t, service, func(r *credentialpolicy.Rules) {
				r.MinLength = 48
				r.MaxLength = 48
				r.MinUpper = 5
				r.MinDigits = 4
				r.MinSymbols = 3
				r.Exclude = "OI1l0"
			})
			changed := false
			service.changePassword = func(_ context.Context, _ sshclient.Target, _ sshclient.Credentials, next string, _ time.Duration) error {
				changed = true
				assert.True(t, rules.Matches(next))
				return nil
			}
			service.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
				assert.True(t, rules.Matches(c.Password))
				return nil
			}
			if automatic {
				service.RotateDuePasswords(context.Background())
			} else {
				_, e := service.RotatePassword(context.Background(), asset.ID)
				require.NoError(t, e)
			}
			assert.True(t, changed)
			p, e := store.Password(asset.ID)
			require.NoError(t, e)
			assert.True(t, rules.Matches(p))
		})
	}
}
func TestSharedPasswordPolicyMergesAllStoresIncludingInactiveServices(t *testing.T) {
	f := sharedFixture(t)
	a := setTestPasswordPolicy(t, f.services[0], func(r *credentialpolicy.Rules) { r.MinLength = 48; r.Exclude = "O0" })
	b := setTestPasswordPolicy(t, f.services[1], func(r *credentialpolicy.Rules) { r.MinDigits = 8; r.MinSymbols = 5; r.Exclude = "l1I" })
	delete(f.c.services, "other") // Archived stores still participate without a running service.
	_, e := f.services[0].RotatePassword(context.Background(), f.assets[0].ID)
	require.NoError(t, e)
	assert.True(t, a.Matches(f.remote) && b.Matches(f.remote))
	f.check(t, f.remote)
}
func TestIncompatibleSharedPasswordPoliciesDoNotChangeRemoteOrVaults(t *testing.T) {
	f := sharedFixture(t)
	setTestPasswordPolicy(t, f.services[0], func(r *credentialpolicy.Rules) { r.MinLength = 64 })
	setTestPasswordPolicy(t, f.services[1], func(r *credentialpolicy.Rules) { r.MinLength = 16; r.MaxLength = 32 })
	_, e := f.services[0].RotatePassword(context.Background(), f.assets[0].ID)
	assert.ErrorIs(t, e, ErrSharedCredentialConflict)
	assert.Zero(t, f.changes)
	f.check(t, "initial-credential")
}
func TestConfiguredPasswordPolicyDoesNotRegeneratePendingRecovery(t *testing.T) {
	service, store, asset, _ := newRotationServiceTest(t)
	candidate := "synthetic-previously-selected-candidate"
	require.NoError(t, store.BeginPasswordRotation(asset.ID, candidate, time.Now().UTC()))
	rules := setTestPasswordPolicy(t, service, func(r *credentialpolicy.Rules) { r.MinLength = 64; r.MinSymbols = 8 })
	assert.False(t, rules.Matches(candidate))
	service.changePassword = func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		t.Fatal("recovery regenerated a password")
		return nil
	}
	service.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		if c.Password == candidate {
			return nil
		}
		return errors.New("authentication failed")
	}
	service.RecoverPendingPasswordRotations(context.Background())
	actual, e := store.Password(asset.ID)
	require.NoError(t, e)
	assert.Equal(t, candidate, actual)
	assert.False(t, store.HasPendingPasswordRotation(asset.ID))
}
