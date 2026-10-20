package assets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestFixedPasswordRotationBindsReceiptsAndNeverBypassesOrganizationRules(t *testing.T) {
	s, st, a, _ := newRotationServiceTest(t)
	attachManagedCoordinator(t, s)
	in := managedIntent(t, s, a.ID, "", "fixed-local-operation")
	in.FixedSecretID = "fixed-secret-one"
	in.FixedPassword = strings.Repeat("Ab2!", 16)
	remote := "initial-credential"
	calls := 0
	s.changePassword = func(_ context.Context, _ sshclient.Target, _ sshclient.Credentials, next string, _ time.Duration) error {
		calls++
		assert.True(t, next == in.FixedPassword)
		remote = next
		return nil
	}
	s.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		if c.Password != remote {
			return errors.New("synthetic authentication failure")
		}
		return nil
	}
	out, e := s.ExecuteManagedRotation(context.Background(), in, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	assert.Equal(t, 1, calls)
	replay := in
	replay.FixedPassword = ""
	out, e = s.InspectManagedRotation(context.Background(), replay)
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	wrong := in
	wrong.FixedSecretID = "fixed-secret-other"
	_, e = s.ExecuteManagedRotation(context.Background(), wrong, func() error { return nil })
	assert.ErrorIs(t, e, rotationplans.ErrConflict)
	assert.Equal(t, 1, calls)
	actual, e := st.Password(a.ID)
	require.NoError(t, e)
	assert.True(t, actual == in.FixedPassword)
	next := managedIntent(t, s, a.ID, "", "fixed-local-policy-conflict")
	next.FixedSecretID = "fixed-secret-later"
	next.FixedPassword = in.FixedPassword
	setTestPasswordPolicy(t, s, func(r *credentialpolicy.Rules) { r.MinLength = 80 })
	out, e = s.ExecuteManagedRotation(context.Background(), next, func() error { return nil })
	assert.ErrorIs(t, e, credentialpolicy.ErrConflict)
	assert.Equal(t, "password_policy_conflict", out.Code)
	assert.Equal(t, 1, calls)
}

func TestFixedPasswordSharedAccountsEnforceInactiveOrganizationConstraints(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "allowed", true: "conflict"}[conflict], func(t *testing.T) {
			f := sharedFixture(t)
			setTestPasswordPolicy(t, f.services[1], func(r *credentialpolicy.Rules) {
				r.MinDigits = 10
				if conflict {
					r.Exclude = "A"
				}
			})
			delete(f.c.services, "other")
			in := managedIntent(t, f.services[0], f.assets[0].ID, "", "fixed-shared-operation")
			in.FixedSecretID = "fixed-shared-secret"
			in.FixedPassword = strings.Repeat("Ab2!", 16)
			out, e := f.services[0].ExecuteManagedRotation(context.Background(), in, func() error { return nil })
			if conflict {
				assert.ErrorIs(t, e, credentialpolicy.ErrConflict)
				assert.Equal(t, "password_policy_conflict", out.Code)
				assert.Zero(t, f.changes)
				f.check(t, "initial-credential")
				return
			}
			require.NoError(t, e)
			assert.Equal(t, "succeeded", out.State)
			assert.True(t, f.remote == in.FixedPassword)
			f.check(t, f.remote)
		})
	}
}

func TestFixedPasswordPendingRecoveryReloadUsesOriginalSecretIdentity(t *testing.T) {
	s, st, a, path := newRotationServiceTest(t)
	attachManagedCoordinator(t, s)
	in := managedIntent(t, s, a.ID, "", "fixed-pending-recovery")
	in.FixedSecretID = "fixed-pending-secret"
	in.FixedPassword = strings.Repeat("Ab2!", 12)
	pending := &plannedPasswordIntent{FixedSecretID: in.FixedSecretID, PasswordPolicy: in.PasswordPolicy, RequestID: in.RequestID, Revision: in.Target.Revision, Version: in.Target.Version, Actor: in.Actor}
	require.NoError(t, st.beginPasswordRotation(a.ID, in.FixedPassword, time.Now().UTC(), "", "", "", pending))
	reopened, e := OpenStore(path, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, e)
	peer := NewService(reopened, nil)
	attachManagedCoordinator(t, peer)
	setTestPasswordPolicy(t, peer, func(r *credentialpolicy.Rules) { r.MinLength = 80 })
	peer.changePassword = func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		t.Error("recovery attempted a different password change")
		return nil
	}
	peer.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		if c.Password == in.FixedPassword {
			return nil
		}
		return errors.New("synthetic authentication failure")
	}
	wrong := in
	wrong.FixedSecretID = "different-fixed-secret"
	out, e := peer.RecoverManagedRotation(context.Background(), wrong, in.Actor, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "recovery_required", out.State)
	assert.True(t, reopened.HasPendingPasswordRotation(a.ID))
	out, e = peer.RecoverManagedRotation(context.Background(), in, in.Actor, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", out.State)
	actual, e := reopened.Password(a.ID)
	require.NoError(t, e)
	assert.True(t, actual == in.FixedPassword)
	assert.False(t, reopened.HasPendingPasswordRotation(a.ID))
}
