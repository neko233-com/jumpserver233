package assets

import (
	"context"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/neko233-com/jumpserver233/server/internal/core/rotationplans"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPlanPasswordPolicyMergesLocalConstraintsAndBindsReceipt(t *testing.T) {
	s, st, a, _ := newRotationServiceTest(t)
	attachManagedCoordinator(t, s)
	org := setTestPasswordPolicy(t, s, func(r *credentialpolicy.Rules) { r.MinLength = 48; r.MinSymbols = 4; r.Exclude = "OI" })
	in := managedIntent(t, s, a.ID, "", "planned-policy-receipt")
	in.PasswordPolicy = credentialpolicy.Defaults()
	in.PasswordPolicy.MinLength = 56
	in.PasswordPolicy.MaxLength = 80
	in.PasswordPolicy.MinDigits = 8
	in.PasswordPolicy.Exclude = "1l0"
	calls := 0
	remote := "initial-credential"
	s.changePassword = func(_ context.Context, _ sshclient.Target, _ sshclient.Credentials, next string, _ time.Duration) error {
		calls++
		assert.True(t, org.Matches(next))
		assert.True(t, in.PasswordPolicy.Matches(next))
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
	actual, e := st.Password(a.ID)
	require.NoError(t, e)
	assert.Equal(t, remote, actual)
	_, e = s.ExecuteManagedRotation(context.Background(), in, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, 1, calls)
	changed := in
	changed.PasswordPolicy.MinLength++
	_, e = s.ExecuteManagedRotation(context.Background(), changed, func() error { return nil })
	assert.ErrorIs(t, e, rotationplans.ErrConflict)
	assert.Equal(t, 1, calls)
}

func TestPlanPasswordPolicyMergesSharedOrganizationsAndRejectsConflicts(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "merged", true: "conflict"}[conflict], func(t *testing.T) {
			f := sharedFixture(t)
			orgA := setTestPasswordPolicy(t, f.services[0], func(r *credentialpolicy.Rules) { r.MinLength = 48; r.MinSymbols = 4; r.Exclude = "OI" })
			orgB := setTestPasswordPolicy(t, f.services[1], func(r *credentialpolicy.Rules) { r.MinDigits = 6; r.Exclude = "1l0" })
			in := managedIntent(t, f.services[0], f.assets[0].ID, "", "planned-shared-policy")
			in.PasswordPolicy = credentialpolicy.Defaults()
			in.PasswordPolicy.MinLength = 56
			in.PasswordPolicy.MaxLength = 64
			in.PasswordPolicy.MinUpper = 8
			if conflict {
				in.PasswordPolicy.MinLength = 16
				in.PasswordPolicy.MaxLength = 32
			}
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
			assert.True(t, orgA.Matches(f.remote) && orgB.Matches(f.remote) && in.PasswordPolicy.Matches(f.remote))
			f.check(t, f.remote)
		})
	}
}

func TestPlanPasswordPolicyLocalConflictDoesNotChangeRemote(t *testing.T) {
	s, st, a, _ := newRotationServiceTest(t)
	attachManagedCoordinator(t, s)
	setTestPasswordPolicy(t, s, func(r *credentialpolicy.Rules) { r.MinLength = 64 })
	in := managedIntent(t, s, a.ID, "", "planned-local-conflict")
	in.PasswordPolicy = credentialpolicy.Defaults()
	in.PasswordPolicy.MinLength = 16
	in.PasswordPolicy.MaxLength = 32
	before, e := st.Password(a.ID)
	require.NoError(t, e)
	s.changePassword = func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		t.Error("policy conflict changed remote credentials")
		return nil
	}
	out, e := s.ExecuteManagedRotation(context.Background(), in, func() error { return nil })
	assert.ErrorIs(t, e, credentialpolicy.ErrConflict)
	assert.Equal(t, "password_policy_conflict", out.Code)
	after, e := st.Password(a.ID)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	assert.False(t, st.HasPendingPasswordRotation(a.ID))
}

func TestPlanPasswordPolicyRecoveryKeepsSelectedPasswordAfterPolicyChange(t *testing.T) {
	s, st, a, _ := newRotationServiceTest(t)
	attachManagedCoordinator(t, s)
	in := managedIntent(t, s, a.ID, "", "planned-policy-recovery")
	in.PasswordPolicy = credentialpolicy.Defaults()
	in.PasswordPolicy.MinLength = 48
	in.PasswordPolicy.MaxLength = 48
	selected, e := credentialpolicy.Generate(in.PasswordPolicy)
	require.NoError(t, e)
	planned := &plannedPasswordIntent{RequestID: in.RequestID, Revision: in.Target.Revision, Version: in.Target.Version, Actor: in.Actor, PasswordPolicy: in.PasswordPolicy}
	require.NoError(t, st.beginPasswordRotation(a.ID, selected, time.Now().UTC(), "", "", "", planned))
	setTestPasswordPolicy(t, s, func(r *credentialpolicy.Rules) { r.MinLength = 64 })
	s.changePassword = func(context.Context, sshclient.Target, sshclient.Credentials, string, time.Duration) error {
		t.Error("recovery regenerated credentials")
		return nil
	}
	s.verifyPassword = func(_ context.Context, _ sshclient.Target, c sshclient.Credentials, _ time.Duration) error {
		if c.Password == selected {
			return nil
		}
		return errors.New("synthetic authentication failure")
	}
	wrong := in
	wrong.PasswordPolicy.MinDigits++
	rejected, e := s.RecoverManagedRotation(context.Background(), wrong, in.Actor, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "recovery_required", rejected.State)
	assert.True(t, st.HasPendingPasswordRotation(a.ID))
	recovered, e := s.RecoverManagedRotation(context.Background(), in, in.Actor, func() error { return nil })
	require.NoError(t, e)
	assert.Equal(t, "succeeded", recovered.State)
	actual, e := st.Password(a.ID)
	require.NoError(t, e)
	assert.Equal(t, selected, actual)
	assert.False(t, st.HasPendingPasswordRotation(a.ID))
}
