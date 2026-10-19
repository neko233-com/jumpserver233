package rotationplans

import (
	"context"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestPlanPasswordPolicySnapshotSurvivesEditReplayAndReload(t *testing.T) {
	s, f, path := newFixture(t)
	rules := credentialpolicy.Defaults()
	rules.MinLength = 56
	rules.MinDigits = 8
	rules.Exclude = "OI1l0"
	in := PlanInput{Name: "Password policy metadata", Kind: "manual", Targets: []Selection{{AccountID: "account-a"}}, PasswordPolicy: rules}
	p, e := s.Save(context.Background(), testActor(), "", in, false)
	require.NoError(t, e)
	run, e := s.Submit(context.Background(), testActor(), p.ID, "policy-snapshot-replay", false)
	require.NoError(t, e)
	assert.Equal(t, rules, run.PasswordPolicy)
	edit := p.PlanInput
	edit.PasswordPolicy.MinLength = 64
	updated, e := s.Save(context.Background(), testActor(), p.ID, edit, false)
	require.NoError(t, e)
	assert.Equal(t, 64, updated.PasswordPolicy.MinLength)
	_, e = s.Save(context.Background(), testActor(), p.ID, edit, false)
	assert.ErrorIs(t, e, ErrConflict)
	replay, e := s.Submit(context.Background(), testActor(), p.ID, run.RequestID, false)
	require.NoError(t, e)
	assert.Equal(t, run.ID, replay.ID)
	assert.Equal(t, rules, replay.PasswordPolicy)
	// A corrupt private intent cannot substitute another constraint set.
	e = s.mutate(func(d *state) error {
		r := d.Runs[run.ID]
		for id, op := range r.Intents {
			op.PasswordPolicy = credentialpolicy.Rules{}
			r.Intents[id] = op
		}
		d.Runs[run.ID] = r
		return nil
	})
	assert.ErrorIs(t, e, ErrInvalid)
	s.Close()
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), rules.Exclude)
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	runner := f.runner()
	original := runner.Execute
	runner.Execute = func(ctx context.Context, in Intent, guard func() error) (Outcome, error) {
		assert.Equal(t, rules, in.PasswordPolicy)
		return original(ctx, in, guard)
	}
	peer.SetRunner(runner)
	result := drive(t, peer, run.ID)
	assert.Equal(t, "succeeded", result.State)
	assert.Equal(t, rules, result.PasswordPolicy)
	assert.Equal(t, 1, f.calls)
	newer, e := peer.Submit(context.Background(), testActor(), p.ID, "policy-snapshot-newer", false)
	require.NoError(t, e)
	assert.Equal(t, 64, newer.PasswordPolicy.MinLength)
}

func TestPlanPasswordPolicyValidationAndKeyOnlyPlans(t *testing.T) {
	s, f, _ := newFixture(t)
	rules := credentialpolicy.Defaults()
	in := PlanInput{Name: "Policy validation", Kind: "manual", Targets: []Selection{{AccountID: "account-a"}}, PasswordPolicy: rules}
	in.PasswordPolicy.MaxLength = 15
	_, e := s.Save(context.Background(), testActor(), "", in, false)
	assert.ErrorIs(t, e, ErrInvalid)
	in.PasswordPolicy = rules
	f.mu.Lock()
	target := f.targets["account-a"]
	target.CredentialType = "ssh_key"
	f.targets["account-a"] = target
	f.mu.Unlock()
	_, e = s.Save(context.Background(), testActor(), "", in, false)
	assert.ErrorIs(t, e, ErrInvalid)
	in.PasswordPolicy = credentialpolicy.Rules{}
	p, e := s.Save(context.Background(), testActor(), "", in, false)
	require.NoError(t, e)
	assert.True(t, p.PasswordPolicy.IsZero())
}

func TestPlanPasswordPolicyMixedTargetsKeepKeyIntentsUnchanged(t *testing.T) {
	s, f, _ := newFixture(t)
	f.mu.Lock()
	key := f.targets["account-b"]
	key.CredentialType = "ssh_key"
	f.targets["account-b"] = key
	f.mu.Unlock()
	rules := credentialpolicy.Defaults()
	rules.MinLength = 56
	runner := f.runner()
	original := runner.Execute
	runner.Execute = func(ctx context.Context, in Intent, guard func() error) (Outcome, error) {
		if in.Target.CredentialType == "password" {
			assert.Equal(t, rules, in.PasswordPolicy)
		} else {
			assert.True(t, in.PasswordPolicy.IsZero())
		}
		return original(ctx, in, guard)
	}
	s.SetRunner(runner)
	p, e := s.Save(context.Background(), testActor(), "", PlanInput{Name: "Mixed password and key", Kind: "manual", Targets: []Selection{{AccountID: "account-a"}, {AccountID: "account-b"}}, PasswordPolicy: rules}, false)
	require.NoError(t, e)
	run, e := s.Submit(context.Background(), testActor(), p.ID, "mixed-policy-snapshot", false)
	require.NoError(t, e)
	result := drive(t, s, run.ID)
	assert.Equal(t, "succeeded", result.State)
	assert.Equal(t, 2, f.calls)
}
