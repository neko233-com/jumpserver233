package rotationplans

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixedInput(request string) SaveInput {
	return SaveInput{PlanInput: PlanInput{Name: "Protected fixed plan", Kind: "manual", PasswordMode: "fixed", Targets: []Selection{{AccountID: "account-a"}}}, RequestID: request, FixedPassword: strings.Repeat("Ab2!", 16)}
}

func TestFixedPasswordSaveIsEncryptedWriteOnlyAndIdempotent(t *testing.T) {
	s, _, path := newFixture(t)
	input := fixedInput("fixed-create-receipt")
	p, e := s.SaveRequest(context.Background(), testActor(), "", input, false, true)
	require.NoError(t, e)
	replay, e := s.SaveRequest(context.Background(), testActor(), "", input, false, true)
	require.NoError(t, e)
	assert.Equal(t, p.ID, replay.ID)
	assert.Equal(t, 1, replay.Revision)
	originalID := s.data.Plans[p.ID].FixedSecretID
	assert.NotEmpty(t, originalID)
	bad := input
	bad.FixedPassword = strings.Repeat("Cd3#", 16)
	_, e = s.SaveRequest(context.Background(), testActor(), "", bad, false, true)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.SaveRequest(context.Background(), Actor{ID: "different-actor", Name: "Other"}, "", input, true, true)
	assert.ErrorIs(t, e, ErrConflict)
	keep := SaveInput{PlanInput: p.PlanInput, RequestID: "fixed-keep-receipt"}
	updated, e := s.SaveRequest(context.Background(), testActor(), p.ID, keep, false, true)
	require.NoError(t, e)
	assert.Equal(t, originalID, s.data.Plans[p.ID].FixedSecretID)
	_, e = s.SaveRequest(context.Background(), testActor(), p.ID, SaveInput{PlanInput: p.PlanInput, RequestID: "fixed-stale-receipt"}, false, true)
	assert.ErrorIs(t, e, ErrConflict)
	replacement := SaveInput{PlanInput: updated.PlanInput, RequestID: "fixed-replace-receipt", FixedPassword: bad.FixedPassword}
	replaced, e := s.SaveRequest(context.Background(), testActor(), p.ID, replacement, false, true)
	require.NoError(t, e)
	assert.NotEqual(t, originalID, s.data.Plans[p.ID].FixedSecretID)
	current, e := s.SaveRequest(context.Background(), testActor(), "", input, false, true)
	require.NoError(t, e)
	assert.Equal(t, replaced.Revision, current.Revision)
	encoded, e := json.Marshal([]any{current, s.data.Audit})
	require.NoError(t, e)
	assert.NotContains(t, string(encoded), input.FixedPassword)
	assert.NotContains(t, string(encoded), bad.FixedPassword)
	assert.NotContains(t, string(encoded), "fixed_secret_id")
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), input.FixedPassword)
	assert.NotContains(t, string(raw), bad.FixedPassword)
	generated := SaveInput{PlanInput: replaced.PlanInput, RequestID: "fixed-clear-receipt"}
	generated.PasswordMode = "generated"
	cleared, e := s.SaveRequest(context.Background(), testActor(), p.ID, generated, false, true)
	require.NoError(t, e)
	assert.Empty(t, s.data.Plans[p.ID].FixedPassword)
	assert.Empty(t, s.data.Plans[p.ID].FixedSecretID)
	require.NoError(t, s.Delete(p.ID, cleared.Revision, testActor(), false))
	_, e = s.SaveRequest(context.Background(), testActor(), "", input, false, true)
	assert.ErrorIs(t, e, ErrNotFound)
	assert.Empty(t, s.data.Plans)
}

func TestFixedPasswordConcurrentSaveCreatesOnePlanAndReceipt(t *testing.T) {
	s, _, _ := newFixture(t)
	input := fixedInput("fixed-concurrent-create")
	var wg sync.WaitGroup
	results := make(chan Plan, 16)
	failures := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := s.SaveRequest(context.Background(), testActor(), "", input, false, true)
			if e != nil {
				failures <- e
				return
			}
			results <- p
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for e := range failures {
		require.NoError(t, e)
	}
	id := ""
	for p := range results {
		if id == "" {
			id = p.ID
		}
		assert.Equal(t, id, p.ID)
		assert.Equal(t, 1, p.Revision)
	}
	assert.Len(t, s.data.Plans, 1)
	assert.Len(t, s.data.SaveReceipts, 1)
	assert.Len(t, s.data.Audit, 1)
}

func TestFixedPasswordSnapshotReloadScrubsCompletedRunSecret(t *testing.T) {
	s, f, path := newFixture(t)
	runner := f.runner()
	runner.AuthorizeFixed = func(Actor) error { return nil }
	s.SetRunner(runner)
	input := fixedInput("fixed-snapshot-create")
	p, e := s.SaveRequest(context.Background(), testActor(), "", input, false, true)
	require.NoError(t, e)
	run, e := s.Submit(context.Background(), testActor(), p.ID, "fixed-snapshot-run", false)
	require.NoError(t, e)
	oldID := s.data.Runs[run.ID].FixedSecretID
	edit := SaveInput{PlanInput: p.PlanInput, RequestID: "fixed-snapshot-edit", FixedPassword: strings.Repeat("Cd3#", 16)}
	_, e = s.SaveRequest(context.Background(), testActor(), p.ID, edit, false, true)
	require.NoError(t, e)
	s.Close()
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	runner = f.runner()
	runner.AuthorizeFixed = func(Actor) error { return nil }
	execute := runner.Execute
	runner.Execute = func(ctx context.Context, in Intent, guard func() error) (Outcome, error) {
		assert.True(t, in.FixedPassword == input.FixedPassword, "executor did not receive original protected value")
		assert.Equal(t, oldID, in.FixedSecretID)
		return execute(ctx, in, guard)
	}
	peer.SetRunner(runner)
	result := drive(t, peer, run.ID)
	assert.Equal(t, "succeeded", result.State)
	assert.Equal(t, "fixed", result.PasswordMode)
	assert.Empty(t, peer.data.Runs[run.ID].FixedPassword)
	assert.True(t, peer.data.Plans[p.ID].FixedPassword == edit.FixedPassword)
	raw, e := json.Marshal(result)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "fixed_secret_id")
	assert.NotContains(t, string(raw), input.FixedPassword)
	peer.Close()
	again, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer again.Close()
	assert.Empty(t, again.data.Runs[run.ID].FixedPassword)
	assert.Equal(t, 1, f.calls)
}

func TestFixedPasswordPermissionRevocationAndModeValidation(t *testing.T) {
	s, f, _ := newFixture(t)
	input := fixedInput("fixed-permission-create")
	_, e := s.SaveRequest(context.Background(), testActor(), "", input, false, false)
	assert.ErrorIs(t, e, ErrDenied)
	bad := input
	bad.RequestID = ""
	_, e = s.SaveRequest(context.Background(), testActor(), "", bad, false, true)
	assert.ErrorIs(t, e, ErrInvalid)
	bad = input
	bad.FixedPassword = ""
	_, e = s.SaveRequest(context.Background(), testActor(), "", bad, false, true)
	assert.ErrorIs(t, e, ErrInvalid)
	var fixedAllowed atomic.Bool
	fixedAllowed.Store(true)
	runner := f.runner()
	runner.AuthorizeFixed = func(Actor) error {
		if !fixedAllowed.Load() {
			return ErrDenied
		}
		return nil
	}
	s.SetRunner(runner)
	p, e := s.SaveRequest(context.Background(), testActor(), "", input, false, true)
	require.NoError(t, e)
	run, e := s.Submit(context.Background(), testActor(), p.ID, "fixed-revoked-run", false)
	require.NoError(t, e)
	fixedAllowed.Store(false)
	result := drive(t, s, run.ID)
	assert.Equal(t, "failed", result.State)
	assert.Equal(t, "denied", result.Items[0].State)
	assert.Zero(t, f.calls)
	assert.Empty(t, s.data.Runs[run.ID].FixedPassword)
	_, e = s.Submit(context.Background(), testActor(), p.ID, "fixed-revoked-new", false)
	assert.ErrorIs(t, e, ErrDenied)
	clear := SaveInput{PlanInput: p.PlanInput, RequestID: "fixed-unauthorized-clear"}
	clear.PasswordMode = "generated"
	_, e = s.SaveRequest(context.Background(), testActor(), p.ID, clear, false, false)
	assert.ErrorIs(t, e, ErrDenied)
	assert.True(t, s.data.Plans[p.ID].FixedPassword == input.FixedPassword)
	keys, keyFixture, _ := newFixture(t)
	keyFixture.mu.Lock()
	target := keyFixture.targets["account-a"]
	target.CredentialType = "ssh_key"
	keyFixture.targets["account-a"] = target
	keyFixture.mu.Unlock()
	_, e = keys.SaveRequest(context.Background(), testActor(), "", fixedInput("fixed-key-only-denied"), false, true)
	assert.ErrorIs(t, e, ErrInvalid)
}

func TestFixedPasswordReceiptCapacityExpiresWithoutEvictingLiveReceipts(t *testing.T) {
	s, _, _ := newFixture(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	require.NoError(t, s.mutate(func(d *state) error {
		for i := 0; i < MaxSaveReceipts; i++ {
			d.SaveReceipts = append(d.SaveReceipts, saveReceipt{RequestID: fmt.Sprintf("receipt-%d", i), ActorID: testActor().ID, PlanID: "deleted-plan", Digest: strings.Repeat("a", 64), At: now})
		}
		return nil
	}))
	_, e := s.SaveRequest(context.Background(), testActor(), "", fixedInput("fixed-capacity-new"), false, true)
	assert.ErrorIs(t, e, ErrCapacity)
	assert.Empty(t, s.data.Plans)
	now = now.Add(91 * 24 * time.Hour)
	_, e = s.SaveRequest(context.Background(), testActor(), "", fixedInput("fixed-capacity-new"), false, true)
	require.NoError(t, e)
	assert.Len(t, s.data.SaveReceipts, 1)
}

func TestFixedPasswordStoreRejectsIncompleteAuthenticatedState(t *testing.T) {
	for _, missing := range []string{"version", "plans", "runs", "audit"} {
		t.Run(missing, func(t *testing.T) {
			s, _, path := newFixture(t)
			data := map[string]any{"version": 1, "plans": map[string]any{}, "runs": map[string]any{}, "audit": []any{}}
			delete(data, missing)
			plain, e := json.Marshal(data)
			require.NoError(t, e)
			nonce := make([]byte, s.aead.NonceSize())
			box := envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/rotation-plans/v1"))}
			raw, e := json.Marshal(box)
			require.NoError(t, e)
			s.Close()
			require.NoError(t, os.WriteFile(path, raw, 0600))
			_, e = Open(path, make([]byte, 32), nil)
			assert.ErrorIs(t, e, ErrInvalid)
			after, e := os.ReadFile(path)
			require.NoError(t, e)
			assert.Equal(t, raw, after)
		})
	}
	t.Run("truncated", func(t *testing.T) {
		s, _, path := newFixture(t)
		s.Close()
		require.NoError(t, os.WriteFile(path, []byte{}, 0600))
		_, e := Open(path, make([]byte, 32), nil)
		assert.ErrorIs(t, e, ErrInvalid)
	})
}
