package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeActivationTestRelease(data string, r activationRelease) error {
	body, _ := json.Marshal(r)
	return atomicPrivate(activationPath(data, "release"), body)
}
func activationFixture(t *testing.T) (*Lock, UpgradeGuard, ActivationRecord) {
	t.Helper()
	opt := fixture(t)
	lock, e := Acquire(opt.DataDir)
	require.NoError(t, e)
	t.Cleanup(func() { _ = lock.Close() })
	g := UpgradeGuard{Schema: 1, RootID: strings.Repeat("a", 32), ID: strings.Repeat("b", 32), BinarySHA256: strings.Repeat("c", 64), Phase: "selected"}
	require.NoError(t, SetUpgradeGuard(lock, g))
	assert.ErrorIs(t, CheckNoUpgradePending(lock.DataDir), ErrUpgradePending)
	assert.ErrorIs(t, CheckUpgradeGuard(lock.DataDir, "", g.BinarySHA256), ErrUpgradePending)
	g.Phase = "trial"
	g.Attempt = strings.Repeat("d", 32)
	require.NoError(t, SetUpgradeGuard(lock, g))
	r, e := PublishActivation(lock, g, "127.0.0.1:18080", "v1.2.3", "trial")
	require.NoError(t, e)
	return lock, g, r
}
func TestActivationReleaseRequiresExactLocalAttemptAndCannotReplayAfterCommit(t *testing.T) {
	lock, g, r := activationFixture(t)
	_, e := CheckActivationGuard(lock.DataDir, g.ID, strings.Repeat("e", 32), g.BinarySHA256)
	assert.ErrorIs(t, e, ErrUpgradePending)
	_, e = CheckActivationGuard(lock.DataDir, g.ID, g.Attempt, g.BinarySHA256)
	require.NoError(t, e)
	wrong := r
	wrong.PID++
	assert.ErrorIs(t, ReleaseActivation(lock.DataDir, wrong), ErrConflict)
	wrong = r
	wrong.Attempt = strings.Repeat("e", 32)
	assert.ErrorIs(t, ReleaseActivation(lock.DataDir, wrong), ErrConflict)
	require.NoError(t, ReleaseActivation(lock.DataDir, r))
	require.NoError(t, ReleaseActivation(lock.DataDir, r))
	active, e := AwaitActivation(context.Background(), lock, g, r)
	require.NoError(t, e)
	assert.Equal(t, "active", active.Phase)
	assert.ErrorIs(t, ReleaseActivation(lock.DataDir, r), ErrConflict)
	assert.ErrorIs(t, SetUpgradeGuard(lock, g), ErrConflict)
	_, e = PublishActivation(lock, active, r.Address, r.Version, "active")
	require.NoError(t, e)
	require.NoError(t, ClearActivation(lock, active))
	require.NoError(t, ClearActivation(lock, active))
	_, e = ReadActivation(lock.DataDir)
	assert.ErrorIs(t, e, os.ErrNotExist)
}
func TestActivationStaleReleaseNeverCommitsAndCleanupPreservesAnotherAttempt(t *testing.T) {
	lock, g, r := activationFixture(t)
	stale := releaseOf(r)
	stale.Attempt = strings.Repeat("e", 32)
	require.NoError(t, writeActivationTestRelease(lock.DataDir, stale))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, e := AwaitActivation(ctx, lock, g, r)
	require.ErrorIs(t, e, context.DeadlineExceeded)
	current, e := ReadUpgradeGuard(lock.DataDir)
	require.NoError(t, e)
	assert.Equal(t, "trial", current.Phase)
	require.NoError(t, ClearActivation(lock, g))
	_, e = readActivationRelease(lock.DataDir)
	assert.False(t, errors.Is(e, os.ErrNotExist))
}
