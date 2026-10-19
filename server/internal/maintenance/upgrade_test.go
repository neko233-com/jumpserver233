package maintenance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpgradeGuardBlocksOrdinaryStartupBackupAndWrongTarget(t *testing.T) {
	opt := fixture(t)
	lock, e := Acquire(opt.DataDir)
	require.NoError(t, e)
	require.NoError(t, UpgradeSource(lock))
	g := UpgradeGuard{Schema: 1, RootID: strings.Repeat("a", 32), ID: strings.Repeat("b", 32), BinarySHA256: strings.Repeat("c", 64), Phase: "pending"}
	require.NoError(t, SetUpgradeGuard(lock, g))
	require.NoError(t, SetUpgradeGuard(lock, g))
	require.NoError(t, lock.Close())
	assert.ErrorIs(t, CheckUpgradeGuard(opt.DataDir, "", g.BinarySHA256), ErrUpgradePending)
	assert.ErrorIs(t, CheckUpgradeGuard(opt.DataDir, g.ID, strings.Repeat("d", 64)), ErrUpgradePending)
	assert.NoError(t, CheckUpgradeGuard(opt.DataDir, g.ID, g.BinarySHA256))
	_, e = Create(context.Background(), opt)
	assert.ErrorIs(t, e, ErrUpgradePending)
	_, e = Restore(context.Background(), opt)
	assert.ErrorIs(t, e, ErrUpgradePending)
	lock, e = Acquire(opt.DataDir)
	require.NoError(t, e)
	defer lock.Close()
	changed := g
	changed.RootID = strings.Repeat("d", 32)
	assert.ErrorIs(t, SetUpgradeGuard(lock, changed), ErrConflict)
	assert.ErrorIs(t, ClearUpgradeGuard(lock, g.RootID, strings.Repeat("e", 32)), ErrConflict)
	g.Phase = "active"
	require.NoError(t, SetUpgradeGuard(lock, g))
	require.NoError(t, CheckUpgradeGuard(opt.DataDir, "", g.BinarySHA256))
	require.NoError(t, CheckNoUpgradePending(opt.DataDir))
	assert.ErrorIs(t, CheckUpgradeGuard(opt.DataDir, g.ID, g.BinarySHA256), ErrUpgradePending)
	require.NoError(t, ClearUpgradeGuard(lock, g.RootID, g.ID))
	require.NoError(t, ClearUpgradeGuard(lock, g.RootID, g.ID))
	assert.NoError(t, CheckUpgradeGuard(opt.DataDir, "", ""))
}
func TestUpgradeLockedCheckpointsRequireLiveLockAndExcludeGuard(t *testing.T) {
	opt := fixture(t)
	_, e := CreateLocked(context.Background(), opt, nil)
	assert.ErrorIs(t, e, ErrBusy)
	lock, e := Acquire(opt.DataDir)
	require.NoError(t, e)
	g := UpgradeGuard{Schema: 1, RootID: strings.Repeat("a", 32), ID: strings.Repeat("b", 32), BinarySHA256: strings.Repeat("c", 64), Phase: "pending"}
	require.NoError(t, SetUpgradeGuard(lock, g))
	_, e = CreateLocked(context.Background(), opt, lock)
	require.NoError(t, e)
	opt.DataDir = filepath.Join(filepath.Dir(opt.DataDir), "restored")
	require.NoError(t, lock.Close())
	_, e = Restore(context.Background(), opt)
	require.NoError(t, e)
	_, e = ReadUpgradeGuard(opt.DataDir)
	assert.ErrorIs(t, e, os.ErrNotExist)
	_, e = CreateLocked(context.Background(), opt, lock)
	assert.ErrorIs(t, e, ErrBusy)
	_, e = RestoreLocked(context.Background(), opt, lock)
	assert.ErrorIs(t, e, ErrBusy)
}

func TestUpgradeCheckpointReplayRetainsPreviousDataLocation(t *testing.T) {
	opt := fixture(t)
	_, e := Create(context.Background(), opt)
	require.NoError(t, e)
	opt.Replace = true
	first, e := Restore(context.Background(), opt)
	require.NoError(t, e)
	require.NotEmpty(t, first.PreviousDataDir)
	again, e := Restore(context.Background(), opt)
	require.NoError(t, e)
	assert.True(t, again.Unchanged)
	assert.Equal(t, first.PreviousDataDir, again.PreviousDataDir)
	assert.DirExists(t, again.PreviousDataDir)
}
