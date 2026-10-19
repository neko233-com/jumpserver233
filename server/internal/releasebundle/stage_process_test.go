package releasebundle

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeStageCrashReleasesProcessLockAndCleansOwnedStage(t *testing.T) {
	if os.Getenv("JMS_STAGE_CRASH_TEST") == "1" {
		s, e := openStagingRoot(os.Getenv("JMS_STAGE_CRASH_ROOT"), "linux", "amd64", false)
		require.NoError(t, e)
		defer s.close()
		id, e := stageID()
		require.NoError(t, e)
		name := ".jms233-stage-" + id
		require.NoError(t, s.root.Mkdir(name, 0700))
		require.NoError(t, writeStageJSON(s.root, name+"/"+stageReceiptFile, stageReceipt{Schema: 1, Owner: s.owner.ID, Token: id, ArchiveSHA256: os.Getenv("JMS_STAGE_CRASH_SHA")}, true))
		require.NoError(t, s.root.WriteFile(name+"/partial", []byte("interrupted extraction"), 0600))
		require.NoError(t, os.WriteFile(os.Getenv("JMS_STAGE_CRASH_READY"), []byte("ready"), 0600))
		time.Sleep(time.Hour)
		return
	}
	_, root, archive, sha := stagedFixture(t)
	ready := filepath.Join(t.TempDir(), "ready")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeStageCrashReleasesProcessLockAndCleansOwnedStage$")
	child.Env = append(os.Environ(), "JMS_STAGE_CRASH_TEST=1", "JMS_STAGE_CRASH_ROOT="+root, "JMS_STAGE_CRASH_SHA="+sha, "JMS_STAGE_CRASH_READY="+ready)
	require.NoError(t, child.Start())
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	require.Eventually(t, func() bool { _, e := os.Stat(ready); return e == nil }, 10*time.Second, 20*time.Millisecond)
	_, e := InspectStage(context.Background(), root, sha, "linux", "amd64")
	require.Error(t, e)
	require.NoError(t, child.Process.Kill())
	require.Error(t, child.Wait())
	waited = true
	result, e := Stage(context.Background(), archive, sha, "linux", "amd64", root)
	require.NoError(t, e)
	assert.True(t, result.Unchanged)
	assert.Equal(t, 1, result.CleanedStages)
	n, e := CleanStages(context.Background(), root, "linux", "amd64")
	require.NoError(t, e)
	assert.Zero(t, n)
}
