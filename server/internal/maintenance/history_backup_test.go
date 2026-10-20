package maintenance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/executionhistory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const backupHistoryOrg = "00000000-0000-0000-0000-000000000099"

func backupHistoryKey(root []byte, org bool) []byte {
	if !org {
		return root
	}
	mac := hmac.New(sha256.New, root)
	mac.Write([]byte("jms233/organization-vault/v1\x00" + backupHistoryOrg))
	return mac.Sum(nil)
}
func backupHistoryPath(data string, org bool) string {
	if org {
		return filepath.Join(data, "organizations", backupHistoryOrg, "execution-history.sqlite")
	}
	return filepath.Join(data, "execution-history.sqlite")
}

func TestBackupHistoryCrashWriterHelper(t *testing.T) {
	if os.Getenv("JMS_QA_HISTORY_CRASH_CHILD") != "1" {
		return
	}
	data := os.Getenv("JMS_QA_HISTORY_DATA")
	key, e := os.ReadFile(filepath.Join(data, "vault.key"))
	require.NoError(t, e)
	for _, org := range []bool{false, true} {
		s, e := executionhistory.Open(backupHistoryPath(data, org), backupHistoryKey(key, org), nil)
		require.NoError(t, e)
		at := time.Now().UTC()
		require.NoError(t, s.Put(t.Context(), executionhistory.Record{Kind: "job", ID: "archived-job", Owner: "qa-owner", RequestOwner: "qa-owner", RequestID: "original-request", CreatedAt: at, Summary: []byte(`{"state":"succeeded"}`), Payload: []byte(`{"output":"synthetic-private-archived-output"}`)}))
		// Deliberately do not Close: the parent backs up a stopped process whose
		// latest commits still exist in WAL, as after a power loss.
	}
	os.Exit(0)
}

func TestOfflineBackupRestoresCommittedWALHistoryAndIdempotentRequests(t *testing.T) {
	opt := fixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBackupHistoryCrashWriterHelper$")
	child.Env = append(os.Environ(), "JMS_QA_HISTORY_CRASH_CHILD=1", "JMS_QA_HISTORY_DATA="+opt.DataDir)
	require.NoError(t, child.Run())
	for _, org := range []bool{false, true} {
		st, e := os.Stat(backupHistoryPath(opt.DataDir, org) + "-wal")
		require.NoError(t, e)
		assert.Greater(t, st.Size(), int64(0))
	}
	created, e := Create(ctx, opt)
	require.NoError(t, e)
	verified, e := Verify(ctx, opt)
	require.NoError(t, e)
	assert.Equal(t, created.BackupID, verified.BackupID)
	restore := opt
	restore.DataDir = filepath.Join(t.TempDir(), "restored")
	restored, e := Restore(ctx, restore)
	require.NoError(t, e)
	assert.Equal(t, created.BackupID, restored.BackupID)
	key, e := os.ReadFile(filepath.Join(restore.DataDir, "vault.key"))
	require.NoError(t, e)
	for _, org := range []bool{false, true} {
		s, e := executionhistory.Open(backupHistoryPath(restore.DataDir, org), backupHistoryKey(key, org), nil)
		require.NoError(t, e)
		require.NoError(t, s.Verify(ctx))
		record, e := s.FindRequest(ctx, "job", "qa-owner", "original-request")
		require.NoError(t, e)
		assert.JSONEq(t, `{"output":"synthetic-private-archived-output"}`, string(record.Payload))
		require.NoError(t, s.Put(ctx, executionhistory.Record{Kind: "job", ID: "after-import", Owner: "qa-owner", RequestOwner: "qa-owner", RequestID: "after-import-request", CreatedAt: time.Now().UTC(), Summary: []byte(`{"state":"succeeded"}`), Payload: []byte(`{"output":"new-data-after-import"}`)}))
		require.NoError(t, s.Close())
	}
	again, e := Restore(ctx, restore)
	require.NoError(t, e)
	assert.True(t, again.Unchanged)
	// A repeated import does not overwrite data that evolved after the first import.
	s, e := executionhistory.Open(backupHistoryPath(restore.DataDir, false), key, nil)
	require.NoError(t, e)
	defer s.Close()
	_, e = s.FindRequest(ctx, "job", "qa-owner", "original-request")
	require.NoError(t, e)
	after, e := s.FindRequest(ctx, "job", "qa-owner", "after-import-request")
	require.NoError(t, e)
	assert.JSONEq(t, `{"output":"new-data-after-import"}`, string(after.Payload))
}
