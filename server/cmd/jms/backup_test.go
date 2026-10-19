package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackupCLIOfflineWorkflowProtectedStdinAndIdempotence(t *testing.T) {
	t.Setenv("JMS_CLUSTER_MODE", "false")
	t.Setenv("JMS_VAULT_KEY", "")
	parent := t.TempDir()
	data := filepath.Join(parent, "data")
	key := bytes.Repeat([]byte{3}, 32)
	require.NoError(t, maintenance.RecordMode(data, false))
	require.NoError(t, os.WriteFile(filepath.Join(data, "vault.key"), key, 0600))
	require.NoError(t, maintenance.RecordVaultKey(data, key))
	file := filepath.Join(parent, "snapshot.jmsbackup")
	password := "synthetic-cli-backup-password"
	var output bytes.Buffer
	run := func(args ...string) error {
		output.Reset()
		return executeBackup(context.Background(), args, strings.NewReader(password+"\n"), &output, &output, func(bool) ([]byte, error) { t.Fatal("protected stdin must not prompt"); return nil, nil })
	}
	require.NoError(t, run("create", "--file", file, "--data-dir", data, "--passphrase-file", "-"))
	var result maintenance.Result
	require.NoError(t, json.Unmarshal(output.Bytes(), &result))
	assert.Len(t, result.BackupID, 32)
	assert.NotContains(t, output.String(), password)
	assert.NotContains(t, output.String(), "vault.key")
	require.NoError(t, run("verify", "--file", file, "--passphrase-file", "-"))
	target := filepath.Join(parent, "restored")
	require.NoError(t, run("restore", "--file", file, "--data-dir", target, "--passphrase-file", "-"))
	require.FileExists(t, filepath.Join(target, "vault.key"))
	require.NoError(t, run("restore", "--file", file, "--data-dir", target, "--passphrase-file", "-"))
	require.NoError(t, json.Unmarshal(output.Bytes(), &result))
	assert.True(t, result.Unchanged)
	require.NoError(t, run("recover", "--data-dir", target))
	assert.JSONEq(t, `{"status":"ready"}`, output.String())
}
func TestBackupCLIRejectsUnsafeArgumentsClusterAndInvalidPassphrases(t *testing.T) {
	t.Setenv("JMS_CLUSTER_MODE", "false")
	t.Setenv("JMS_VAULT_KEY", "")
	for _, args := range [][]string{nil, {"unknown"}, {"create"}, {"verify", "--file", "x", "--replace"}, {"recover", "--file", "x"}, {"recover", "--passphrase-file", "-"}, {"create", "--file", "x", "--password", "secret"}, {"verify", "--file", "x", "extra"}} {
		e := executeBackup(context.Background(), args, strings.NewReader(""), ioDiscard{}, ioDiscard{}, func(bool) ([]byte, error) { return nil, nil })
		assert.Error(t, e)
	}
	for _, password := range []string{"short", strings.Repeat("x", 1025)} {
		e := executeBackup(context.Background(), []string{"verify", "--file", "x", "--passphrase-file", "-"}, strings.NewReader(password), ioDiscard{}, ioDiscard{}, nil)
		assert.ErrorContains(t, e, "12-1024")
	}
	t.Setenv("JMS_CLUSTER_MODE", "true")
	e := executeBackup(context.Background(), []string{"create", "--file", "x", "--passphrase-file", "-"}, strings.NewReader("synthetic-valid-backup-key"), ioDiscard{}, ioDiscard{}, nil)
	assert.ErrorIs(t, e, maintenance.ErrCluster)
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
