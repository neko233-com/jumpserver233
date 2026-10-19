package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeInstallCLIRejectsIncompleteArgumentsBeforePromptOrNetwork(t *testing.T) {
	for _, args := range [][]string{{}, {"install"}, {"install", "--root", "x", "--data-dir", "x", "--sha256", "x", "--request-id", "valid-request"}, {"run", "--root", "x", "--data-dir", "x"}, {"install-status", "--root", "x", "--passphrase-file", "-"}, {"install-recover", "--root", "x", "--revision", "1"}} {
		var out bytes.Buffer
		prompt := func(bool) ([]byte, error) { t.Fatal("invalid arguments prompted for a passphrase"); return nil, nil }
		require.Error(t, executeInstallation(context.Background(), args, strings.NewReader(""), &out, io.Discard, prompt))
		assert.Empty(t, out.String())
	}
	t.Setenv("JMS_CLUSTER_MODE", "true")
	require.ErrorIs(t, executeInstallation(context.Background(), []string{"install-status", "--root", "x"}, strings.NewReader(""), io.Discard, io.Discard, nil), maintenance.ErrCluster)
}
func TestNativeInstallPassphraseInputIsBoundedAndNeverEchoed(t *testing.T) {
	password, e := readInstallPassphrase(strings.NewReader("synthetic-install-password\n"), "-", nil, false)
	require.NoError(t, e)
	assert.Equal(t, "synthetic-install-password", string(password))
	clear(password)
	for _, value := range []string{"short", strings.Repeat("a", 1027)} {
		password, e = readInstallPassphrase(strings.NewReader(value), "-", nil, false)
		require.Error(t, e)
		assert.Nil(t, password)
	}
}
