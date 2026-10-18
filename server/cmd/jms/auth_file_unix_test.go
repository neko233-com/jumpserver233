//go:build !windows

package main

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthenticationStateUsesOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	require.NoError(t, saveAuthState(path, authState{Server: "http://127.0.0.1:8080", Next: "login"}))
	info, e := os.Stat(path)
	require.NoError(t, e)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
