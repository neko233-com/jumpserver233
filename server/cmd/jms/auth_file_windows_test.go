package main

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthenticationStateHasProtectedWindowsDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	require.NoError(t, saveAuthState(path, authState{Server: "http://127.0.0.1:8080", Next: "login"}))
	descriptor, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, e)
	text := descriptor.String()
	assert.Contains(t, text, "D:P")
	assert.NotContains(t, text, ";;;WD)")
	assert.NotContains(t, text, ";;;BU)")
	require.NoError(t, saveAuthState(path, authState{Server: "http://127.0.0.1:8080", Next: "password-complete"}))
	_, e = os.ReadFile(path)
	require.NoError(t, e)
}
