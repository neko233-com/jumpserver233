package hostagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func adminTestTask(t *testing.T) AccountAdminTask {
	t.Helper()
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	raw := append([]byte{0, 0, 0, 11}, []byte("ssh-ed25519")...)
	raw = append(raw, 0, 0, 0, 32)
	raw = append(raw, pub...)
	return AccountAdminTask{ID: "ra-" + strings.Repeat("a", 32), Action: "create", Username: "adminqa_test", Shell: "/bin/sh", PublicKey: "ssh-ed25519 " + base64.StdEncoding.EncodeToString(raw)}
}
func TestAccountAdminContractAcceptsOnlyExplicitRegularIdentityActionsAndPublicKeys(t *testing.T) {
	task := adminTestTask(t)
	require.NoError(t, task.Validate())
	assert.NotEmpty(t, AccountAdminKeyFingerprint(task.PublicKey))
	for _, change := range []func(*AccountAdminTask){func(v *AccountAdminTask) { v.Username = "root" }, func(v *AccountAdminTask) { v.Username = "--force" }, func(v *AccountAdminTask) { v.Username = "../escape" }, func(v *AccountAdminTask) { v.Username = "name\narg" }, func(v *AccountAdminTask) { v.ID = "ra-" + strings.Repeat("A", 32) }, func(v *AccountAdminTask) { v.PublicKey += " command=evil" }, func(v *AccountAdminTask) { v.Shell = "/bin/sh; evil" }, func(v *AccountAdminTask) { v.UID = 1000 }, func(v *AccountAdminTask) { v.Action = "kill" }} {
		bad := task
		change(&bad)
		assert.Error(t, bad.Validate())
	}
	for _, action := range []string{"disable", "enable", "delete"} {
		v := task
		v.Action = action
		v.PublicKey = ""
		v.Shell = ""
		v.UID = 1000
		require.NoError(t, v.Validate())
		v.UID = 0
		assert.Error(t, v.Validate())
		v.UID = 999
		assert.Error(t, v.Validate())
		v.UID = 65534
		assert.Error(t, v.Validate())
	}
	req := AccountAdminRequest{Task: task, Mode: "apply"}
	raw, e := json.Marshal(req)
	require.NoError(t, e)
	parsed, e := DecodeAccountAdminRequest(raw)
	require.NoError(t, e)
	assert.Equal(t, req, parsed)
	for _, bad := range []string{string(raw) + " {}", strings.Replace(string(raw), `"mode":"apply"`, `"mode":"apply","mode":"inspect"`, 1), strings.Replace(string(raw), `"mode":"apply"`, `"mode":"apply","password":"not-accepted"`, 1), strings.Replace(string(raw), `"mode":"apply"`, `"mode":"auto"`, 1)} {
		_, e = DecodeAccountAdminRequest([]byte(bad))
		require.Error(t, e)
	}
}
func TestAccountAdminResultBindsDigestIdentityAndNeverAcceptsSecretFields(t *testing.T) {
	task := adminTestTask(t)
	result := AccountAdminResult{Format: AccountAdminFormat, ID: task.ID, Digest: task.Digest(), Action: task.Action, Username: task.Username, UID: 1000, GID: 1000, Home: "/home/" + task.Username, Shell: task.Shell, State: "applied", Stage: "ready"}
	raw, e := json.Marshal(result)
	require.NoError(t, e)
	decoded, e := DecodeAccountAdminResult(raw, task)
	require.NoError(t, e)
	assert.Equal(t, result, decoded)
	for _, change := range []func(*AccountAdminResult){func(v *AccountAdminResult) { v.Digest = strings.Repeat("b", 64) }, func(v *AccountAdminResult) { v.Username = "other" }, func(v *AccountAdminResult) { v.UID = 0 }, func(v *AccountAdminResult) { v.ErrorCode = "failed" }, func(v *AccountAdminResult) { v.State = "running" }} {
		bad := result
		change(&bad)
		raw, _ := json.Marshal(bad)
		_, e = DecodeAccountAdminResult(raw, task)
		require.Error(t, e)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"password":"not-accepted"}`)...)
	_, e = DecodeAccountAdminResult(raw, task)
	require.Error(t, e)
}
