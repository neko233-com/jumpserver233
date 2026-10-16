package sshclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xssh "golang.org/x/crypto/ssh"
)

func planTestKey(t *testing.T) xssh.PublicKey {
	t.Helper()
	_, private, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)
	signer, e := xssh.NewSignerFromKey(private)
	require.NoError(t, e)
	return signer.PublicKey()
}
func TestKeyPlanPreservesRestrictionsOtherKeysAndAuthorityEntries(t *testing.T) {
	old := sshidentity.Signer().PublicKey()
	next := planTestKey(t)
	other := planTestKey(t)
	id := "kr-0123456789abcdef0123456789abcdef"
	oldText := strings.TrimSpace(string(xssh.MarshalAuthorizedKey(old)))
	otherText := strings.TrimSpace(string(xssh.MarshalAuthorizedKey(other)))
	oldLine := `restrict,from="127.0.0.1,::1",command="printf \"a,b\"" ` + oldText + " original comment"
	second := `no-agent-forwarding ` + oldText + " second"
	unrelated := "# preserved comment\n" + otherText + " unrelated\ncert-authority " + otherText + " authority\ninvalid opaque line\n"
	before := []byte(unrelated + oldLine + "\n" + second + "\n")
	plan, e := prepareKeyPlan(before, old.Marshal(), next.Marshal(), id)
	require.NoError(t, e)
	require.Len(t, plan.NewLines, 2)
	_, oldOptions, _, ok := parsedAuthorization(oldLine)
	require.True(t, ok)
	_, newOptions, comment, ok := parsedAuthorization(plan.NewLines[0])
	require.True(t, ok)
	assert.Equal(t, oldOptions, newOptions)
	assert.Equal(t, keyMarker(id), comment)
	installed, e := transformKeyFile(before, plan, "install")
	require.NoError(t, e)
	assert.Contains(t, string(installed), string(before))
	again, e := transformKeyFile(installed, plan, "install")
	require.NoError(t, e)
	assert.Equal(t, installed, again)
	retired, e := transformKeyFile(installed, plan, "retire")
	require.NoError(t, e)
	assert.Empty(t, matchingKeyLines(retired, old.Marshal()))
	assert.Contains(t, string(retired), unrelated)
	assert.Len(t, matchingKeyLines(retired, next.Marshal()), 2)
	again, e = transformKeyFile(retired, plan, "retire")
	require.NoError(t, e)
	assert.Equal(t, retired, again)
	rolled, e := transformKeyFile(installed, plan, "rollback")
	require.NoError(t, e)
	assert.Equal(t, before, rolled)
	changed := []byte(strings.Replace(string(installed), oldLine, "no-pty "+oldText+" edited", 1))
	_, e = transformKeyFile(changed, plan, "retire")
	assert.ErrorIs(t, e, ErrAuthorizedKeysChanged)
	rolled, e = transformKeyFile(changed, plan, "rollback")
	require.NoError(t, e)
	assert.Contains(t, string(rolled), "no-pty "+oldText+" edited")
	assert.Empty(t, matchingKeyLines(rolled, next.Marshal()))
	widened := plan
	widened.NewLines = append([]string(nil), plan.NewLines...)
	widened.NewLines[0] = generatedKeyLine(next, nil, id)
	assert.ErrorIs(t, ValidateKeyPlan(widened), ErrKeyPlan)
	_, e = prepareKeyPlan(append(before, []byte("cert-authority "+oldText+" shared CA\n")...), old.Marshal(), next.Marshal(), id)
	assert.ErrorIs(t, e, ErrAuthorizedKeysUnsupported)
	foreign := append(installed, []byte(strings.TrimSpace(string(xssh.MarshalAuthorizedKey(next)))+" foreign\n")...)
	_, e = transformKeyFile(foreign, plan, "rollback")
	assert.ErrorIs(t, e, ErrAuthorizedKeysChanged)
}
func TestKeyInstallationPlanBoundsAndConflictingEdits(t *testing.T) {
	next := planTestKey(t)
	other := planTestKey(t)
	id := "kr-abcdef0123456789abcdef0123456789"
	before := []byte("# unchanged\n")
	plan, e := prepareKeyPlan(before, nil, next.Marshal(), id)
	require.NoError(t, e)
	manual := []byte(strings.TrimSpace(string(xssh.MarshalAuthorizedKey(other))) + " manual\n")
	installed, e := transformKeyFile(append(before, manual...), plan, "install")
	require.NoError(t, e)
	assert.Contains(t, string(installed), string(manual))
	_, e = prepareKeyPlan(make([]byte, maxAuthorizedKeysBytes+1), nil, next.Marshal(), id)
	require.Error(t, e)
	_, e = prepareKeyPlan(before, nil, next.Marshal(), "not-an-operation")
	require.Error(t, e)
	_, e = prepareKeyPlan(before, other.Marshal(), next.Marshal(), id)
	assert.ErrorIs(t, e, ErrAuthorizedKeyMissing)
	plan.NewLines = []string{"invalid"}
	assert.ErrorIs(t, ValidateKeyPlan(plan), ErrKeyPlan)
}
