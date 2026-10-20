package identityscope

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSourcePathsAreExactAndReturnToLocalLogin(t *testing.T) {
	id := "idp-0123456789abcdef0123456789abcdef"
	p := Prefix(id)
	assert.True(t, ValidPrefix(p))
	assert.Equal(t, id, ID(p))
	for _, bad := range []string{"idp-../escape", "idp-0123456789ABCDEF0123456789abcdef", id + "/other", ""} {
		assert.False(t, ValidID(bad))
	}
	assert.False(t, ValidPrefix(p+"/"))
	assert.Equal(t, p+"/api/v1/authentication/saml/finalize?code=a", ReturnPath(p, "/api/v1/authentication/saml/finalize?code=a"))
	assert.Equal(t, "/login?identity_source="+id+"&sso=continue", ReturnPath(p, "/login?sso=continue"))
	assert.Equal(t, "/console", ReturnPath(p, "/console"))
	assert.Equal(t, "/login?sso=continue", ReturnPath("", "/login?sso=continue"))
}
