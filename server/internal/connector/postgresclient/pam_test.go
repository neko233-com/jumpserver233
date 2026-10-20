package postgresclient

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestPAMSCRAMVerifierUsesIndependentSaltAndMatchingStoredKeys(t *testing.T) {
	password := "synthetic-PAM-password-233"
	one, e := scramVerifier(password)
	require.NoError(t, e)
	two, e := scramVerifier(password)
	require.NoError(t, e)
	assert.NotEqual(t, one, two)
	assert.NotContains(t, one, password)
	parts := strings.Split(one, "$")
	require.Len(t, parts, 3)
	assert.Equal(t, "SCRAM-SHA-256", parts[0])
	salt, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(parts[1], "4096:"))
	require.NoError(t, e)
	require.Len(t, salt, 16)
	salted, e := pbkdf2.Key(sha256.New, password, salt, 4096, 32)
	require.NoError(t, e)
	keys := strings.Split(parts[2], ":")
	require.Len(t, keys, 2)
	h := hmac.New(sha256.New, salted)
	h.Write([]byte("Client Key"))
	stored := sha256.Sum256(h.Sum(nil))
	assert.Equal(t, base64.StdEncoding.EncodeToString(stored[:]), keys[0])
	h = hmac.New(sha256.New, salted)
	h.Write([]byte("Server Key"))
	assert.Equal(t, base64.StdEncoding.EncodeToString(h.Sum(nil)), keys[1])
	_, e = scramVerifier("bad\npassword")
	assert.Error(t, e)
}
