package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecondaryStampRemainsPrivateAcrossQuarantineAndResume(t *testing.T) {
	s, u := proofService(t)
	login, e := s.Authenticate("proof.admin", "synthetic-proof-password")
	require.NoError(t, e)
	stamp := strings.Repeat("a", 64)
	assert.Empty(t, s.SessionSecondaryStamp(login.AccessToken))
	require.NoError(t, s.SetSessionSecondaryStamp(login.AccessToken, u.ID, stamp))
	assert.ErrorIs(t, s.SetSessionSecondaryStamp(login.AccessToken, "other", stamp), ErrInvalidLoginProof)
	assert.ErrorIs(t, s.SetSessionSecondaryStamp(login.AccessToken, u.ID, "forged"), ErrInvalidLoginProof)
	proof, e := s.QuarantineLogin(login.AccessToken)
	require.NoError(t, e)
	value, e := s.LoginProofSecondaryStamp(proof.Proof, u.ID)
	require.NoError(t, e)
	assert.Equal(t, stamp, value)
	_, e = s.LoginProofSecondaryStamp(proof.Proof, "other")
	assert.ErrorIs(t, e, ErrInvalidLoginProof)
	session, e := s.ResumeLoginProof(proof.Proof)
	require.NoError(t, e)
	assert.Equal(t, stamp, s.SessionSecondaryStamp(session.AccessToken))
	require.NoError(t, s.RevokeToken(session.AccessToken))
	assert.Empty(t, s.SessionSecondaryStamp(session.AccessToken))
}
