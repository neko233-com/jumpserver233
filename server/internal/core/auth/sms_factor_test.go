package auth

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSMSMFAPhoneBindingEncryptionGenerationAndReaderBoundary(t *testing.T) {
	s, u := proofService(t)
	login, e := s.Authenticate(u.Username, "synthetic-proof-password")
	require.NoError(t, e)
	token, e := s.CreatePermanentToken(u.ID)
	require.NoError(t, e)
	key, e := s.CreateAccessKey(u.ID)
	require.NoError(t, e)
	_ = key
	verified, stamp, e := s.VerifySMSManagement(u.ID, "synthetic-proof-password", "", login.AccessToken)
	require.NoError(t, e)
	assert.NotEmpty(t, stamp)
	bound, e := s.SetVerifiedSMSContact(u.ID, "+8613800000000", verified.AuthGeneration)
	require.NoError(t, e)
	assert.True(t, bound.SMSMFAEnabled)
	assert.Equal(t, u.AuthGeneration+1, bound.AuthGeneration)
	_, ok := s.ValidateToken(login.AccessToken)
	assert.False(t, ok)
	_, ok = s.ValidatePermanentToken(token.Token)
	assert.False(t, ok)
	assert.NotEqual(t, stamp, s.SMSIdentityStamp(u.ID))
	phone, generation, e := s.SMSContact(u.ID)
	require.NoError(t, e)
	assert.Equal(t, "+8613800000000", phone)
	assert.Equal(t, bound.AuthGeneration, generation)
	duplicate, e := s.SetVerifiedSMSContact(u.ID, phone, u.AuthGeneration)
	require.NoError(t, e)
	assert.Equal(t, bound.AuthGeneration, duplicate.AuthGeneration)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), phone)
	assert.Contains(t, string(raw), `"version":4`)
	public, _ := json.Marshal(bound)
	assert.NotContains(t, string(public), phone)
	reloaded, e := OpenServiceWithVaultKey(s.path, []byte(strings.Repeat("p", 32)))
	require.NoError(t, e)
	restored, _, e := reloaded.SMSContact(u.ID)
	require.NoError(t, e)
	assert.Equal(t, phone, restored)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["version"] = json.RawMessage(`3`)
	bad, e := json.Marshal(doc)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(s.path, bad, 0600))
	_, e = OpenServiceWithVaultKey(s.path, []byte(strings.Repeat("p", 32)))
	assert.ErrorIs(t, e, ErrUserStoreCorrupt)
}
func TestSMSMFAStampIsPrivateAndPreservesRadiusAcrossLoginProofs(t *testing.T) {
	s, u := proofService(t)
	login, e := s.Authenticate(u.Username, "synthetic-proof-password")
	require.NoError(t, e)
	sms, radius := strings.Repeat("a", 64), strings.Repeat("b", 64)
	require.NoError(t, s.SetSessionSMSStamp(login.AccessToken, u.ID, sms))
	require.NoError(t, s.SetSessionSecondaryStamp(login.AccessToken, u.ID, radius))
	proof, e := s.QuarantineLogin(login.AccessToken)
	require.NoError(t, e)
	value, e := s.LoginProofSMSStamp(proof.Proof, u.ID)
	require.NoError(t, e)
	assert.Equal(t, sms, value)
	next, e := s.ResumeLoginProof(proof.Proof)
	require.NoError(t, e)
	assert.Equal(t, sms, s.SessionSMSStamp(next.AccessToken))
	assert.Equal(t, radius, s.SessionSecondaryStamp(next.AccessToken))
	public, _ := json.Marshal(next)
	assert.NotContains(t, string(public), sms)
	assert.NotContains(t, string(public), radius)
}
func TestSMSMFAFirstLoginEnrollmentReissuesOnlyTheCurrentVerifiedIdentity(t *testing.T) {
	s, u := proofService(t)
	_, proof := quarantineTest(t, s)
	session, e := s.ResumeLoginProofWithSMSContact(proof.Proof, "+8613800000000", u.AuthGeneration)
	require.NoError(t, e)
	assert.True(t, session.User.SMSMFAEnabled)
	assert.Equal(t, u.AuthGeneration+1, session.User.AuthGeneration)
	_, e = s.ResumeLoginProofWithSMSContact(proof.Proof, "+8613800000001", u.AuthGeneration)
	assert.ErrorIs(t, e, ErrInvalidLoginProof)
	_, e = s.ResumeLoginProof(proof.Proof)
	assert.ErrorIs(t, e, ErrInvalidLoginProof)
	_, ok := s.ValidateToken(session.AccessToken)
	assert.True(t, ok)
}

func TestSMSMFAChainedFactorsKeepTheOriginalProofDeadlineAfterAUserDelay(t *testing.T) {
	s, u := proofService(t)
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	_, first := quarantineTest(t, s)
	now = now.Add(90 * time.Second)
	next, err := s.ResumeLoginProof(first.Proof)
	require.NoError(t, err)
	stamp := strings.Repeat("d", 64)
	require.NoError(t, s.SetSessionSMSStamp(next.AccessToken, u.ID, stamp))
	review, err := s.QuarantineLogin(next.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, first.ExpiresAt, review.ExpiresAt)
	actual, err := s.LoginProofSMSStamp(review.Proof, u.ID)
	require.NoError(t, err)
	assert.Equal(t, stamp, actual)
	now = first.ExpiresAt
	_, err = s.ResumeLoginProof(review.Proof)
	assert.ErrorIs(t, err, ErrInvalidLoginProof)
}
