package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermanentTokenLifecyclePersistsOnlyDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	service, err := OpenService(path)
	require.NoError(t, err)
	admin, err := service.Bootstrap("admin.user", "an-initial-admin-password-123")
	require.NoError(t, err)

	credentials, err := service.CreatePermanentToken(admin.ID)
	require.NoError(t, err)
	assert.True(t, validPermanentTokenID(credentials.ID))
	assert.NotEmpty(t, credentials.Token)
	assert.NotContains(t, credentials.Token, "=")

	owner, valid := service.ValidatePermanentToken(credentials.Token)
	require.True(t, valid)
	assert.Equal(t, admin.ID, owner.ID)
	assert.False(t, func() bool { _, ok := service.ValidateToken(credentials.Token); return ok }(), "permanent tokens must not authenticate as Bearer sessions")

	listed, err := service.ListPermanentTokens(admin.ID)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, credentials.ID, listed[0].ID)
	metadata, err := json.Marshal(listed)
	require.NoError(t, err)
	assert.NotContains(t, string(metadata), credentials.Token)

	stored, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.NotContains(t, string(stored), credentials.Token)

	reloaded, err := OpenService(path)
	require.NoError(t, err)
	owner, valid = reloaded.ValidatePermanentToken(credentials.Token)
	require.True(t, valid)
	assert.Equal(t, admin.ID, owner.ID)

	require.NoError(t, reloaded.DeletePermanentToken(admin.ID, credentials.ID))
	_, valid = reloaded.ValidatePermanentToken(credentials.Token)
	assert.False(t, valid)
	_, err = reloaded.ListPermanentTokens(admin.ID)
	require.NoError(t, err)
	assert.ErrorIs(t, reloaded.DeletePermanentToken(admin.ID, credentials.ID), ErrPermanentTokenNotFound)
}

func TestPermanentTokenLimitAndOwnerBoundary(t *testing.T) {
	service, err := OpenService(filepath.Join(t.TempDir(), "users.json"))
	require.NoError(t, err)
	admin, err := service.Bootstrap("admin.user", "an-initial-admin-password-123")
	require.NoError(t, err)
	operator, err := service.CreateUser("operator.one", "an-operator-password-1234", RoleOperator)
	require.NoError(t, err)

	assert.ErrorIs(t, service.DeletePermanentToken(operator.ID, "pt-00000000000000000000000000000000"), ErrPermanentTokenNotFound)
	for i := 0; i < maxPermanentTokens; i++ {
		_, err := service.CreatePermanentToken(admin.ID)
		require.NoError(t, err)
	}
	_, err = service.CreatePermanentToken(admin.ID)
	assert.ErrorIs(t, err, ErrPermanentTokenLimit)
}
