package api

import (
	"net/http/httptest"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrganizationHeaderIsExplicitAndRejectsAmbiguity(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/v1/assets", nil)
	id, e := organizationHeader(r)
	require.NoError(t, e)
	assert.Equal(t, organizations.DefaultID, id)
	r.Header.Set("X-JMS-ORG", "11111111-1111-4111-8111-111111111111")
	id, e = organizationHeader(r)
	require.NoError(t, e)
	assert.Equal(t, "11111111-1111-4111-8111-111111111111", id)
	r.Header.Add("X-JMS-ORG", organizations.DefaultID)
	_, e = organizationHeader(r)
	assert.ErrorIs(t, e, organizations.ErrInvalid)
	for _, value := range []string{"GLOBAL", "00000000-0000-0000-0000-000000000000", "../../escape", " "} {
		r.Header.Set("X-JMS-ORG", value)
		_, e = organizationHeader(r)
		assert.ErrorIs(t, e, organizations.ErrInvalid, value)
	}
	r = httptest.NewRequest("GET", "/ws/api/v1/sessions/test/terminal?org="+organizations.DefaultID, nil)
	id, e = organizationHeader(r)
	require.NoError(t, e)
	assert.Equal(t, organizations.DefaultID, id)
	r.Header.Set("X-JMS-ORG", "11111111-1111-4111-8111-111111111111")
	_, e = organizationHeader(r)
	assert.ErrorIs(t, e, organizations.ErrInvalid)
	r = httptest.NewRequest("GET", "/ws/api/v1/sessions/test/terminal?org="+organizations.DefaultID+"&org="+organizations.DefaultID, nil)
	_, e = organizationHeader(r)
	assert.ErrorIs(t, e, organizations.ErrInvalid)
	r = httptest.NewRequest("GET", "/api/v1/assets?org="+organizations.DefaultID, nil)
	_, e = organizationHeader(r)
	assert.ErrorIs(t, e, organizations.ErrInvalid)
}
