package sessionclient

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserSDKManagementAndStrictRequests(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-user-sdk", r.Header.Get("Authorization"))
		if r.Method == "POST" {
			var in struct{ Changes []UserChange }
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Len(t, in.Changes, 1)
			assert.Equal(t, 2, in.Changes[0].Revision)
		}
		fmt.Fprint(w, `{"results":[],"total":0}`)
	}))
	defer s.Close()
	c, e := New(s.URL, "synthetic-user-sdk")
	require.NoError(t, e)
	ctx := context.Background()
	_, e = c.ManagedUsers(ctx, "current", "a & b", 0, 25)
	require.NoError(t, e)
	_, e = c.ManagedUser(ctx, "user-test")
	require.NoError(t, e)
	_, e = c.UserAudit(ctx, "user-test", 0, 25)
	require.NoError(t, e)
	name := "name"
	_, e = c.UpdateUser(ctx, "user-test", UserUpdate{Revision: 2, Name: &name})
	require.NoError(t, e)
	for _, action := range []string{"archive", "restore", "revoke"} {
		_, e = c.UserAction(ctx, "user-test", action, 2)
		require.NoError(t, e)
	}
	assert.Equal(t, 7, calls)
	for _, id := range []string{"", "../escape", "bad?query"} {
		_, e = c.ManagedUser(ctx, id)
		require.Error(t, e)
	}
	_, e = c.ManagedUsers(ctx, "invalid", "", 0, 25)
	require.Error(t, e)
	_, e = c.UserAction(ctx, "user-test", "delete", 2)
	require.Error(t, e)
	_, e = c.UserAction(ctx, "user-test", "revoke", 0)
	require.Error(t, e)
	_, e = c.ChangeUsers(ctx, nil)
	require.Error(t, e)
	assert.Equal(t, 7, calls)
}
