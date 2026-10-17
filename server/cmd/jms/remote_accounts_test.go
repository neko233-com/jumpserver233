package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteAccountCLIReturnsDurableApprovalTaskWithoutSecretsAndRequiresDeleteConfirmation(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/accounts") {
			json.NewEncoder(w).Encode(sessionclient.ManagedAccountPage{Version: "parent-version", Total: 1, Results: []sessionclient.ManagedAccount{{ID: "account", AssetID: "asset", Username: "remoteqa_test", Version: "version", RemoteAccount: &sessionclient.RemoteAccountState{UID: 1001}}}})
			return
		}
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/remote-account-tasks") {
			var in sessionclient.RemoteAccountInput
			require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
			assert.Equal(t, "remoteqa_test", in.Username)
			assert.NotEmpty(t, in.RequestID)
			if in.Action == "delete" {
				assert.EqualValues(t, 1001, in.UID)
				assert.Equal(t, "account", in.AccountID)
			}
			w.WriteHeader(202)
		}
		w.Write([]byte(`{"operation":{"task":{"id":"ra-task","username":"remoteqa_test","private_key":"synthetic-must-drop"},"attempt":1},"review_id":"review","revision":1,"password":"synthetic-must-drop","state":"prepared"}`))
	}))
	defer s.Close()
	c, e := sessionclient.New(s.URL, "synthetic-token")
	require.NoError(t, e)
	for _, args := range [][]string{{"remote-create", "asset", "--username", "remoteqa_test"}, {"remote-delete", "asset", "--username", "remoteqa_test", "--confirm", "remoteqa_test"}, {"remote-submit", "asset", "ra-task"}, {"remote-attempt", "asset", "ra-task", "--mode", "inspect", "--revision", "2"}} {
		var out bytes.Buffer
		require.NoError(t, executeAccounts(context.Background(), c, args, &out))
		assert.Contains(t, out.String(), "ra-task")
		assert.Contains(t, out.String(), "review")
		assert.NotContains(t, out.String(), "synthetic-must-drop")
	}
	before := calls
	for _, args := range [][]string{{"remote-delete", "asset", "--username", "remoteqa_test"}, {"remote-attempt", "asset", "ra-task", "--mode", "auto", "--revision", "2"}, {"remote-attempt", "asset", "ra-task", "--mode", "apply"}, {"remote-tasks", "asset", "--limit", "101"}, {"remote-create", "asset", "--username", "remoteqa_test", "--uid", "1001"}} {
		require.Error(t, executeAccounts(context.Background(), c, args, &bytes.Buffer{}))
	}
	assert.Equal(t, before, calls)
}
