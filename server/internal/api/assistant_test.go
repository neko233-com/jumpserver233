package api

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/aichat"
	"github.com/neko233-com/jumpserver233/server/internal/core/assistant"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssistantAuthorizationGuardCancelsWhileTeardownOwnsWriteLock(t *testing.T) {
	var global, local sync.RWMutex
	global.Lock()
	defer global.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		unlock, e := assistantPermissionReadLock(ctx, &global, &local)
		if e == nil {
			unlock()
		}
		done <- e
	}()
	cancel()
	select {
	case e := <-done:
		assert.ErrorIs(t, e, assistant.ErrDenied)
	case <-time.After(time.Second):
		t.Fatal("authorization guard blocked teardown")
	}
	require.True(t, local.TryLock())
	local.Unlock()
}
func TestAssistantAPIUsesExplicitPermissionsPrincipalAndWriteOnlySecrets(t *testing.T) {
	dir := t.TempDir()
	a, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, e)
	admin, e := a.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	user, e := a.CreateUser("assistant.operator", "synthetic-assistant-operator-password", coreauth.RoleOperator)
	require.NoError(t, e)
	other, e := a.CreateUser("assistant.other", "synthetic-assistant-other-password", coreauth.RoleOperator)
	require.NoError(t, e)
	adminLogin, e := a.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	login, e := a.Authenticate(user.Username, "synthetic-assistant-operator-password")
	require.NoError(t, e)
	otherLogin, e := a.Authenticate(other.Username, "synthetic-assistant-other-password")
	require.NoError(t, e)
	store, e := assistant.Open(filepath.Join(dir, "assistant.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer store.Close()
	roles, e := rbac.Open(filepath.Join(dir, "rbac.json"), nil)
	require.NoError(t, e)
	router := NewRouter("test", Dependencies{Auth: a, Assistant: store, RBAC: roles})
	var calls atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Explain only, never execute"},"finish_reason":"stop"}]}`))
	}))
	defer provider.Close()
	secret := "synthetic-assistant-test-key"
	config := assistant.SettingsInput{Settings: aichat.Settings{Endpoint: provider.URL + "/v1/chat/completions", Model: "synthetic-model", MaxTokens: 512, RootCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}))}, Enabled: true, Secret: &secret, RequestID: "assistant-api-settings"}
	raw, e := json.Marshal(config)
	require.NoError(t, e)
	denied := doJSONRequest(t, router, "PUT", "/api/v1/assistant/settings", string(raw), login.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 403, denied.Code)
	saved := doJSONRequest(t, router, "PUT", "/api/v1/assistant/settings", string(raw), adminLogin.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, saved.Code, saved.Body.String())
	assert.NotContains(t, saved.Body.String(), secret)
	body := `{"message":"Explain pwd","locale":"en","consent":true,"revision":0,"request_id":"assistant-api-question"}`
	denied = doJSONRequest(t, router, "POST", "/api/v1/assistant/turns", body, login.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 403, denied.Code)
	assert.Zero(t, calls.Load())
	role, e := roles.SaveRole("", rbac.RoleInput{Name: "Assistant user", Permissions: []string{"assistant.use"}}, admin.ID, admin.Username)
	require.NoError(t, e)
	for _, u := range []coreauth.User{user, other} {
		_, e = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: u.ID, RoleIDs: []string{role.ID}}, admin.ID, admin.Username)
		require.NoError(t, e)
	}
	response := doJSONRequest(t, router, "POST", "/api/v1/assistant/turns", body, login.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, response.Code, response.Body.String())
	var result assistant.SubmitResult
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	assert.Equal(t, "completed", result.Turn.Status)
	again := doJSONRequest(t, router, "POST", "/api/v1/assistant/turns", body, login.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, again.Code)
	assert.EqualValues(t, 1, calls.Load())
	for _, path := range []string{"/api/v1/assistant/settings", "/api/v1/assistant/audit", "/api/v1/assistant/conversations?all=true"} {
		response = doJSONRequest(t, router, "GET", path, "", login.AccessToken, "127.0.0.1:12345")
		assert.Equal(t, 403, response.Code, path)
	}
	response = doJSONRequest(t, router, "GET", "/api/v1/assistant/conversations/"+result.ConversationID, "", otherLogin.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 404, response.Code)
	response = doJSONRequest(t, router, "GET", "/api/v1/assistant/conversations/"+result.ConversationID+"?all=true", "", adminLogin.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, response.Code)
	var conversation assistant.Conversation
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &conversation))
	assert.Equal(t, user.ID, conversation.OwnerID)
	forged := `{"message":"Explain pwd","locale":"en","consent":true,"revision":0,"request_id":"assistant-forged-question","owner_id":"admin"}`
	response = doJSONRequest(t, router, "POST", "/api/v1/assistant/turns", forged, login.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 400, response.Code)
}
