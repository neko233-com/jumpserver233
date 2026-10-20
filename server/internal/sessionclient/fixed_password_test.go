package sessionclient

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFixedPasswordSDKSeparatesWriteInputFromPublicMetadata(t *testing.T) {
	secret := strings.Repeat("Ab2!", 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.Header.Get("Authorization"))
		var input RotationPlanSaveInput
		require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
		assert.True(t, input.FixedPassword == secret)
		assert.Equal(t, "fixed-sdk-request", input.RequestID)
		w.WriteHeader(201)
		// Foreign credential keys must never become fields of the public DTO.
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "fixed-sdk-plan", "password_mode": "fixed", "fixed_password": secret, "fixed_secret_id": "private-id", "save_request_id": input.RequestID})
	}))
	defer server.Close()
	client, e := New(server.URL, "synthetic-token")
	require.NoError(t, e)
	output, e := client.SaveRotationPlanRequest(context.Background(), "", RotationPlanSaveInput{RotationPlanInput: RotationPlanInput{Name: "Fixed metadata", Kind: "manual", PasswordMode: "fixed", Targets: []RotationSelection{{AccountID: "account-a"}}}, RequestID: "fixed-sdk-request", FixedPassword: secret})
	require.NoError(t, e)
	assert.Equal(t, "fixed", output.PasswordMode)
	assert.Equal(t, "fixed-sdk-request", output.SaveRequestID)
	raw, e := json.Marshal(output)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), secret)
	assert.NotContains(t, string(raw), "fixed_secret_id")
}
