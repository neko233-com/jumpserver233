package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/neko233-com/jumpserver233/server/internal/config"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/labels"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/core/replayarchive"
	"github.com/neko233-com/jumpserver233/server/internal/core/sshcertificates"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func orgHTTP(t *testing.T, address, method, path, token, organization string, input any, status int) []byte {
	t.Helper()
	var body io.Reader
	if input != nil {
		if value, ok := input.([]byte); ok {
			body = bytes.NewReader(value)
		} else {
			raw, e := json.Marshal(input)
			require.NoError(t, e)
			body = bytes.NewReader(raw)
		}
	}
	r, e := http.NewRequest(method, "http://"+address+path, body)
	require.NoError(t, e)
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if organization != "" {
		r.Header.Set("X-JMS-ORG", organization)
	}
	response, e := (&http.Client{Timeout: 10 * time.Second}).Do(r)
	require.NoError(t, e)
	defer response.Body.Close()
	raw, e := io.ReadAll(response.Body)
	require.NoError(t, e)
	require.Equal(t, status, response.StatusCode, method+" "+path)
	return raw
}
func TestStandaloneOrganizationsIsolateResourcesRolesAndSessions(t *testing.T) {
	address := freeAddress(t)
	cfg := &config.Config{Addr: address, PublicURL: "http://" + address, DataDir: t.TempDir(), MonitorInterval: time.Hour, ShutdownTimeout: time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runNode(ctx, cfg, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			assert.NoError(t, e)
		case <-time.After(15 * time.Second):
			t.Error("organization test server did not stop")
		}
	})
	waitForHTTPStatus(t, "http://"+address+"/api/health", 200, 10*time.Second)
	var login coreauth.LoginSession
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/authentication/bootstrap", "", "", map[string]string{"username": "org.root", "password": "synthetic-org-root-password"}, 201), &login))
	token := login.AccessToken
	var user coreauth.User
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/users", token, "", map[string]string{"username": "org.operator", "password": "synthetic-org-operator-password", "role": "operator"}, 201), &user))
	var operator coreauth.LoginSession
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/authentication/auth/", "", "", map[string]string{"username": user.Username, "password": "synthetic-org-operator-password"}, 200), &operator))
	var org organizations.Organization
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/organizations", token, "", organizations.Input{Name: "Isolated operations", Enabled: true}, 201), &org))
	require.NotEqual(t, organizations.DefaultID, org.ID)
	var a, b coreassets.Asset
	asset := coreassets.Input{Name: "Default secret host", Host: "127.0.0.1", Port: 65530, Username: "ops", Password: "synthetic-organization-remote-password", HostKeyFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/assets", token, "", asset, 201), &a))
	asset.Name = "Isolated secret host"
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/assets", token, org.ID, asset, 201), &b))
	var isolatedLabel labels.Label
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/labels/labels", token, org.ID, labels.Input{Name: "Tenant", Value: "isolated", RequestID: "org-label-001"}, 201), &isolatedLabel))
	orgLabelInput := labels.BindingInput{LabelIDs: []string{isolatedLabel.ID}, RequestID: "org-label-bind-001"}
	orgHTTP(t, address, "PUT", "/api/v1/labels/bindings/asset/"+b.ID, token, org.ID, orgLabelInput, 200)
	assert.NotContains(t, string(orgHTTP(t, address, "GET", "/api/v1/labels/choices", token, "", nil, 200)), isolatedLabel.ID)
	orgStorageInput := replayarchive.Input{Config: replayarchive.Config{Provider: "sftp", Enabled: false, Prefix: "org-archive", SFTPAssetID: b.ID, SFTPDirectory: "archives"}, RequestID: "organization-storage-001"}
	var orgStorage replayarchive.Config
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/settings/replay-storage", token, org.ID, orgStorageInput, 200), &orgStorage))
	assert.NotContains(t, string(orgHTTP(t, address, "GET", "/api/v1/settings/replay-storage", token, "", nil, 200)), orgStorage.SFTPTarget)
	orgHTTP(t, address, "GET", "/api/v1/labels/bindings/asset/"+b.ID, token, "", nil, 404)
	orgHTTP(t, address, "GET", "/api/v1/labels/choices", operator.AccessToken, org.ID, nil, 403)
	orgHTTP(t, address, "POST", "/api/v1/ops/templates", token, org.ID, map[string]any{"name": "Organization-only template", "command": "printf isolated", "timeout_seconds": 5}, 201)
	assert.NotContains(t, string(orgHTTP(t, address, "GET", "/api/v1/ops/templates", token, "", nil, 200)), "Organization-only template")
	defaultInventory := string(orgHTTP(t, address, "GET", "/api/v1/assets", token, "", nil, 200))
	assert.Contains(t, defaultInventory, a.ID)
	assert.NotContains(t, defaultInventory, b.ID)
	isolated := string(orgHTTP(t, address, "GET", "/api/v1/assets", token, org.ID, nil, 200))
	assert.Contains(t, isolated, b.ID)
	assert.NotContains(t, isolated, a.ID)
	assert.NotContains(t, isolated, asset.Password)
	orgHTTP(t, address, "GET", "/api/v1/assets", operator.AccessToken, org.ID, nil, 403)
	orgHTTP(t, address, "GET", "/api/v1/assets", token, "00000000-0000-0000-0000-000000000000", nil, 400)
	orgHTTP(t, address, "GET", "/api/v1/assets", token, "11111111-1111-4111-8111-111111111111", nil, 404)
	var member organizations.Member
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/organizations/"+org.ID+"/members", token, "", organizations.MemberInput{UserID: user.ID, Role: "member"}, 200), &member))
	assert.JSONEq(t, "[]", string(orgHTTP(t, address, "GET", "/api/v1/assets", operator.AccessToken, org.ID, nil, 200)))
	orgHTTP(t, address, "POST", "/api/v1/grants", token, org.ID, map[string]any{"user_id": user.ID, "asset_id": b.ID, "account": "ops", "actions": []string{"view", "connect"}}, 201)
	inventory := string(orgHTTP(t, address, "GET", "/api/v1/assets", operator.AccessToken, org.ID, nil, 200))
	assert.Contains(t, inventory, b.ID)
	assert.NotContains(t, inventory, a.ID)
	orgHTTP(t, address, "POST", "/api/v1/sessions", operator.AccessToken, org.ID, gateway.CreateRequest{AssetID: a.ID, Cols: 80, Rows: 24}, 404)
	orgHTTP(t, address, "GET", "/api/v1/sessions/foreign/replay", token, org.ID, nil, 404)
	orgHTTP(t, address, "GET", "/api/v1/ops/jobs/foreign", token, org.ID, nil, 404)
	asset.GatewayID = &a.ID
	orgHTTP(t, address, "POST", "/api/v1/assets", token, org.ID, asset, 400)
	// Organization administration does not grant global identity/security power.
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/organizations/"+org.ID+"/members", token, "", organizations.MemberInput{UserID: user.ID, Role: "admin", Revision: member.Revision}, 200), &member))
	orgHTTP(t, address, "GET", "/api/v1/organization-rbac/roles", operator.AccessToken, org.ID, nil, 200)
	orgHTTP(t, address, "POST", "/api/v1/organization-rbac/roles", operator.AccessToken, org.ID, map[string]any{"name": "forbidden system grant", "permissions": []string{"security.manage"}}, 400)
	orgHTTP(t, address, "POST", "/api/v1/rbac/roles", operator.AccessToken, org.ID, map[string]any{"name": "system escalation", "permissions": []string{"security.manage"}}, 403)
	orgHTTP(t, address, "POST", "/api/v1/users", operator.AccessToken, org.ID, map[string]string{"username": "forged.admin", "password": "synthetic-forged-admin-password", "role": "admin"}, 403)
	orgHTTP(t, address, "PUT", "/api/v1/settings/security/mfa", operator.AccessToken, org.ID, map[string]string{"mode": "all"}, 403)
	// Cookies and permanent tokens select the same server-side organization.
	var permanent coreauth.PermanentTokenCredentials
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/users/me/tokens", operator.AccessToken, org.ID, nil, 201), &permanent))
	for _, scheme := range []string{"cookie", "permanent"} {
		request, e := http.NewRequest("GET", "http://"+address+"/api/v1/assets", nil)
		require.NoError(t, e)
		request.Header.Set("X-JMS-ORG", org.ID)
		if scheme == "cookie" {
			request.AddCookie(&http.Cookie{Name: "jms_sessionid", Value: operator.AccessToken})
		} else {
			request.Header.Set("Authorization", "Token "+permanent.Token)
		}
		response, e := (&http.Client{Timeout: 5 * time.Second}).Do(request)
		require.NoError(t, e)
		raw, e := io.ReadAll(response.Body)
		response.Body.Close()
		require.NoError(t, e)
		assert.Equal(t, 200, response.StatusCode)
		assert.Contains(t, string(raw), b.ID)
		assert.NotContains(t, string(raw), a.ID)
	}
	// Legacy default groups bound to system roles cannot be used as an escalation path.
	var systemGroup struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/user-groups", token, "", map[string]string{"name": "System role holders"}, 201), &systemGroup))
	var systemRole struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/rbac/roles", token, "", map[string]any{"name": "System security", "permissions": []string{"security.manage"}}, 201), &systemRole))
	orgHTTP(t, address, "PUT", "/api/v1/rbac/bindings", token, "", map[string]any{"subject_type": "group", "subject_id": systemGroup.ID, "role_ids": []string{systemRole.ID}}, 200)
	orgHTTP(t, address, "PUT", "/api/v1/organizations/"+organizations.DefaultID+"/members", token, "", organizations.MemberInput{UserID: user.ID, Role: "admin"}, 200)
	orgHTTP(t, address, "PUT", "/api/v1/user-groups/"+systemGroup.ID+"/members/"+user.ID, operator.AccessToken, "", nil, 403)
	orgHTTP(t, address, "POST", "/api/v1/access-policies", operator.AccessToken, org.ID, map[string]any{"name": "org cannot review platform login", "kind": "login", "action": "review", "enabled": true, "priority": 50, "timezone": "UTC"}, 400)
	// A queued schedule cannot retain a removed member's authority.
	orgHTTP(t, address, "POST", "/api/v1/ops/plans", operator.AccessToken, org.ID, map[string]any{"name": "Membership-rechecked plan", "asset_ids": []string{b.ID}, "command": "printf organization-must-not-execute", "kind": "once", "run_at": time.Now().Add(2 * time.Second).UTC(), "timeout_seconds": 5, "request_id": "organization-revoked-plan"}, 201)
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/organizations/"+org.ID+"/members", token, "", organizations.MemberInput{UserID: user.ID, Role: "none", Revision: member.Revision}, 200), &member))
	require.Eventually(t, func() bool {
		var page struct {
			Results []struct {
				State string `json:"state"`
				Items []struct {
					JobID     string `json:"job_id"`
					ErrorCode string `json:"error_code"`
				} `json:"items"`
			} `json:"results"`
		}
		if json.Unmarshal(orgHTTP(t, address, "GET", "/api/v1/ops/runs", token, org.ID, nil, 200), &page) != nil || len(page.Results) != 1 {
			return false
		}
		return page.Results[0].State != "running" && len(page.Results[0].Items) == 1 && page.Results[0].Items[0].JobID == "" && page.Results[0].Items[0].ErrorCode != ""
	}, 8*time.Second, 100*time.Millisecond)
	assert.NotContains(t, string(orgHTTP(t, address, "GET", "/api/v1/ops/jobs", token, org.ID, nil, 200)), "organization-must-not-execute")
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/organizations/"+org.ID+"/members", token, "", organizations.MemberInput{UserID: user.ID, Role: "admin", Revision: member.Revision}, 200), &member))
	t.Run("real SSH, CLI client, ticket routing and live membership revocation", func(t *testing.T) {
		remote := os.Getenv("JMS_TEST_KEY_HOST_ADDR")
		if remote == "" {
			t.Skip("set JMS_TEST_KEY_HOST_ADDR and fingerprint for real organization SSH")
		}
		host, port, e := net.SplitHostPort(remote)
		require.NoError(t, e)
		number, e := strconv.Atoi(port)
		require.NoError(t, e)
		var real coreassets.Asset
		require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/assets", token, org.ID, coreassets.Input{Name: "Real organization host", Host: host, Port: number, Username: "keyqa", Password: "synthetic-keyhost-password-233", HostKeyFingerprint: os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")}, 201), &real))
		probe := orgHTTP(t, address, "POST", "/api/v1/assets/"+real.ID+"/probe", operator.AccessToken, org.ID, nil, 200)
		assert.Contains(t, string(probe), `"state":"online"`)
		path := "organization-proof-" + org.ID + ".txt"
		fileURL := "/api/v1/assets/" + real.ID + "/files/content?path=" + path
		orgHTTP(t, address, "PUT", fileURL, operator.AccessToken, org.ID, []byte("organization-file-proof"), 201)
		assert.Equal(t, "organization-file-proof", string(orgHTTP(t, address, "GET", fileURL, operator.AccessToken, org.ID, nil, 200)))
		orgHTTP(t, address, "GET", fileURL, token, "", nil, 404)
		orgHTTP(t, address, "DELETE", fileURL, operator.AccessToken, org.ID, nil, 204)
		assert.Contains(t, string(orgHTTP(t, address, "GET", "/api/v1/file-transfers", token, org.ID, nil, 200)), real.ID)
		assert.NotContains(t, string(orgHTTP(t, address, "GET", "/api/v1/file-transfers", token, "", nil, 200)), real.ID)
		client, e := sessionclient.New("http://"+address, operator.AccessToken)
		require.NoError(t, e)
		client, e = client.WithOrganization(org.ID)
		require.NoError(t, e)
		job, e := client.SubmitJob(context.Background(), jobs.Input{AssetID: real.ID, Command: "printf organization-isolated", TimeoutSeconds: 5, RequestID: "organization-exec"})
		require.NoError(t, e)
		require.Eventually(t, func() bool {
			result, e := client.GetJob(context.Background(), job.ID)
			return e == nil && result.State == "succeeded" && result.Stdout == "organization-isolated"
		}, 10*time.Second, 50*time.Millisecond)
		orgHTTP(t, address, "GET", "/api/v1/ops/jobs/"+job.ID, token, "", nil, 404)
		var accessKey coreauth.AccessKeyCredentials
		require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/users/me/access-keys", operator.AccessToken, org.ID, nil, 201), &accessKey))
		signed, e := sessionclient.NewWithAccessKey("http://"+address, accessKey.ID, accessKey.Secret)
		require.NoError(t, e)
		signed, e = signed.WithOrganization(org.ID)
		require.NoError(t, e)
		_, e = signed.GetJob(context.Background(), job.ID)
		require.NoError(t, e)
		session, e := client.CreateSession(context.Background(), gateway.CreateRequest{AssetID: real.ID, Cols: 80, Rows: 24})
		require.NoError(t, e)
		assert.Contains(t, session.WebSocketURL, "?org="+org.ID)
		wrong := session
		wrong.WebSocketURL = "/ws/api/v1/sessions/" + session.SessionID + "/terminal?org=" + organizations.DefaultID
		_, e = client.DialTerminal(context.Background(), wrong)
		require.Error(t, e)
		socket, e := client.DialTerminal(context.Background(), session)
		require.NoError(t, e)
		defer socket.CloseNow()
		require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/organizations/"+org.ID+"/members", token, "", organizations.MemberInput{UserID: user.ID, Role: "none", Revision: member.Revision}, 200), &member))
		readCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = socket.Write(readCtx, websocket.MessageBinary, []byte("printf revoked\r"))
		for {
			_, _, e = socket.Read(readCtx)
			if e != nil {
				break
			}
		}
		require.NotErrorIs(t, e, context.DeadlineExceeded)
		orgHTTP(t, address, "GET", "/api/v1/assets", operator.AccessToken, org.ID, nil, 403)
		_, e = signed.GetJob(context.Background(), job.ID)
		require.Error(t, e)
	})
	// Disable/restore keeps encrypted resources while preventing access.
	var organizationCA sshcertificates.Issuer
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "POST", "/api/v1/settings/ssh-certificates/issuers", token, org.ID, sshcertificates.Input{Name: "Organization CA", Provider: "builtin", Enabled: true, RequestID: "organization-ca-001"}, 201), &organizationCA))
	orgCertInput := sshcertificates.BindingInput{IssuerID: organizationCA.ID, RequestID: "organization-bind-ca-001"}
	orgHTTP(t, address, "PUT", "/api/v1/settings/ssh-certificates/bindings/"+b.ID, token, org.ID, orgCertInput, 200)
	assert.NotContains(t, string(orgHTTP(t, address, "GET", "/api/v1/settings/ssh-certificates/issuers", token, "", nil, 200)), organizationCA.ID)
	in := org.Input
	in.Enabled = false
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/organizations/"+org.ID, token, "", in, 200), &org))
	orgHTTP(t, address, "GET", "/api/v1/assets", token, org.ID, nil, 404)
	in = org.Input
	in.Enabled = true
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/organizations/"+org.ID, token, "", in, 200), &org))
	assert.Contains(t, string(orgHTTP(t, address, "GET", "/api/v1/assets", token, org.ID, nil, 200)), b.ID)
	assert.Contains(t, string(orgHTTP(t, address, "GET", "/api/v1/labels/choices", token, org.ID, nil, 200)), isolatedLabel.ID)
	var preservedBinding labels.Binding
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/labels/bindings/asset/"+b.ID, token, org.ID, orgLabelInput, 200), &preservedBinding))
	assert.Equal(t, 1, preservedBinding.Revision)
	var restoredStorage replayarchive.Config
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/settings/replay-storage", token, org.ID, orgStorageInput, 200), &restoredStorage))
	assert.Equal(t, orgStorage, restoredStorage)
	assert.Contains(t, string(orgHTTP(t, address, "GET", "/api/v1/settings/ssh-certificates/issuers", token, org.ID, nil, 200)), organizationCA.ID)
	var restoredCertificatePolicy sshcertificates.Binding
	require.NoError(t, json.Unmarshal(orgHTTP(t, address, "PUT", "/api/v1/settings/ssh-certificates/bindings/"+b.ID, token, org.ID, orgCertInput, 200), &restoredCertificatePolicy))
	assert.Equal(t, 1, restoredCertificatePolicy.Revision)
	orgHTTP(t, address, "DELETE", "/api/v1/organizations/"+org.ID+"?revision="+strconv.Itoa(org.Revision), token, "", nil, 204)
	orgHTTP(t, address, "GET", "/api/v1/assets", token, org.ID, nil, 404)
	orgHTTP(t, address, "POST", "/api/v1/organizations/"+org.ID+"/restore?revision="+strconv.Itoa(org.Revision+1), token, "", nil, 204)
	orgHTTP(t, address, "PUT", "/api/v1/settings/security/mfa", token, "", map[string]string{"mode": "admins"}, 200)
	setup := orgHTTP(t, address, "POST", "/api/v1/authentication/auth/", "", "", map[string]string{"username": user.Username, "password": "synthetic-org-operator-password"}, 401)
	assert.Contains(t, string(setup), `"mfa_setup_required":true`)
	assert.NotContains(t, string(setup), "access_token")

}
