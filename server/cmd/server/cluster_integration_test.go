package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/config"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/neko233-com/jumpserver233/server/testsupport/passkeyauth"
	"github.com/neko233-com/jumpserver233/server/testsupport/samlprovider"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"github.com/stretchr/testify/require"
)

func TestActiveStandbyFailoverKeepsSharedAuthSession(t *testing.T) {
	databaseURL := os.Getenv("JMS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set JMS_TEST_DATABASE_URL to run the active/standby PostgreSQL integration test")
	}
	clusterID := fmt.Sprintf("ha-test-%d", time.Now().UTC().UnixNano())
	dataDir := t.TempDir()
	documents, err := storage.OpenPostgres(context.Background(), databaseURL, clusterID)
	if err != nil {
		t.Fatal(err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	done2 := make(chan error, 1)
	finished1 := false
	finished2 := false
	var keyFixtureCleanup func()
	var organizationIDs []string
	cleanupDocuments := func() {
		for _, id := range append(organizationIDs, organizations.DefaultID) {
			scoped, e := documents.Scoped(id)
			if e == nil {
				for _, key := range []string{"assets", "asset-nodes", "grants", "user-groups", "access-reviews", "command-filters", "rbac", "access-policies", "operations", "ssh-jobs", "database-queries"} {
					_ = scoped.Delete(key)
				}
			}
		}
		for _, key := range []string{"database-queries", "shared-keys", "shared-passwords", "assets", "grants", "users", "auth-sessions", "operations", "rbac", "oidc-config", "ldap-config", "cas-config", "saml-config", "passkeys", "access-policies", "platform-login-reviews", "organizations"} {
			if err := documents.Delete(key); err != nil {
				t.Logf("clean shared document %s: %v", key, err)
			}
		}
		if err := documents.Close(); err != nil {
			t.Logf("close test shared documents: %v", err)
		}
	}
	t.Cleanup(func() {
		cancel1()
		cancel2()
		if !finished1 {
			select {
			case <-done1:
			case <-time.After(10 * time.Second):
				t.Error("first test node did not stop")
			}
		}
		if !finished2 {
			select {
			case <-done2:
			case <-time.After(10 * time.Second):
				t.Error("second test node did not stop")
			}
		}
		if keyFixtureCleanup != nil {
			keyFixtureCleanup()
		}
		cleanupDocuments()
	})

	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	first := integrationNodeConfig(t, clusterID, dataDir, key, freeAddress(t), freeAddress(t))
	second := integrationNodeConfig(t, clusterID, dataDir, key, freeAddress(t), freeAddress(t))
	first.PublicURL = "https://ha-console.example.invalid"
	second.PublicURL = first.PublicURL
	go func() { done1 <- runActiveStandby(ctx1, first) }()
	waitForHTTPStatus(t, "http://"+first.ClusterHealthAddr+"/readyz", http.StatusOK, 20*time.Second)
	go func() { done2 <- runActiveStandby(ctx2, second) }()
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/livez", http.StatusOK, 10*time.Second)
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/readyz", http.StatusServiceUnavailable, 10*time.Second)

	requestBody, err := json.Marshal(map[string]string{
		"username": "admin.user",
		"password": "integration-password-long-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	bootstrapRequest, err := http.NewRequest(http.MethodPost, "http://"+first.Addr+"/api/v1/authentication/bootstrap", bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapRequest.Header.Set("Content-Type", "application/json")
	bootstrapRequest.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	response, err := http.DefaultClient.Do(bootstrapRequest)
	if err != nil {
		t.Fatalf("bootstrap administrator on active node: %v", err)
	}
	if response.StatusCode != http.StatusCreated {
		response.Body.Close()
		t.Fatalf("bootstrap status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	var login auth.LoginSession
	if err := json.NewDecoder(response.Body).Decode(&login); err != nil {
		response.Body.Close()
		t.Fatalf("decode bootstrap session: %v", err)
	}
	response.Body.Close()
	if login.AccessToken == "" {
		t.Fatal("bootstrap did not return a login session")
	}
	apiJSON := func(address, method, path string, body any, status int) []byte {
		t.Helper()
		payload, err := json.Marshal(body)
		require.NoError(t, err)
		request, err := http.NewRequest(method, "http://"+address+path, bytes.NewReader(payload))
		require.NoError(t, err)
		request.Header.Set("Authorization", "Bearer "+login.AccessToken)
		request.Header.Set("Content-Type", "application/json")
		result, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		defer result.Body.Close()
		require.Equal(t, status, result.StatusCode)
		var value json.RawMessage
		require.NoError(t, json.NewDecoder(result.Body).Decode(&value))
		return value
	}
	apiJSON(first.Addr, "POST", "/api/v1/ops/templates", map[string]any{"name": "HA template", "command": "whoami", "timeout_seconds": 30}, http.StatusCreated)
	assetData := apiJSON(first.Addr, "POST", "/api/v1/assets", map[string]any{"name": "HA schedule host", "host": "127.0.0.1", "port": 22, "username": "ops", "password": "synthetic-ha-test-only", "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, http.StatusCreated)
	var asset struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(assetData, &asset))
	var routedAsset struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(apiJSON(first.Addr, "POST", "/api/v1/assets", map[string]any{"name": "HA gateway target", "host": "private.synthetic.invalid", "port": 22, "username": "ops", "password": "synthetic-ha-target", "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gateway_id": asset.ID}, 201), &routedAsset))
	apiJSON(first.Addr, "POST", "/api/v1/assets", map[string]any{"name": "HA key asset", "host": "private.synthetic.invalid", "port": 22, "username": "qa-key", "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "credential_type": "ssh_key", "private_key": string(sshidentity.PEM(sshidentity.Passphrase)), "private_key_passphrase": sshidentity.Passphrase}, 201)
	apiJSON(first.Addr, "POST", "/api/v1/ops/plans", map[string]any{"name": "HA future plan", "asset_ids": []string{asset.ID}, "command": "whoami", "kind": "once", "run_at": time.Now().Add(time.Hour).UTC(), "request_id": "ha-future-plan"}, http.StatusCreated)
	apiJSON(first.Addr, "POST", "/api/v1/rbac/roles", map[string]any{"name": "HA role", "permissions": []string{"jobs.view_all"}}, http.StatusCreated)
	apiJSON(first.Addr, "POST", "/api/v1/access-policies", map[string]any{"name": "HA upload restriction", "kind": "method", "methods": []string{"upload"}, "action": "deny", "enabled": true, "priority": 50, "timezone": "UTC", "sources": []string{"127.0.0.0/8"}}, http.StatusCreated)
	apiJSON(first.Addr, "PUT", "/api/v1/settings/security/oidc", map[string]any{"enabled": false, "client_secret": "synthetic-ha-oidc-secret", "token_auth_method": "client_secret_basic", "revision": 0}, http.StatusOK)
	apiJSON(first.Addr, "PUT", "/api/v1/settings/security/ldap", map[string]any{"enabled": false, "bind_password": "synthetic-ha-directory-secret", "revision": 0}, http.StatusOK)
	apiJSON(first.Addr, "PUT", "/api/v1/settings/security/cas", map[string]any{"enabled": false, "protocol": "3", "revision": 0}, http.StatusOK)
	provider, err := samlprovider.New("https://synthetic-idp.example.invalid")
	require.NoError(t, err)
	samlSettings := apiJSON(first.Addr, "PUT", "/api/v1/settings/security/saml", map[string]any{"enabled": true, "entity_id": first.PublicURL + "/sp", "acs_url": first.PublicURL + "/api/v1/authentication/saml/acs", "metadata_xml": provider.Metadata(), "allow_loopback_http": true, "revision": 0}, http.StatusOK)
	var beforeSAML struct {
		Fingerprint string `json:"sp_fingerprint"`
	}
	require.NoError(t, json.Unmarshal(samlSettings, &beforeSAML))
	require.NotEmpty(t, beforeSAML.Fingerprint)
	apiJSON(first.Addr, "PUT", "/api/v1/settings/security/passkeys", map[string]any{"enabled": true, "revision": 0}, http.StatusOK)
	// Requests model the HTTP backplane behind the configured HTTPS load balancer;
	// the synthetic client forwards Secure cookies explicitly on that backplane.
	ceremony := func(method, path string, body any, authorization string, cookie *http.Cookie, status int) (json.RawMessage, []*http.Cookie) {
		t.Helper()
		payload, e := json.Marshal(body)
		require.NoError(t, e)
		req, e := http.NewRequest(method, "http://"+first.Addr+path, bytes.NewReader(payload))
		require.NoError(t, e)
		req.Header.Set("Content-Type", "application/json")
		if authorization != "" {
			req.Header.Set("Authorization", "Bearer "+authorization)
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, e := http.DefaultClient.Do(req)
		require.NoError(t, e)
		defer res.Body.Close()
		raw, e := io.ReadAll(res.Body)
		require.NoError(t, e)
		require.Equal(t, status, res.StatusCode, string(raw))
		return json.RawMessage(raw), res.Cookies()
	}
	findCookie := func(cookies []*http.Cookie, name string) *http.Cookie {
		t.Helper()
		for _, c := range cookies {
			if c.Name == name && c.MaxAge >= 0 {
				return c
			}
		}
		t.Fatalf("missing synthetic cookie %s", name)
		return nil
	}
	authenticator, err := passkeyauth.New(first.PublicURL, "ha-console.example.invalid")
	require.NoError(t, err)
	registration, registrationCookies := ceremony("POST", "/api/v1/users/me/passkeys/registration/start", map[string]string{"name": "HA Passkey", "password": "integration-password-long-123"}, login.AccessToken, nil, 200)
	attestation, err := authenticator.Registration(registration, passkeyauth.Overrides{})
	require.NoError(t, err)
	ceremony("POST", "/api/v1/users/me/passkeys/registration/finish", map[string]any{"credential": attestation}, login.AccessToken, findCookie(registrationCookies, "jms_passkey_register"), 201)
	assertionOptions, assertionCookies := ceremony("POST", "/api/v1/authentication/passkey/start", nil, "", nil, 200)
	assertion, err := authenticator.Assertion(assertionOptions, passkeyauth.Overrides{})
	require.NoError(t, err)
	_, pendingCookies := ceremony("POST", "/api/v1/authentication/passkey/verify", map[string]any{"credential": assertion}, "", findCookie(assertionCookies, "jms_passkey_flow"), 200)
	_, passkeySessionCookies := ceremony("POST", "/api/v1/authentication/passkey/complete", map[string]string{}, "", findCookie(pendingCookies, "jms_passkey_pending"), 200)
	passkeySessionCookie := findCookie(passkeySessionCookies, "jms_sessionid")

	var reviewUser struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(apiJSON(first.Addr, "POST", "/api/v1/users", map[string]any{"username": "ha.review", "password": "synthetic-ha-review-password", "role": "operator"}, 201), &reviewUser))
	apiJSON(first.Addr, "POST", "/api/v1/access-policies", map[string]any{"name": "HA platform review", "kind": "login", "user_id": reviewUser.ID, "action": "review", "enabled": true, "priority": 50, "timezone": "UTC"}, 201)
	var pendingReview struct {
		ID     string `json:"review_id"`
		Ticket string `json:"review_token"`
	}
	require.NoError(t, json.Unmarshal(apiJSON(first.Addr, "POST", "/api/v1/authentication/auth/", map[string]string{"username": "ha.review", "password": "synthetic-ha-review-password"}, 202), &pendingReview))
	require.NotEmpty(t, pendingReview.Ticket)

	var haOrg organizations.Organization
	require.NoError(t, json.Unmarshal(apiJSON(first.Addr, "POST", "/api/v1/organizations", organizations.Input{Name: "HA scoped operations", Enabled: true}, 201), &haOrg))
	organizationIDs = append(organizationIDs, haOrg.ID)
	var scopedAsset struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/assets", login.AccessToken, haOrg.ID, map[string]any{"name": "HA isolated inventory", "host": "127.0.0.1", "port": 65530, "username": "ops", "password": "synthetic-ha-org-remote-password", "host_key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, 201), &scopedAsset))
	orgHTTP(t, first.Addr, "POST", "/api/v1/ops/plans", login.AccessToken, haOrg.ID, map[string]any{"name": "HA organization plan", "asset_ids": []string{scopedAsset.ID}, "command": "printf organization-ha", "kind": "once", "run_at": time.Now().Add(time.Hour).UTC(), "request_id": "ha-org-plan"}, 201)
	orgHTTP(t, first.Addr, "POST", "/api/v1/organization-rbac/roles", login.AccessToken, haOrg.ID, map[string]any{"name": "HA organization auditor", "permissions": []string{"audit.sessions.view_all"}}, 201)
	orgHTTP(t, first.Addr, "PUT", "/api/v1/organizations/"+haOrg.ID+"/members", login.AccessToken, "", organizations.MemberInput{UserID: reviewUser.ID, Role: "auditor"}, 200)
	var sharedDefault, sharedScoped coreassets.Asset
	var sharedBackup coreassets.CredentialBackup
	if address := os.Getenv("JMS_TEST_KEY_HOST_ADDR"); address != "" {
		host, portText, e := net.SplitHostPort(address)
		require.NoError(t, e)
		var port int
		_, e = fmt.Sscan(portText, &port)
		require.NoError(t, e)
		input := coreassets.Input{Name: "HA coordinated password", Host: host, Port: port, Username: "rotationha", Password: "synthetic-keyhost-password-233", HostKeyFingerprint: os.Getenv("JMS_TEST_KEY_HOST_FINGERPRINT")}
		require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/assets", login.AccessToken, "", input, 201), &sharedDefault))
		require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/assets", login.AccessToken, haOrg.ID, input, 201), &sharedScoped))
		require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "POST", "/api/v1/assets/"+sharedDefault.ID+"/credential-backups", login.AccessToken, "", nil, 201), &sharedBackup))
		orgHTTP(t, first.Addr, "POST", "/api/v1/assets/"+sharedDefault.ID+"/password-rotation", login.AccessToken, "", nil, 200)
	}
	addKeyCleanup := func(cleanup func()) {
		previous := keyFixtureCleanup
		keyFixtureCleanup = func() {
			if previous != nil {
				previous()
			}
			cleanup()
		}
	}
	haDatabase := prepareDatabaseFailover(t, first.Addr, login.AccessToken, haOrg.ID)
	haMySQL := prepareDatabaseFailoverEngine(t, first.Addr, login.AccessToken, haOrg.ID, "mysql")
	haMaria := prepareDatabaseFailoverEngine(t, first.Addr, login.AccessToken, haOrg.ID, "mariadb")
	haSQLServer := prepareDatabaseFailoverEngine(t, first.Addr, login.AccessToken, haOrg.ID, "sqlserver")
	haClickHouse := prepareDatabaseFailoverEngine(t, first.Addr, login.AccessToken, haOrg.ID, "clickhouse")
	haRedis := prepareDatabaseFailoverEngine(t, first.Addr, login.AccessToken, haOrg.ID, "redis")
	haMongoDB := prepareDatabaseFailoverEngine(t, first.Addr, login.AccessToken, haOrg.ID, "mongodb")
	haKubernetes := prepareKubeFailover(t, first.Addr, login.AccessToken, haOrg.ID)
	haTelnet := prepareTelnetFailover(t, first.Addr, login.AccessToken, haOrg.ID)
	haRDP := prepareRDPFailover(t, first.Addr, login.AccessToken, haOrg.ID)
	verifyKubeActiveBeforeFailover(t, haKubernetes)
	verifyTelnetActiveBeforeFailover(t, haTelnet)
	verifyRDPActiveBeforeFailover(t, haRDP)
	var overviewBefore organizations.Overview
	require.NoError(t, json.Unmarshal(orgHTTP(t, first.Addr, "GET", "/api/v1/organizations/overview", login.AccessToken, "", nil, 200), &overviewBefore))
	require.False(t, overviewBefore.Partial)
	require.Equal(t, 2, overviewBefore.CollectedOrganizations)
	// These fixtures deliberately seed durable state outside the running primary.
	// Keep them immediately before shutdown and account for their known additions;
	// the primary's in-memory HTTP snapshot cannot observe a second store's writes.
	haKey := prepareKeyFailover(t, documents, dataDir, []byte("0123456789abcdef0123456789abcdef"), addKeyCleanup)
	haSharedKey, haSharedPeer := prepareSharedKeyFailover(t, documents, dataDir, []byte("0123456789abcdef0123456789abcdef"), haOrg.ID, addKeyCleanup)
	injectedSSHAssets := 0
	for _, proof := range []*keyFailoverProof{haKey, haSharedKey} {
		if proof != nil {
			injectedSSHAssets++
		}
	}
	if haSharedPeer != "" {
		injectedSSHAssets++
	}
	expectedProtocols := maps.Clone(overviewBefore.Totals.Protocols)
	if injectedSSHAssets > 0 {
		expectedProtocols["ssh"] += injectedSSHAssets
	}
	cancel1()
	select {
	case err := <-done1:
		finished1 = true
		if err != nil {
			t.Fatalf("stop first node: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first node did not release its leader lock")
	}
	waitForHTTPStatus(t, "http://"+second.ClusterHealthAddr+"/readyz", http.StatusOK, 20*time.Second)
	var overviewAfter organizations.Overview
	require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "GET", "/api/v1/organizations/overview", login.AccessToken, "", nil, 200), &overviewAfter))
	require.False(t, overviewAfter.Partial)
	require.Equal(t, overviewBefore.Totals.Assets+injectedSSHAssets, overviewAfter.Totals.Assets)
	require.Equal(t, overviewBefore.Totals.SSHAssets+injectedSSHAssets, overviewAfter.Totals.SSHAssets)
	require.Equal(t, expectedProtocols, overviewAfter.Totals.Protocols)
	require.Equal(t, overviewBefore.Memberships, overviewAfter.Memberships)
	require.Equal(t, overviewBefore.CollectedOrganizations, overviewAfter.CollectedOrganizations)
	verifyDatabaseFailover(t, second.Addr, login.AccessToken, haOrg.ID, haDatabase)
	verifyDatabaseFailover(t, second.Addr, login.AccessToken, haOrg.ID, haMySQL)
	verifyDatabaseFailover(t, second.Addr, login.AccessToken, haOrg.ID, haMaria)
	verifyDatabaseFailover(t, second.Addr, login.AccessToken, haOrg.ID, haSQLServer)
	verifyDatabaseFailover(t, second.Addr, login.AccessToken, haOrg.ID, haClickHouse)
	verifyDatabaseFailover(t, second.Addr, login.AccessToken, haOrg.ID, haRedis)
	verifyDatabaseFailover(t, second.Addr, login.AccessToken, haOrg.ID, haMongoDB)
	verifyKubeFailover(t, second.Addr, login.AccessToken, haOrg.ID, haKubernetes)
	verifyTelnetFailover(t, second.Addr, login.AccessToken, haOrg.ID, haTelnet)
	verifyRDPFailover(t, second.Addr, login.AccessToken, haOrg.ID, haRDP)

	request, err := http.NewRequest(http.MethodGet, "http://"+second.Addr+"/api/v1/users/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+login.AccessToken)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("validate login session after failover: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("post-failover session status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	response.Body.Close()
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/assets", nil, 200)), `"gateway_id":"`+asset.ID+`"`)
	require.Contains(t, string(apiJSON(second.Addr, "DELETE", "/api/v1/assets/"+asset.ID, nil, 409)), "ssh_gateway_in_use")
	keyInventory := string(apiJSON(second.Addr, "GET", "/api/v1/assets", nil, 200))
	require.Contains(t, keyInventory, "HA key asset")
	require.Contains(t, keyInventory, `"credential_type":"ssh_key"`)
	require.NotContains(t, keyInventory, "PRIVATE KEY")
	require.NotContains(t, keyInventory, sshidentity.Passphrase)
	if haKey != nil {
		require.Eventually(t, func() bool {
			var items []coreassets.ListItem
			require.NoError(t, json.Unmarshal(apiJSON(second.Addr, "GET", "/api/v1/assets", nil, 200), &items))
			for _, item := range items {
				if item.ID == haKey.ID {
					return item.KeyFingerprint == haKey.Fingerprint && item.SSHKeyRotation != nil && !item.SSHKeyRotation.Pending
				}
			}
			return false
		}, 15*time.Second, 100*time.Millisecond)
		require.NoError(t, sshclient.VerifyPassword(context.Background(), haKey.Target, haKey.New, time.Second))
		require.Error(t, sshclient.VerifyPassword(context.Background(), haKey.Target, haKey.Old, time.Second))
		var job struct {
			ID string `json:"id"`
		}
		require.NoError(t, json.Unmarshal(apiJSON(second.Addr, "POST", "/api/v1/ops/jobs", map[string]any{"asset_id": haKey.ID, "command": "printf ha-key-restored", "timeout_seconds": 5, "request_id": "ha-key-recovery-exec"}, 201), &job))
		require.Eventually(t, func() bool {
			var result struct {
				State  string `json:"state"`
				Stdout string `json:"stdout"`
			}
			require.NoError(t, json.Unmarshal(apiJSON(second.Addr, "GET", "/api/v1/ops/jobs/"+job.ID, nil, 200), &result))
			return result.State == "succeeded" && result.Stdout == "ha-key-restored"
		}, 10*time.Second, 100*time.Millisecond)
	}
	if haSharedKey != nil {
		for _, p := range []struct{ id, org string }{{haSharedKey.ID, ""}, {haSharedPeer, haOrg.ID}} {
			require.Eventually(t, func() bool {
				var inventory []coreassets.ListItem
				require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "GET", "/api/v1/assets", login.AccessToken, p.org, nil, 200), &inventory))
				for _, a := range inventory {
					if a.ID == p.id {
						return a.KeyFingerprint == haSharedKey.Fingerprint && a.SSHKeyRotation != nil && a.SSHKeyRotation.Shared && !a.SSHKeyRotation.Pending
					}
				}
				return false
			}, 20*time.Second, 100*time.Millisecond)
			var job struct {
				ID string `json:"id"`
			}
			require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "POST", "/api/v1/ops/jobs", login.AccessToken, p.org, map[string]any{"asset_id": p.id, "command": "printf shared-key-ha", "timeout_seconds": 5, "request_id": "shared-ha-" + p.id}, 201), &job))
			require.Eventually(t, func() bool {
				var result struct {
					State  string `json:"state"`
					Stdout string `json:"stdout"`
				}
				require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "GET", "/api/v1/ops/jobs/"+job.ID, login.AccessToken, p.org, nil, 200), &result))
				return result.State == "succeeded" && result.Stdout == "shared-key-ha"
			}, 10*time.Second, 100*time.Millisecond)
		}
		require.Error(t, sshclient.VerifyPassword(context.Background(), haSharedKey.Target, haSharedKey.Old, time.Second))
		require.NoError(t, sshclient.VerifyPassword(context.Background(), haSharedKey.Target, haSharedKey.New, time.Second))
	}
	resolveRequest, err := http.NewRequest("POST", "http://"+second.Addr+"/api/v1/login-reviews/"+pendingReview.ID+"/approve", nil)
	require.NoError(t, err)
	resolveRequest.Header.Set("Authorization", "Bearer "+login.AccessToken)
	resolveResponse, err := http.DefaultClient.Do(resolveRequest)
	require.NoError(t, err)
	resolveResponse.Body.Close()
	require.Equal(t, 204, resolveResponse.StatusCode)
	var reviewedLogin auth.LoginSession
	require.NoError(t, json.Unmarshal(apiJSON(second.Addr, "POST", "/api/v1/authentication/login-review/complete", map[string]string{"review_token": pendingReview.Ticket}, 200), &reviewedLogin))
	require.Equal(t, reviewUser.ID, reviewedLogin.User.ID)
	require.NotEmpty(t, reviewedLogin.AccessToken)
	identityRequest, err := http.NewRequest("GET", "http://"+second.Addr+"/api/v1/users/me", nil)
	require.NoError(t, err)
	identityRequest.Header.Set("Authorization", "Bearer "+reviewedLogin.AccessToken)
	identityResponse, err := http.DefaultClient.Do(identityRequest)
	require.NoError(t, err)
	identityResponse.Body.Close()
	require.Equal(t, 200, identityResponse.StatusCode)
	apiJSON(second.Addr, "POST", "/api/v1/authentication/login-review/complete", map[string]string{"review_token": pendingReview.Ticket}, 409)
	scopedInventory := string(orgHTTP(t, second.Addr, "GET", "/api/v1/assets", login.AccessToken, haOrg.ID, nil, 200))
	require.Contains(t, scopedInventory, scopedAsset.ID)
	require.NotContains(t, scopedInventory, asset.ID)
	require.NotContains(t, string(apiJSON(second.Addr, "GET", "/api/v1/assets", nil, 200)), scopedAsset.ID)
	require.Contains(t, string(orgHTTP(t, second.Addr, "GET", "/api/v1/ops/plans", login.AccessToken, haOrg.ID, nil, 200)), "HA organization plan")
	require.Contains(t, string(orgHTTP(t, second.Addr, "GET", "/api/v1/organization-rbac/roles", login.AccessToken, haOrg.ID, nil, 200)), "HA organization auditor")
	require.Contains(t, string(orgHTTP(t, second.Addr, "GET", "/api/v1/assets", reviewedLogin.AccessToken, haOrg.ID, nil, 200)), scopedAsset.ID)
	if sharedDefault.ID != "" {
		for _, p := range []struct{ id, org string }{{sharedDefault.ID, ""}, {sharedScoped.ID, haOrg.ID}} {
			var item coreassets.ListItem
			require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "POST", "/api/v1/assets/"+p.id+"/probe", login.AccessToken, p.org, nil, 200), &item))
			require.Equal(t, uint64(2), item.CredentialRevision)
			require.Equal(t, "online", item.Monitor.State)
			var inventory []coreassets.ListItem
			require.NoError(t, json.Unmarshal(orgHTTP(t, second.Addr, "GET", "/api/v1/assets", login.AccessToken, p.org, nil, 200), &inventory))
			found := false
			for _, current := range inventory {
				if current.ID == p.id {
					found = true
					require.NotNil(t, current.PasswordRotation)
					require.True(t, current.PasswordRotation.Shared)
				}
			}
			require.True(t, found)
		}
		orgHTTP(t, second.Addr, "POST", "/api/v1/assets/"+sharedDefault.ID+"/credential-backups/"+sharedBackup.ID+"/restore", login.AccessToken, "", nil, 200)
	}
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/ops/templates", nil, http.StatusOK)), "HA template")
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/ops/plans", nil, http.StatusOK)), "HA future plan")
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/rbac/roles", nil, http.StatusOK)), "HA role")
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/access-policies", nil, 200)), "HA upload restriction")
	require.Contains(t, string(apiJSON(second.Addr, "PUT", "/api/v1/assets/"+asset.ID+"/files/content?path=x", nil, 403)), "access_policy_denied")
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/ops/plans", nil, 200)), `"source_ip":"127.0.0.1"`)
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/settings/security/oidc", nil, http.StatusOK)), `"has_client_secret":true`)
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/settings/security/ldap", nil, http.StatusOK)), `"has_bind_password":true`)
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/settings/security/cas", nil, http.StatusOK)), `"revision":1`)
	var afterSAML struct {
		Fingerprint string `json:"sp_fingerprint"`
	}
	require.NoError(t, json.Unmarshal(apiJSON(second.Addr, "GET", "/api/v1/settings/security/saml", nil, http.StatusOK), &afterSAML))
	require.Equal(t, beforeSAML.Fingerprint, afterSAML.Fingerprint)
	restoredPasskeyRequest, err := http.NewRequest("GET", "http://"+second.Addr+"/api/v1/users/me", nil)
	require.NoError(t, err)
	restoredPasskeyRequest.AddCookie(passkeySessionCookie)
	restoredPasskeyResponse, err := http.DefaultClient.Do(restoredPasskeyRequest)
	require.NoError(t, err)
	defer restoredPasskeyResponse.Body.Close()
	require.Equal(t, 200, restoredPasskeyResponse.StatusCode)
	require.Contains(t, string(apiJSON(second.Addr, "GET", "/api/v1/users/me/passkeys", nil, 200)), "HA Passkey")

	cancel2()
	select {
	case err := <-done2:
		finished2 = true
		if err != nil {
			t.Fatalf("stop second node: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second node did not stop")
	}
}

func integrationNodeConfig(t *testing.T, clusterID, dataDir, key, apiAddr, healthAddr string) *config.Config {
	t.Helper()
	return &config.Config{
		Addr:              apiAddr,
		Version:           "integration",
		ShutdownTimeout:   10 * time.Second,
		DataDir:           filepath.Clean(dataDir),
		VaultKey:          key,
		AdminToken:        "0123456789abcdef0123456789abcdef",
		MonitorInterval:   time.Hour,
		ClusterMode:       true,
		DatabaseURL:       os.Getenv("JMS_TEST_DATABASE_URL"),
		ClusterID:         clusterID,
		ClusterHealthAddr: healthAddr,
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func waitForHTTPStatus(t *testing.T, url string, expectedStatus int, timeout time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	lastStatus := 0
	for time.Now().Before(deadline) {
		response, err := client.Get(url)
		if err == nil {
			lastStatus = response.StatusCode
			response.Body.Close()
			if lastStatus == expectedStatus {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to return HTTP %d (last status %d)", url, expectedStatus, lastStatus)
}
