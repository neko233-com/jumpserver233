package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	coreaccessreviews "github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	corefiles "github.com/neko233-com/jumpserver233/server/internal/core/files"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
)

func TestSFTPFileAPIRequiresSFTPGrant(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	admin, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := identities.CreateUser("operator.one", "an-operator-password-1234", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	operatorSession, err := identities.Authenticate(operator.Username, "an-operator-password-1234")
	if err != nil {
		t.Fatal(err)
	}
	assets := testAssetService(t)
	asset, err := assets.Create(coreassets.Input{Name: "files-host", Host: "192.0.2.25", Username: "deploy", Password: "test-only", Port: 22, HostKeyFingerprint: validTestFingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := coregrants.OpenStore(filepath.Join(t.TempDir(), "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	openCalls := 0
	fileService := corefiles.NewService(func(_ context.Context, _ string) (corefiles.Remote, error) {
		openCalls++
		return nil, errors.New("test connector unavailable")
	}, nil)
	router := NewRouter("test", Dependencies{Assets: assets, Auth: identities, Grants: grants, Files: fileService})
	endpoint := "/api/v1/assets/" + asset.ID + "/files"

	denied := doJSONRequest(t, router, http.MethodGet, endpoint, "", operatorSession.AccessToken, "127.0.0.1:43210")
	if denied.Code != http.StatusForbidden || openCalls != 0 {
		t.Fatalf("file listing without SFTP grant = status %d, connector calls %d", denied.Code, openCalls)
	}

	grantPayload, err := json.Marshal(coregrants.Input{UserID: operator.ID, AssetID: asset.ID, Account: "deploy", Actions: []string{"sftp"}})
	if err != nil {
		t.Fatal(err)
	}
	created := doJSONRequest(t, router, http.MethodPost, "/api/v1/grants", string(grantPayload), admin.AccessToken, "127.0.0.1:43210")
	if created.Code != http.StatusCreated {
		t.Fatalf("create SFTP grant = %d %s", created.Code, created.Body.String())
	}

	allowed := doJSONRequest(t, router, http.MethodGet, endpoint, "", operatorSession.AccessToken, "127.0.0.1:43210")
	if allowed.Code != http.StatusBadGateway || openCalls != 1 {
		t.Fatalf("file listing with SFTP grant = status %d, connector calls %d, body %s", allowed.Code, openCalls, allowed.Body.String())
	}
	visible := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets", "", operatorSession.AccessToken, "127.0.0.1:43210")
	if visible.Code != http.StatusOK || !strings.Contains(visible.Body.String(), `"sftp"`) {
		t.Fatalf("SFTP grant did not expose file permission in inventory: %d %s", visible.Code, visible.Body.String())
	}
}

func TestSFTPLoginReviewIssuesBoundShortLivedSession(t *testing.T) {
	dataDir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dataDir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	admin, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := identities.CreateUser("operator.one", "an-operator-password-1234", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	operatorSession, err := identities.Authenticate(operator.Username, "an-operator-password-1234")
	if err != nil {
		t.Fatal(err)
	}
	requireReview := true
	assets := testAssetService(t)
	asset, err := assets.Create(coreassets.Input{
		Name: "reviewed-files-host", Host: "192.0.2.25", Username: "deploy", Password: "test-only",
		Port: 22, HostKeyFingerprint: validTestFingerprint(), LoginReviewRequired: &requireReview,
	})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := coregrants.OpenStore(filepath.Join(dataDir, "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grants.Create(coregrants.Input{UserID: operator.ID, AssetID: asset.ID, Account: "deploy", Actions: []string{"sftp"}}, admin.User.Username); err != nil {
		t.Fatal(err)
	}
	reviews, err := coreaccessreviews.OpenStore(filepath.Join(dataDir, "access-reviews.json"))
	if err != nil {
		t.Fatal(err)
	}
	sftpSessions := corefiles.NewAccessSessionStore()
	openCalls := 0
	fileService := corefiles.NewService(func(_ context.Context, _ string) (corefiles.Remote, error) {
		openCalls++
		return nil, errors.New("test connector unavailable")
	}, nil)
	router := NewRouter("test", Dependencies{
		Assets: assets, AccessReviews: reviews, Auth: identities, Grants: grants,
		Sessions: nil, Files: fileService, SFTPSessions: sftpSessions,
	})
	base := "/api/v1/assets/" + asset.ID + "/files"
	denied := doSFTPRequest(t, router, http.MethodGet, base, operatorSession.AccessToken, "")
	if denied.Code != http.StatusPreconditionRequired || openCalls != 0 {
		t.Fatalf("SFTP without approved session = status %d, connector calls %d", denied.Code, openCalls)
	}

	start := doSFTPRequest(t, router, http.MethodPost, base+"/session", operatorSession.AccessToken, "")
	if start.Code != http.StatusAccepted || openCalls != 0 {
		t.Fatalf("start SFTP review = status %d, connector calls %d, body %s", start.Code, openCalls, start.Body.String())
	}
	var pending struct {
		ReviewID string `json:"review_id"`
		Action   string `json:"action"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if pending.ReviewID == "" || pending.Action != coreaccessreviews.ActionSFTP {
		t.Fatalf("pending SFTP review = %#v", pending)
	}
	approve := doJSONRequest(t, router, http.MethodPost, "/api/v1/access-reviews/"+pending.ReviewID+"/approve", "", admin.AccessToken, "127.0.0.1:43210")
	if approve.Code != http.StatusNoContent {
		t.Fatalf("approve SFTP review = %d %s", approve.Code, approve.Body.String())
	}
	issue := doSFTPRequest(t, router, http.MethodPost, base+"/session", operatorSession.AccessToken, "")
	if issue.Code != http.StatusCreated {
		t.Fatalf("issue approved SFTP session = %d %s", issue.Code, issue.Body.String())
	}
	var issued struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(issue.Body.Bytes(), &issued); err != nil || issued.SessionToken == "" {
		t.Fatalf("issued SFTP session payload = %#v, %v", issued, err)
	}

	opened := doSFTPRequest(t, router, http.MethodGet, base, operatorSession.AccessToken, issued.SessionToken)
	if opened.Code != http.StatusBadGateway || openCalls != 1 {
		t.Fatalf("approved SFTP request = status %d, connector calls %d", opened.Code, openCalls)
	}
	revoked := doSFTPRequest(t, router, http.MethodDelete, base+"/session", operatorSession.AccessToken, issued.SessionToken)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke SFTP session = %d %s", revoked.Code, revoked.Body.String())
	}
	closed := doSFTPRequest(t, router, http.MethodGet, base, operatorSession.AccessToken, issued.SessionToken)
	if closed.Code != http.StatusPreconditionRequired || openCalls != 1 {
		t.Fatalf("revoked SFTP session = status %d, connector calls %d", closed.Code, openCalls)
	}
}

func doSFTPRequest(t *testing.T, handler http.Handler, method, endpoint, bearer, sftpToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, endpoint, nil)
	req.RemoteAddr = "127.0.0.1:43210"
	req.Header.Set("Authorization", "Bearer "+bearer)
	if sftpToken != "" {
		req.Header.Set("X-JMS-SFTP-Session", sftpToken)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
