package api

import (
	"net/http"
	"path/filepath"
	"testing"

	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func TestCommandReviewRoutesAreAdminOnly(t *testing.T) {
	dataDir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dataDir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.review", "admin-password-for-review-tests"); err != nil {
		t.Fatal(err)
	}
	admin, err := identities.Authenticate("admin.review", "admin-password-for-review-tests")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := identities.CreateUser("operator.review", "operator-password-for-review-tests", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	operatorLogin, err := identities.Authenticate(operator.Username, "operator-password-for-review-tests")
	if err != nil {
		t.Fatal(err)
	}
	broker := gateway.NewBroker(dataDir, []byte("0123456789abcdef0123456789abcdef"), nil)
	defer broker.CloseAll()
	router := NewRouter("test", Dependencies{Auth: identities, Sessions: broker})
	const remote = "192.0.2.30:45678"
	listed := doJSONRequest(t, router, http.MethodGet, "/api/v1/command-reviews", "", admin.AccessToken, remote)
	if listed.Code != http.StatusOK || listed.Body.String() != "{\"results\":[],\"total\":0}\n" {
		t.Fatalf("admin command review list = %d %s", listed.Code, listed.Body.String())
	}
	if response := doJSONRequest(t, router, http.MethodGet, "/api/v1/command-reviews", "", operatorLogin.AccessToken, remote); response.Code != http.StatusForbidden {
		t.Fatalf("operator command review list = %d, want 403: %s", response.Code, response.Body.String())
	}
	if response := doJSONRequest(t, router, http.MethodPost, "/api/v1/command-reviews/invalid-review-id/approve", "", admin.AccessToken, remote); response.Code != http.StatusNotFound {
		t.Fatalf("missing command review approval = %d, want 404: %s", response.Code, response.Body.String())
	}
}
