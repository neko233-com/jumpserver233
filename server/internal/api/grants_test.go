package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func TestOperatorInventoryAndSessionAccessFollowTimeBoundGrant(t *testing.T) {
	identities, err := coreauth.OpenService(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", bootstrapPassword); err != nil {
		t.Fatal(err)
	}
	adminSession, err := identities.Authenticate("admin.user", bootstrapPassword)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := identities.CreateUser("operator.one", "an-operator-password-1234", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	operatorSession, err := identities.Authenticate("operator.one", "an-operator-password-1234")
	if err != nil {
		t.Fatal(err)
	}
	assets := testAssetService(t)
	asset, err := assets.Create(coreassets.Input{
		Name: "ops-host", Host: "192.0.2.20", Username: "deploy", Password: "test-only",
		Port: 22, HostKeyFingerprint: validTestFingerprint(),
	})
	if err != nil {
		t.Fatal(err)
	}
	grants, err := coregrants.OpenStore(filepath.Join(t.TempDir(), "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker := gateway.NewBroker(t.TempDir(), []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: assetID, Name: "ops-host", Username: "deploy"}, sessionTestTerminal{}, nil
	})
	t.Cleanup(broker.CloseAll)
	router := NewRouter("test", Dependencies{Assets: assets, Auth: identities, Grants: grants, Sessions: broker})

	initial := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets", "", operatorSession.AccessToken, "127.0.0.1:43210")
	if initial.Code != http.StatusOK || initial.Body.String() != "[]\n" {
		t.Fatalf("inventory before grant = %d %s", initial.Code, initial.Body.String())
	}
	viewGrant, err := json.Marshal(coregrants.Input{UserID: operator.ID, AssetID: asset.ID, Account: "deploy", Actions: []string{"view"}})
	if err != nil {
		t.Fatal(err)
	}
	createdView := doJSONRequest(t, router, http.MethodPost, "/api/v1/grants", string(viewGrant), adminSession.AccessToken, "127.0.0.1:43210")
	if createdView.Code != http.StatusCreated {
		t.Fatalf("create view grant = %d %s", createdView.Code, createdView.Body.String())
	}
	visible := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets", "", operatorSession.AccessToken, "127.0.0.1:43210")
	var items []coreassets.ListItem
	if err := json.Unmarshal(visible.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if visible.Code != http.StatusOK || len(items) != 1 || items[0].ID != asset.ID || len(items[0].Permissions) != 1 || items[0].Permissions[0] != "view" {
		t.Fatalf("inventory with view grant = %d %#v", visible.Code, items)
	}
	if strings.Contains(visible.Body.String(), "password_rotation") || strings.Contains(visible.Body.String(), "password_rotated_at") {
		t.Fatalf("operator inventory exposed password rotation details: %s", visible.Body.String())
	}
	operatorRotation := doJSONRequest(t, router, http.MethodPost, "/api/v1/assets/"+asset.ID+"/password-rotation", "", operatorSession.AccessToken, "127.0.0.1:43210")
	if operatorRotation.Code != http.StatusForbidden {
		t.Fatalf("operator password rotation = %d, want 403", operatorRotation.Code)
	}
	createSession := `{"asset_id":"` + asset.ID + `","cols":80,"rows":24}`
	denied := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", createSession, operatorSession.AccessToken, "127.0.0.1:43210")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("session with view-only grant = %d %s, want 403", denied.Code, denied.Body.String())
	}
	connectGrant, err := json.Marshal(coregrants.Input{UserID: operator.ID, AssetID: asset.ID, Account: "deploy", Actions: []string{"connect"}})
	if err != nil {
		t.Fatal(err)
	}
	createdConnect := doJSONRequest(t, router, http.MethodPost, "/api/v1/grants", string(connectGrant), adminSession.AccessToken, "127.0.0.1:43210")
	if createdConnect.Code != http.StatusCreated {
		t.Fatalf("create connect grant = %d %s", createdConnect.Code, createdConnect.Body.String())
	}
	allowed := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", createSession, operatorSession.AccessToken, "127.0.0.1:43210")
	if allowed.Code != http.StatusCreated {
		t.Fatalf("session with connect grant = %d %s", allowed.Code, allowed.Body.String())
	}
	listedGrants := doJSONRequest(t, router, http.MethodGet, "/api/v1/grants", "", adminSession.AccessToken, "127.0.0.1:43210")
	if listedGrants.Code != http.StatusOK || len(grants.List()) != 2 {
		t.Fatalf("list grants = %d %s", listedGrants.Code, listedGrants.Body.String())
	}
	forbiddenGrant := doJSONRequest(t, router, http.MethodGet, "/api/v1/grants", "", operatorSession.AccessToken, "127.0.0.1:43210")
	if forbiddenGrant.Code != http.StatusForbidden {
		t.Fatalf("operator grant management = %d, want 403", forbiddenGrant.Code)
	}
}
