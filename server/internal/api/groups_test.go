package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	coregrants "github.com/neko233-com/jumpserver233/server/internal/core/grants"
	coregroups "github.com/neko233-com/jumpserver233/server/internal/core/groups"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func TestGroupGrantControlsOperatorInventoryAndSSHSession(t *testing.T) {
	dataDir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dataDir, "users.json"))
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
		Name: "group-host", Host: "192.0.2.30", Username: "deploy", Password: "test-only",
		Port: 22, HostKeyFingerprint: validTestFingerprint(),
	})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := coregroups.OpenStore(filepath.Join(dataDir, "user-groups.json"))
	if err != nil {
		t.Fatal(err)
	}
	grants, err := coregrants.OpenStore(filepath.Join(dataDir, "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker := gateway.NewBroker(filepath.Join(dataDir, "sessions"), []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: assetID, Name: "group-host", Username: "deploy"}, sessionTestTerminal{}, nil
	})
	t.Cleanup(broker.CloseAll)
	router := NewRouter("test", Dependencies{Assets: assets, Auth: identities, Groups: groups, Grants: grants, Sessions: broker})

	createdGroupResponse := doJSONRequest(t, router, http.MethodPost, "/api/v1/user-groups", `{"name":"Platform","description":"SSH operators"}`, adminSession.AccessToken, "127.0.0.1:43210")
	if createdGroupResponse.Code != http.StatusCreated {
		t.Fatalf("create group = %d %s", createdGroupResponse.Code, createdGroupResponse.Body.String())
	}
	var group coregroups.Group
	if err := json.Unmarshal(createdGroupResponse.Body.Bytes(), &group); err != nil {
		t.Fatal(err)
	}
	memberPath := "/api/v1/user-groups/" + group.ID + "/members/" + operator.ID
	addedMember := doJSONRequest(t, router, http.MethodPut, memberPath, "", adminSession.AccessToken, "127.0.0.1:43210")
	if addedMember.Code != http.StatusOK {
		t.Fatalf("add group member = %d %s", addedMember.Code, addedMember.Body.String())
	}
	adminGroupMembership := doJSONRequest(t, router, http.MethodPut, "/api/v1/user-groups/"+group.ID+"/members/"+adminSession.User.ID, "", adminSession.AccessToken, "127.0.0.1:43210")
	if adminGroupMembership.Code != http.StatusBadRequest {
		t.Fatalf("add administrator to access group = %d, want 400", adminGroupMembership.Code)
	}

	grantBody := `{"group_id":"` + group.ID + `","asset_id":"` + asset.ID + `","account":"deploy","actions":["connect"]}`
	createdGrant := doJSONRequest(t, router, http.MethodPost, "/api/v1/grants", grantBody, adminSession.AccessToken, "127.0.0.1:43210")
	if createdGrant.Code != http.StatusCreated {
		t.Fatalf("create group grant = %d %s", createdGrant.Code, createdGrant.Body.String())
	}
	if !grants.ReferencesGroup(group.ID) {
		t.Fatal("created group grant was not indexed by group")
	}
	operatorInventory := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets", "", operatorSession.AccessToken, "127.0.0.1:43210")
	var items []coreassets.ListItem
	if err := json.Unmarshal(operatorInventory.Body.Bytes(), &items); err != nil {
		t.Fatal(err)
	}
	if operatorInventory.Code != http.StatusOK || len(items) != 1 || items[0].ID != asset.ID || len(items[0].Permissions) != 2 {
		t.Fatalf("group-granted inventory = %d %#v", operatorInventory.Code, items)
	}
	createdSession := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", `{"asset_id":"`+asset.ID+`","cols":80,"rows":24}`, operatorSession.AccessToken, "127.0.0.1:43210")
	if createdSession.Code != http.StatusCreated {
		t.Fatalf("create session with group grant = %d %s", createdSession.Code, createdSession.Body.String())
	}

	removedMember := doJSONRequest(t, router, http.MethodDelete, memberPath, "", adminSession.AccessToken, "127.0.0.1:43210")
	if removedMember.Code != http.StatusOK {
		t.Fatalf("remove group member = %d %s", removedMember.Code, removedMember.Body.String())
	}
	deniedInventory := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets", "", operatorSession.AccessToken, "127.0.0.1:43210")
	if deniedInventory.Code != http.StatusOK || deniedInventory.Body.String() != "[]\n" {
		t.Fatalf("inventory after membership removal = %d %s", deniedInventory.Code, deniedInventory.Body.String())
	}
	deniedSession := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", `{"asset_id":"`+asset.ID+`","cols":80,"rows":24}`, operatorSession.AccessToken, "127.0.0.1:43210")
	if deniedSession.Code != http.StatusForbidden {
		t.Fatalf("session after membership removal = %d, want 403", deniedSession.Code)
	}
	operatorGroupList := doJSONRequest(t, router, http.MethodGet, "/api/v1/user-groups", "", operatorSession.AccessToken, "127.0.0.1:43210")
	if operatorGroupList.Code != http.StatusForbidden {
		t.Fatalf("operator group management = %d, want 403", operatorGroupList.Code)
	}

	deleteInUseGroup := doJSONRequest(t, router, http.MethodDelete, "/api/v1/user-groups/"+group.ID, "", adminSession.AccessToken, "127.0.0.1:43210")
	if deleteInUseGroup.Code != http.StatusConflict {
		t.Fatalf("delete group with active grant = %d, want 409", deleteInUseGroup.Code)
	}
	var grant coregrants.Grant
	if err := json.Unmarshal(createdGrant.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	revoke := doJSONRequest(t, router, http.MethodDelete, "/api/v1/grants/"+grant.ID, "", adminSession.AccessToken, "127.0.0.1:43210")
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke group grant = %d %s", revoke.Code, revoke.Body.String())
	}
	deleteGroup := doJSONRequest(t, router, http.MethodDelete, "/api/v1/user-groups/"+group.ID, "", adminSession.AccessToken, "127.0.0.1:43210")
	if deleteGroup.Code != http.StatusNoContent {
		t.Fatalf("delete unused group = %d %s", deleteGroup.Code, deleteGroup.Body.String())
	}
}
