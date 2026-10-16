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
	corenodes "github.com/neko233-com/jumpserver233/server/internal/core/nodes"
	"github.com/neko233-com/jumpserver233/server/internal/gateway"
)

func TestNodeGrantAppliesToAssetsAndSessionInSubtree(t *testing.T) {
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
	nodes, err := corenodes.OpenStore(filepath.Join(dataDir, "asset-nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	grants, err := coregrants.OpenStore(filepath.Join(dataDir, "grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	broker := gateway.NewBroker(filepath.Join(dataDir, "sessions"), []byte("0123456789abcdef0123456789abcdef"), func(_ context.Context, assetID string, _, _ int) (gateway.AssetInfo, gateway.Terminal, error) {
		return gateway.AssetInfo{ID: assetID, Name: "production-host", Username: "deploy"}, sessionTestTerminal{}, nil
	})
	t.Cleanup(broker.CloseAll)
	router := NewRouter("test", Dependencies{Assets: assets, Auth: identities, Grants: grants, Nodes: nodes, Sessions: broker})
	adminIP := "127.0.0.1:43210"

	createNode := func(body string) corenodes.Node {
		t.Helper()
		response := doJSONRequest(t, router, http.MethodPost, "/api/v1/assets/nodes", body, adminSession.AccessToken, adminIP)
		if response.Code != http.StatusCreated {
			t.Fatalf("create node = %d %s", response.Code, response.Body.String())
		}
		var node corenodes.Node
		if err := json.Unmarshal(response.Body.Bytes(), &node); err != nil {
			t.Fatal(err)
		}
		return node
	}
	root := createNode(`{"name":"Production"}`)
	child := createNode(`{"name":"API","parent_id":"` + root.ID + `"}`)
	unrelated := createNode(`{"name":"Staging"}`)

	assetResponse := doJSONRequest(t, router, http.MethodPost, "/api/v1/assets", `{"name":"production-host","host":"192.0.2.50","port":22,"group":"Production","node_id":"`+child.ID+`","username":"deploy","password":"test-only","host_key_fingerprint":"`+validTestFingerprint()+`"}`, adminSession.AccessToken, adminIP)
	if assetResponse.Code != http.StatusCreated {
		t.Fatalf("create node-assigned asset = %d %s", assetResponse.Code, assetResponse.Body.String())
	}
	var asset coreassets.ListItem
	if err := json.Unmarshal(assetResponse.Body.Bytes(), &asset); err != nil {
		t.Fatal(err)
	}
	if asset.NodeID != child.ID {
		t.Fatalf("asset node_id = %q, want %q", asset.NodeID, child.ID)
	}

	grantBody := `{"user_id":"` + operator.ID + `","node_id":"` + root.ID + `","account":"deploy","actions":["connect","sftp"]}`
	grantResponse := doJSONRequest(t, router, http.MethodPost, "/api/v1/grants", grantBody, adminSession.AccessToken, adminIP)
	if grantResponse.Code != http.StatusCreated {
		t.Fatalf("create node grant = %d %s", grantResponse.Code, grantResponse.Body.String())
	}
	var grant coregrants.Grant
	if err := json.Unmarshal(grantResponse.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.NodeID != root.ID || grant.AssetID != "" || !grants.ReferencesNode(root.ID) {
		t.Fatalf("node grant was not stored on its node: %+v", grant)
	}

	nodeList := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets/nodes", "", operatorSession.AccessToken, adminIP)
	var visibleNodes []corenodes.Node
	if err := json.Unmarshal(nodeList.Body.Bytes(), &visibleNodes); err != nil {
		t.Fatal(err)
	}
	if nodeList.Code != http.StatusOK || len(visibleNodes) != 2 || visibleNodes[0].ID == unrelated.ID || visibleNodes[1].ID == unrelated.ID {
		t.Fatalf("operator node list = %d %#v; want only the granted asset's ancestor chain", nodeList.Code, visibleNodes)
	}

	operatorInventory := doJSONRequest(t, router, http.MethodGet, "/api/v1/assets", "", operatorSession.AccessToken, adminIP)
	var visibleAssets []coreassets.ListItem
	if err := json.Unmarshal(operatorInventory.Body.Bytes(), &visibleAssets); err != nil {
		t.Fatal(err)
	}
	if operatorInventory.Code != http.StatusOK || len(visibleAssets) != 1 || visibleAssets[0].ID != asset.ID {
		t.Fatalf("operator inventory with inherited node grant = %d %#v", operatorInventory.Code, visibleAssets)
	}
	if len(visibleAssets[0].Permissions) != 3 {
		t.Fatalf("inherited node actions = %#v; want connect, sftp and implied view", visibleAssets[0].Permissions)
	}

	session := doJSONRequest(t, router, http.MethodPost, "/api/v1/sessions", `{"asset_id":"`+asset.ID+`","cols":80,"rows":24}`, operatorSession.AccessToken, adminIP)
	if session.Code != http.StatusCreated {
		t.Fatalf("session using inherited node grant = %d %s", session.Code, session.Body.String())
	}

	deleteAssignedNode := doJSONRequest(t, router, http.MethodDelete, "/api/v1/assets/nodes/"+child.ID, "", adminSession.AccessToken, adminIP)
	if deleteAssignedNode.Code != http.StatusConflict {
		t.Fatalf("delete node assigned to asset = %d, want 409", deleteAssignedNode.Code)
	}
	deleteGrantedNode := doJSONRequest(t, router, http.MethodDelete, "/api/v1/assets/nodes/"+root.ID, "", adminSession.AccessToken, adminIP)
	if deleteGrantedNode.Code != http.StatusConflict {
		t.Fatalf("delete node referenced by grant = %d, want 409", deleteGrantedNode.Code)
	}

	revokeGrant := doJSONRequest(t, router, http.MethodDelete, "/api/v1/grants/"+grant.ID, "", adminSession.AccessToken, adminIP)
	if revokeGrant.Code != http.StatusNoContent {
		t.Fatalf("revoke node grant = %d %s", revokeGrant.Code, revokeGrant.Body.String())
	}
	removeAsset := doJSONRequest(t, router, http.MethodDelete, "/api/v1/assets/"+asset.ID, "", adminSession.AccessToken, adminIP)
	if removeAsset.Code != http.StatusNoContent {
		t.Fatalf("remove node-assigned asset = %d %s", removeAsset.Code, removeAsset.Body.String())
	}
	removeChild := doJSONRequest(t, router, http.MethodDelete, "/api/v1/assets/nodes/"+child.ID, "", adminSession.AccessToken, adminIP)
	if removeChild.Code != http.StatusNoContent {
		t.Fatalf("remove leaf node = %d %s", removeChild.Code, removeChild.Body.String())
	}
	removeRoot := doJSONRequest(t, router, http.MethodDelete, "/api/v1/assets/nodes/"+root.ID, "", adminSession.AccessToken, adminIP)
	if removeRoot.Code != http.StatusNoContent {
		t.Fatalf("remove empty parent node = %d %s", removeRoot.Code, removeRoot.Body.String())
	}
}
