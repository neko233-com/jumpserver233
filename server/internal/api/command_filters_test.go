package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	coreassets "github.com/neko233-com/jumpserver233/server/internal/core/assets"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	corecommandfilters "github.com/neko233-com/jumpserver233/server/internal/core/commandfilters"
)

func TestCommandFilterRoutesAreAdminOnlyAndPersistRules(t *testing.T) {
	dataDir := t.TempDir()
	identities, err := coreauth.OpenService(filepath.Join(dataDir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.Bootstrap("admin.user", "admin-password-for-filter-tests"); err != nil {
		t.Fatal(err)
	}
	admin, err := identities.Authenticate("admin.user", "admin-password-for-filter-tests")
	if err != nil {
		t.Fatal(err)
	}
	operator, err := identities.CreateUser("operator.user", "operator-password-for-filter-tests", coreauth.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	operatorLogin, err := identities.Authenticate(operator.Username, "operator-password-for-filter-tests")
	if err != nil {
		t.Fatal(err)
	}
	assetStore, err := coreassets.OpenStore(filepath.Join(dataDir, "assets.json"), []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	filterStore, err := corecommandfilters.OpenStore(filepath.Join(dataDir, "command-filters.json"))
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter("test", Dependencies{Assets: coreassets.NewService(assetStore, nil), Auth: identities, CommandFilters: filterStore})
	const remote = "192.0.2.20:34567"
	created := doJSONRequest(t, router, http.MethodPost, "/api/v1/command-filters", `{"name":"deny reboot","account":"*","match":"contains","pattern":"reboot","action":"deny","priority":20}`, admin.AccessToken, remote)
	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"name":"deny reboot"`) {
		t.Fatalf("create command filter = %d %s", created.Code, created.Body.String())
	}
	listed := doJSONRequest(t, router, http.MethodGet, "/api/v1/command-filters", "", admin.AccessToken, remote)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"priority":20`) {
		t.Fatalf("list command filters = %d %s", listed.Code, listed.Body.String())
	}
	if response := doJSONRequest(t, router, http.MethodGet, "/api/v1/command-filters", "", operatorLogin.AccessToken, remote); response.Code != http.StatusForbidden {
		t.Fatalf("operator command filter list = %d, want 403: %s", response.Code, response.Body.String())
	}
	var rows []corecommandfilters.Filter
	if err := json.Unmarshal(listed.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode filter list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("command filter rows = %#v", rows)
	}
	deleted := doJSONRequest(t, router, http.MethodDelete, "/api/v1/command-filters/"+rows[0].ID, "", admin.AccessToken, remote)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete command filter = %d %s", deleted.Code, deleted.Body.String())
	}
}
