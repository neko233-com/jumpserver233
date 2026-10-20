package api

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/announcements"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnnouncementsUsePlatformPermissionsAndBindReadingsToPrincipal(t *testing.T) {
	dir := t.TempDir()
	identities, e := coreauth.OpenService(filepath.Join(dir, "users.json"))
	require.NoError(t, e)
	admin, e := identities.Bootstrap("admin", bootstrapPassword)
	require.NoError(t, e)
	reader, e := identities.CreateUser("notice-reader", "synthetic-announcement-reader-233", coreauth.RoleOperator)
	require.NoError(t, e)
	adminLogin, e := identities.Authenticate("admin", bootstrapPassword)
	require.NoError(t, e)
	readerLogin, e := identities.Authenticate(reader.Username, "synthetic-announcement-reader-233")
	require.NoError(t, e)
	store, e := announcements.Open(filepath.Join(dir, "announcements.json"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer store.Close()
	router := NewRouter("test", Dependencies{Auth: identities, Announcements: store})
	body := `{"title":{"en":"Maintenance","zh-CN":"维护"},"body":{"en":"<img src=x>","zh-CN":"维护内容"},"published":true,"request_id":"api-notice-001"}`
	denied := doJSONRequest(t, router, "POST", "/api/v1/announcements", body, readerLogin.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 403, denied.Code)
	created := doJSONRequest(t, router, "POST", "/api/v1/announcements", body, adminLogin.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 201, created.Code, created.Body.String())
	var notice announcements.Notice
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &notice))
	replayed := doJSONRequest(t, router, "POST", "/api/v1/announcements", body, adminLogin.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 201, replayed.Code)
	assert.JSONEq(t, created.Body.String(), replayed.Body.String())
	for _, path := range []string{"/api/v1/announcements?manage=true", "/api/v1/announcements/audit"} {
		res := doJSONRequest(t, router, "GET", path, "", readerLogin.AccessToken, "127.0.0.1:12345")
		assert.Equal(t, 403, res.Code)
	}
	forged := doJSONRequest(t, router, "POST", "/api/v1/announcements/"+notice.ID+"/read", `{"revision":1,"user_id":"forged"}`, readerLogin.AccessToken, "127.0.0.1:12345")
	assert.Equal(t, 400, forged.Code)
	read := doJSONRequest(t, router, "POST", "/api/v1/announcements/"+notice.ID+"/read", `{"revision":1}`, readerLogin.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, read.Code, read.Body.String())
	var receipt announcements.Reading
	require.NoError(t, json.Unmarshal(read.Body.Bytes(), &receipt))
	assert.Equal(t, reader.ID, receipt.UserID)
	audit := doJSONRequest(t, router, "GET", "/api/v1/announcements/audit", "", adminLogin.AccessToken, "127.0.0.1:12345")
	require.Equal(t, 200, audit.Code)
	var page struct {
		Results []announcements.Audit `json:"results"`
	}
	require.NoError(t, json.Unmarshal(audit.Body.Bytes(), &page))
	require.Len(t, page.Results, 1)
	assert.Equal(t, admin.ID, page.Results[0].ActorID)
	assert.NotContains(t, audit.Body.String(), "<img")
	assert.NotContains(t, rbac.OrganizationCatalog(), "announcements.manage")
}
