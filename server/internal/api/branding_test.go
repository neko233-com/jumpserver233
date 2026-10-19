package api

import (
	"bytes"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/branding"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func brandingEnv(t *testing.T) *policyTestEnv {
	t.Helper()
	e := monitoringEnv(t)
	var err error
	e.d.Branding, err = branding.Open(filepath.Join(t.TempDir(), "branding.json"), nil)
	require.NoError(t, err)
	e.router = NewRouter("test", e.d)
	return e
}
func brandingPNG(t *testing.T) []byte {
	t.Helper()
	im := image.NewNRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			im.Set(x, y, color.NRGBA{30, 180, 120, 255})
		}
	}
	var data bytes.Buffer
	require.NoError(t, png.Encode(&data, im))
	return data.Bytes()
}
func brandingInput(s branding.Settings) branding.Input { return branding.AsInput(s) }
func TestBrandingPublicSnapshotAndImagesNeverExposePrivateAudit(t *testing.T) {
	e := brandingEnv(t)
	in := brandingInput(branding.Defaults())
	in.NameEN = "Operations Vault"
	in.NameZH = "运维平台"
	logo := append(brandingPNG(t), []byte("synthetic-private-metadata")...)
	in.Logo = &logo
	in.Icon = &logo
	r := e.send(t, "PUT", "/api/v1/settings/branding", in, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, r.Code, r.Body.String())
	assert.Contains(t, r.Header().Get("Cache-Control"), "no-store")
	var saved branding.Public
	require.NoError(t, json.Unmarshal(r.Body.Bytes(), &saved))
	public := e.send(t, "GET", "/api/v1/branding", nil, "", "192.0.2.1:4000")
	require.Equal(t, 200, public.Code)
	assert.Contains(t, public.Body.String(), in.NameEN)
	for _, private := range []string{"actor_id", "synthetic-private-metadata", "created_by"} {
		assert.NotContains(t, public.Body.String(), private)
	}
	conditional := httptest.NewRequest("GET", "/api/v1/branding", nil)
	conditional.Header.Set("If-None-Match", public.Header().Get("ETag"))
	recorder := httptest.NewRecorder()
	e.router.ServeHTTP(recorder, conditional)
	assert.Equal(t, 304, recorder.Code)
	assert.Empty(t, recorder.Body.String())
	imagePath := "/api/v1/branding/images/" + saved.LogoDigest
	imageResponse := e.send(t, "GET", imagePath, nil, "", "192.0.2.1:4000")
	require.Equal(t, 200, imageResponse.Code)
	assert.Equal(t, "image/png", imageResponse.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", imageResponse.Header().Get("X-Content-Type-Options"))
	assert.Contains(t, imageResponse.Header().Get("Cache-Control"), "immutable")
	assert.NotContains(t, imageResponse.Body.String(), "synthetic-private-metadata")
	_, err := png.Decode(bytes.NewReader(imageResponse.Body.Bytes()))
	require.NoError(t, err)
	conditional = httptest.NewRequest("GET", imagePath, nil)
	conditional.Header.Set("If-None-Match", imageResponse.Header().Get("ETag"))
	recorder = httptest.NewRecorder()
	e.router.ServeHTTP(recorder, conditional)
	assert.Equal(t, 304, recorder.Code)
	assert.Equal(t, 404, e.send(t, "GET", "/api/v1/branding/images/invalid", nil, "", "192.0.2.1:4000").Code)
	clear := brandingInput(saved.Settings)
	empty := []byte{}
	clear.Logo = &empty
	clear.Icon = &empty
	assert.Equal(t, 200, e.send(t, "PUT", "/api/v1/settings/branding", clear, e.adminToken, "192.0.2.1:4000").Code)
	assert.Equal(t, 404, e.send(t, "GET", imagePath, nil, "", "192.0.2.1:4000").Code)
}
func TestBrandingIndependentGlobalPermissionAndCurrentRevocation(t *testing.T) {
	e := brandingEnv(t)
	in := brandingInput(branding.Defaults())
	in.NameEN = "Changed branding"
	for _, token := range []string{"", e.token} {
		for _, path := range []string{"/api/v1/settings/branding", "/api/v1/settings/branding/audit"} {
			assert.Contains(t, []int{401, 403}, e.send(t, "GET", path, nil, token, "192.0.2.1:4000").Code)
		}
		assert.Contains(t, []int{401, 403}, e.send(t, "PUT", "/api/v1/settings/branding", in, token, "192.0.2.1:4000").Code)
		assert.Contains(t, []int{401, 403}, e.send(t, "POST", "/api/v1/settings/branding/prepare-image", map[string]any{"kind": "logo", "data": brandingPNG(t)}, token, "192.0.2.1:4000").Code)
	}
	role, err := e.d.RBAC.SaveRole("", rbac.RoleInput{Name: "Global branding", Permissions: []string{"branding.manage"}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	binding, err := e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, RoleIDs: []string{role.ID}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	e.router = NewOrganizationRouter("test", e.d, func(string) (http.Handler, error) { t.Fatal("branding must use global authorization"); return nil, nil })
	payload, err := json.Marshal(in)
	require.NoError(t, err)
	request := httptest.NewRequest("PUT", "/api/v1/settings/branding", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer "+e.token)
	request.Header.Set("X-JMS-ORG", "00000000-0000-0000-0000-000000000002")
	response := httptest.NewRecorder()
	e.router.ServeHTTP(response, request)
	require.Equal(t, 200, response.Code, response.Body.String())
	_, err = e.d.RBAC.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: e.operator.ID, Revision: binding.Revision, RoleIDs: []string{}}, e.admin.ID, e.admin.Username)
	require.NoError(t, err)
	assert.Equal(t, 403, e.send(t, "GET", "/api/v1/settings/branding", nil, e.token, "192.0.2.1:4000").Code)
	assert.Equal(t, 403, e.send(t, "PUT", "/api/v1/settings/branding", in, e.token, "192.0.2.1:4000").Code)
}
func TestBrandingPreparationRetriesConflictsAndInvalidBodies(t *testing.T) {
	e := brandingEnv(t)
	prepared := e.send(t, "POST", "/api/v1/settings/branding/prepare-image", map[string]any{"kind": "logo", "data": brandingPNG(t)}, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, prepared.Code)
	assert.Contains(t, prepared.Header().Get("Cache-Control"), "no-store")
	_, total, err := e.d.Branding.Audit(0, 10)
	require.NoError(t, err)
	assert.Zero(t, total)
	in := brandingInput(branding.Defaults())
	in.NameEN = "Updated"
	first := e.send(t, "PUT", "/api/v1/settings/branding", in, e.adminToken, "192.0.2.1:4000")
	require.Equal(t, 200, first.Code)
	retry := e.send(t, "PUT", "/api/v1/settings/branding", in, e.adminToken, "192.0.2.1:4000")
	assert.Equal(t, 200, retry.Code)
	assert.JSONEq(t, first.Body.String(), retry.Body.String())
	_, total, err = e.d.Branding.Audit(0, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	in.NameEN = "Conflict"
	assert.Equal(t, 409, e.send(t, "PUT", "/api/v1/settings/branding", in, e.adminToken, "192.0.2.1:4000").Code)
	for _, body := range []any{map[string]any{"logo_url": "https://invalid.example/"}, map[string]any{"revision": 2, "name_en": "name", "name_zh": "名称", "theme": "graphite", "accent": "#0d1117"}} {
		assert.Equal(t, 400, e.send(t, "PUT", "/api/v1/settings/branding", body, e.adminToken, "192.0.2.1:4000").Code)
	}
	assert.Equal(t, 400, e.send(t, "POST", "/api/v1/settings/branding/prepare-image", map[string]any{"kind": "logo", "data": []byte(`<svg onload="bad()"/>`)}, e.adminToken, "192.0.2.1:4000").Code)
	assert.Equal(t, 400, e.send(t, "GET", "/api/v1/settings/branding/audit?offset=-1", nil, e.adminToken, "192.0.2.1:4000").Code)
}
