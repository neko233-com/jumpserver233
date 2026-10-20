package api

import (
	"context"
	"encoding/json"
	coreauth "github.com/neko233-com/jumpserver233/server/internal/core/auth"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/neko233-com/jumpserver233/server/internal/core/rbac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOrganizationOverviewRequiresGlobalAuthorityAndRechecksRevocation(t *testing.T) {
	dir := t.TempDir()
	a, err := coreauth.OpenServiceWithVaultKey(filepath.Join(dir, "users.json"), make([]byte, 32))
	require.NoError(t, err)
	admin, err := a.Bootstrap("overview.admin", "synthetic-overview-admin-password")
	require.NoError(t, err)
	u, err := a.CreateUser("overview.operator", "synthetic-overview-operator-password", coreauth.RoleOperator)
	require.NoError(t, err)
	login, err := a.Authenticate(u.Username, "synthetic-overview-operator-password")
	require.NoError(t, err)
	orgs, err := organizations.Open(filepath.Join(dir, "organizations.json"), nil)
	require.NoError(t, err)
	roles, err := rbac.Open(filepath.Join(dir, "roles.json"), nil)
	require.NoError(t, err)
	role, err := roles.SaveRole("", rbac.RoleInput{Name: "Overview reader", Permissions: []string{"organizations.overview"}}, admin.ID, admin.Username)
	require.NoError(t, err)
	calls := 0
	revoke := false
	var binding rbac.Binding
	d := Dependencies{Auth: a, Organizations: orgs, RBAC: roles, OrganizationCounts: func(context.Context, string) (organizations.ResourceCounts, error) {
		calls++
		if revoke {
			_, e := roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: u.ID, Revision: binding.Revision, RoleIDs: []string{}}, admin.ID, admin.Username)
			require.NoError(t, e)
		}
		return organizations.ResourceCounts{}, nil
	}}
	handler := NewRouter("source-only", d)
	request := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+login.AccessToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	assert.Equal(t, 403, request("/api/v1/organizations/overview").Code)
	assert.Zero(t, calls)
	binding, err = roles.SaveBinding(rbac.BindingInput{SubjectType: "user", SubjectID: u.ID, RoleIDs: []string{role.ID}}, admin.ID, admin.Username)
	require.NoError(t, err)
	first := request("/api/v1/organizations/overview")
	assert.Equal(t, 200, first.Code)
	assert.Contains(t, first.Header().Get("Cache-Control"), "no-store")
	var out organizations.Overview
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &out))
	assert.Equal(t, 1, out.CollectedOrganizations)
	assert.NotContains(t, first.Body.String(), u.Username)
	assert.Equal(t, 400, request("/api/v1/organizations/overview?include_archived=true&include_archived=false").Code)
	assert.Equal(t, 400, request("/api/v1/organizations/overview?unknown=1").Code)
	revoke = true
	assert.Equal(t, 403, request("/api/v1/organizations/overview").Code)
	assert.Equal(t, 403, request("/api/v1/organizations/overview").Code)
	assert.NotContains(t, rbac.OrganizationCatalog(), "organizations.overview")
}

func TestOrganizationOverviewBoundsConcurrentCollections(t *testing.T) {
	dir := t.TempDir()
	a, err := coreauth.OpenServiceWithVaultKey(filepath.Join(dir, "users.json"), make([]byte, 32))
	require.NoError(t, err)
	orgs, err := organizations.Open(filepath.Join(dir, "organizations.json"), nil)
	require.NoError(t, err)
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	defer close(release)
	h := NewRouter("source-only", Dependencies{Auth: a, Organizations: orgs, AdminToken: "synthetic-overview-admin-token", OrganizationCounts: func(ctx context.Context, _ string) (organizations.ResourceCounts, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return organizations.ResourceCounts{}, nil
		case <-ctx.Done():
			return organizations.ResourceCounts{}, ctx.Err()
		}
	}})
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/v1/organizations/overview", nil)
		r.Header.Set("Authorization", "Bearer synthetic-overview-admin-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() { defer workers.Done(); request() }()
	}
	for range 4 {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("collectors did not enter")
		}
	}
	assert.Equal(t, 429, request().Code)
	// The service owns no worker goroutines; these are only test HTTP callers.
	for range 4 {
		release <- struct{}{}
	}
	workers.Wait()
}
