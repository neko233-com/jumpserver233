package sessionclient

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountImportSDKPreservesOrganizationAndDoesNotSelectOneSSHIdentityForBulkFiles(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprint(signed), func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, organizations.DefaultID, r.Header.Get("X-JMS-ORG"))
				if signed {
					mac := hmac.New(sha256.New, []byte("synthetic-platform-key"))
					_, _ = fmt.Fprintf(mac, "(request-target): %s %s\naccept: application/json\ndate: %s", strings.ToLower(r.Method), r.URL.RequestURI(), r.Header.Get("Date"))
					assert.Contains(t, r.Header.Get("Authorization"), `signature="`+base64.StdEncoding.EncodeToString(mac.Sum(nil))+`"`)
				} else {
					assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
				}
				assert.True(t, strings.HasPrefix(r.URL.Path, "/api/v1/accounts/imports"))
				w.Header().Set("Content-Type", "application/json")
				if r.Method == "POST" {
					var input AccountImportRequest
					require.NoError(t, json.NewDecoder(r.Body).Decode(&input))
					assert.Equal(t, []byte("synthetic-file-body"), input.Content)
				}
				w.Write([]byte(`{"rows":[],"issues":[],"request_id":"import-id","preview_token":"proof","password":"synthetic-never-return"}`))
			}))
			defer s.Close()
			c, e := New(s.URL, "synthetic-token")
			if signed {
				c, e = NewWithAccessKey(s.URL, "ak-"+strings.Repeat("a", 32), "synthetic-platform-key")
			}
			require.NoError(t, e)
			c, e = c.WithOrganization(organizations.DefaultID)
			require.NoError(t, e)
			c, e = c.WithManagedAccount("selected-ssh-user")
			require.NoError(t, e)
			p, e := c.PreviewAccountImport(context.Background(), AccountImportRequest{Format: "csv", Content: []byte("synthetic-file-body"), RequestID: "import-id"})
			require.NoError(t, e)
			assert.Equal(t, "proof", p.Token)
			safe, e := json.Marshal(p)
			require.NoError(t, e)
			assert.NotContains(t, string(safe), "synthetic-never-return")
			_, e = c.CommitAccountImport(context.Background(), AccountImportRequest{Format: "csv", Content: []byte("synthetic-file-body"), RequestID: "import-id", PreviewToken: p.Token})
			require.NoError(t, e)
			assert.Equal(t, 2, calls)
		})
	}
}

func TestAccountImportActivitySDKKeepsBatchIDWithoutCredentialFields(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"action":"import_create","import_id":"import-activity-001","password":"synthetic-never-return"}],"total":1}`))
	}))
	defer s.Close()
	c, e := New(s.URL, "synthetic-token")
	require.NoError(t, e)
	page, e := c.ManagedAccountActivity(context.Background(), "host", "account", 0, 20)
	require.NoError(t, e)
	require.Len(t, page.Results, 1)
	assert.Equal(t, "import-activity-001", page.Results[0].ImportID)
	raw, e := json.Marshal(page)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "synthetic-never-return")
}
