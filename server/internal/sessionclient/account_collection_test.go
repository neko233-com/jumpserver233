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

	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountCollectionManagedSelectorCanPauseDisabledCredentialAndPreservesSigning(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprint(signed), func(t *testing.T) {
			endpoint := "account-asset-physical-" + strings.Repeat("a", 32)
			mutations := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, organizations.DefaultID, r.Header.Get("X-JMS-ORG"))
				w.Header().Set("Content-Type", "application/json")
				if signed {
					mac := hmac.New(sha256.New, []byte("synthetic-platform-key"))
					_, _ = fmt.Fprintf(mac, "(request-target): %s %s\naccept: application/json\ndate: %s", strings.ToLower(r.Method), r.URL.RequestURI(), r.Header.Get("Date"))
					assert.Contains(t, r.Header.Get("Authorization"), `signature="`+base64.StdEncoding.EncodeToString(mac.Sum(nil))+`"`)
				} else {
					assert.Equal(t, "Bearer synthetic-platform-token", r.Header.Get("Authorization"))
				}
				switch r.URL.Path {
				case "/api/v1/assets/asset-physical/accounts":
					_ = json.NewEncoder(w).Encode(ManagedAccountPage{Total: 1, Results: []ManagedAccount{{ID: endpoint, AssetID: "asset-physical", Username: "ops", Active: false}}})
				case "/api/v1/assets/" + endpoint + "/account-discovery/plans/plan":
					mutations++
					var in AccountCollectionPlanUpdate
					require.NoError(t, json.NewDecoder(r.Body).Decode(&in))
					assert.False(t, in.Enabled)
					_ = json.NewEncoder(w).Encode(AccountCollectionPlan{ID: "plan", Revision: 2})
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer s.Close()
			c, e := New(s.URL, "synthetic-platform-token")
			if signed {
				c, e = NewWithAccessKey(s.URL, "ak-"+strings.Repeat("a", 32), "synthetic-platform-key")
			}
			require.NoError(t, e)
			c, e = c.WithOrganization(organizations.DefaultID)
			require.NoError(t, e)
			c, e = c.WithManagedAccount("ops")
			require.NoError(t, e)
			v, e := c.UpdateAccountCollectionPlan(context.Background(), "asset-physical", "plan", AccountCollectionPlanUpdate{Enabled: false, Revision: 1})
			require.NoError(t, e)
			assert.Equal(t, 2, v.Revision)
			_, e = c.SubmitJob(context.Background(), jobs.Input{AssetID: "asset-physical", Command: "whoami"})
			require.Error(t, e)
			assert.Equal(t, 1, mutations, "disabled selection is management-only")
		})
	}
}
