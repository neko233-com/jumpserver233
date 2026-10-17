package sessionclient

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountRisksSDKKeepsOrganizationAndSignsQueriesWithoutExposingErrors(t *testing.T) {
	for _, mode := range []string{"bearer", "access-key"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				assert.Equal(t, "00000000-0000-0000-0000-000000000002", r.Header.Get("X-JMS-ORG"))
				if mode == "bearer" {
					assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
				} else {
					mac := hmac.New(sha256.New, []byte("synthetic-risk-key"))
					_, _ = fmt.Fprintf(mac, "(request-target): %s %s\naccept: application/json\ndate: %s", strings.ToLower(r.Method), r.URL.RequestURI(), r.Header.Get("Date"))
					assert.Contains(t, r.Header.Get("Authorization"), `signature="`+base64.StdEncoding.EncodeToString(mac.Sum(nil))+`"`)
				}
				switch r.URL.Path {
				case "/api/v1/accounts/risks/policy":
					_ = json.NewEncoder(w).Encode(AccountRiskPolicy{Revision: 3})
				case "/api/v1/accounts/risks":
					assert.Equal(t, "host & key", r.URL.Query().Get("q"))
					_, _ = w.Write([]byte(`{"results":[{"id":"risk-safe","password":"never-decode-extra-secret"}],"total":1}`))
				case "/api/v1/accounts/risks/export":
					assert.Equal(t, "host & key", r.URL.Query().Get("q"))
					w.Header().Set("Content-Type", "text/csv; charset=utf-8")
					_, _ = w.Write([]byte("id,kind\nrisk-safe,weak_password\n"))
				default:
					w.WriteHeader(409)
					_, _ = w.Write([]byte(`{"error_code":"conflict","error":"never-print-server-secret"}`))
				}
			}))
			defer server.Close()
			c, e := New(server.URL+"/", "synthetic-token")
			if mode == "access-key" {
				c, e = NewWithAccessKey(server.URL+"/", "ak-"+strings.Repeat("a", 32), "synthetic-risk-key")
			}
			require.NoError(t, e)
			c, e = c.WithOrganization("00000000-0000-0000-0000-000000000002")
			require.NoError(t, e)
			p, e := c.AccountRiskPolicy(context.Background())
			require.NoError(t, e)
			assert.Equal(t, 3, p.Revision)
			q := AccountRiskQuery{Search: "host & key"}
			rows, total, e := c.AccountRiskFindings(context.Background(), q)
			require.NoError(t, e)
			assert.Equal(t, 1, total)
			raw, e := json.Marshal(rows)
			require.NoError(t, e)
			assert.NotContains(t, string(raw), "never-decode")
			csv, e := c.ExportAccountRisks(context.Background(), q)
			require.NoError(t, e)
			assert.Contains(t, string(csv), "risk-safe")
			_, e = c.ReviewAccountRisk(context.Background(), "risk-safe", 1, "ignore", "review")
			require.Error(t, e)
			assert.NotContains(t, e.Error(), "never-print")
			assert.Equal(t, 4, calls)
		})
	}
}
