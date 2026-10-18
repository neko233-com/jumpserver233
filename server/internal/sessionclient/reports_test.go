package sessionclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type reportShortWriter struct{}

func (reportShortWriter) Write(v []byte) (int, error) { return len(v) - 1, nil }

func TestReportSDKRequiresVerifiedReceiptBeforeWriting(t *testing.T) {
	for _, mode := range []string{"valid", "digest", "receipt", "type", "oversize", "denied", "shortwrite"} {
		t.Run(mode, func(t *testing.T) {
			payload := "source,count\nssh_jobs,2\n"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer synthetic-token", r.Header.Get("Authorization"))
				assert.Equal(t, "true", r.URL.Query().Get("include_platform"))
				assert.Equal(t, "ssh_jobs,assets", r.URL.Query().Get("sources"))
				assert.Equal(t, "true", r.URL.Query().Get("allow_partial"))
				if mode == "denied" {
					w.WriteHeader(403)
					fmt.Fprint(w, `{"password":"synthetic-private"}`)
					return
				}
				data := payload
				if mode == "oversize" {
					data = strings.Repeat("x", (4<<20)+1)
				}
				sum := sha256.Sum256([]byte(data))
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Header().Set("X-JMS-Report-ID", "report-export-00112233445566778899aabbccddeeff")
				w.Header().Set("X-JMS-Report-SHA256", hex.EncodeToString(sum[:]))
				if mode == "digest" {
					w.Header().Set("X-JMS-Report-SHA256", strings.Repeat("0", 64))
				}
				if mode == "receipt" {
					w.Header().Set("X-JMS-Report-ID", "../unsafe")
				}
				if mode == "type" {
					w.Header().Set("Content-Type", "application/json")
				}
				fmt.Fprint(w, data)
			}))
			defer srv.Close()
			c, e := New(srv.URL, "synthetic-token")
			require.NoError(t, e)
			var out bytes.Buffer
			var writer io.Writer = &out
			if mode == "shortwrite" {
				writer = reportShortWriter{}
			}
			receipt, e := c.ExportReport(context.Background(), ReportQuery{IncludePlatform: true, Sources: []string{"ssh_jobs", "assets"}}, true, writer)
			if mode == "valid" {
				require.NoError(t, e)
				assert.Equal(t, payload, out.String())
				assert.Equal(t, len(payload), receipt.Bytes)
			} else {
				require.Error(t, e)
				assert.Empty(t, out.String())
				assert.NotContains(t, e.Error(), "synthetic-private")
			}
		})
	}
}

func TestReportSDKOverviewAndReceiptPaging(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/reports/overview" {
			fmt.Fprint(w, `{"version":1,"sources":[],"password":"synthetic-private"}`)
			return
		}
		assert.Equal(t, "all", r.URL.Query().Get("scope"))
		assert.Equal(t, "25", r.URL.Query().Get("offset"))
		assert.Equal(t, "25", r.URL.Query().Get("limit"))
		fmt.Fprint(w, `{"results":[],"total":0}`)
	}))
	defer srv.Close()
	c, e := New(srv.URL, "synthetic-token")
	require.NoError(t, e)
	r, e := c.ReportOverview(context.Background(), ReportQuery{})
	require.NoError(t, e)
	assert.Equal(t, 1, r.Version)
	_, e = c.ReportExportHistory(context.Background(), true, 25, 25)
	require.NoError(t, e)
}
