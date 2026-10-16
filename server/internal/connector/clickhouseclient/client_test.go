package clickhouseclient

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func query(sql string, ro bool) Input {
	return Input{SQL: sql, ReadOnly: ro, RowLimit: 50, TimeoutSeconds: 10}
}
func tlsFixture(t *testing.T, h http.HandlerFunc) (Target, Credentials) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	host, port, e := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	require.NoError(t, e)
	n, _ := strconv.Atoi(port)
	return Target{Host: host, Port: n, Username: "synthetic-user", Settings: sqlclient.Settings{Database: "qa", TLSMode: "verify-full", RootCAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}))}}, Credentials{Password: "synthetic-private-password"}
}
func TestBoundParametersEscapesNullAndStructuredValues(t *testing.T) {
	values := []json.RawMessage{json.RawMessage(`"a\t中\\N'"`), json.RawMessage(`null`), json.RawMessage(`["a'b",null]`), json.RawMessage(`["hi",18446744073709551615]`), json.RawMessage(`{"z":2,"a":1}`)}
	got, e := bind(values, map[int]string{1: "String", 2: "Nullable(UInt8)", 3: "Array(Nullable(String))", 4: "Tuple(String,UInt64)", 5: "Map(String,UInt64)"})
	require.NoError(t, e)
	assert.Equal(t, "a\\t中\\\\N'", got["param_p1"])
	assert.Equal(t, `\N`, got["param_p2"])
	assert.Equal(t, `['a\'b',NULL]`, got["param_p3"])
	assert.Equal(t, `('hi',18446744073709551615)`, got["param_p4"])
	assert.Equal(t, `{'a':1,'z':2}`, got["param_p5"])
	_, e = bind(nil, map[int]string{1: "String"})
	assert.ErrorIs(t, e, sqlclient.ErrInvalid)
	_, e = parameterValue("\x00", "String", false, 0)
	assert.ErrorIs(t, e, sqlclient.ErrInvalid)
}
func TestHTTPBodyTLSIdentityFixedSettingsAndNoRedirect(t *testing.T) {
	var calls atomic.Int32
	target, secret := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		u, p, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "synthetic-user", u)
		assert.Equal(t, "synthetic-private-password", p)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "identity", r.Header.Get("Accept-Encoding"))
		assert.NotContains(t, r.URL.String(), "private")
		assert.NotContains(t, r.URL.String(), "param_p1")
		assert.Equal(t, "1", r.URL.Query().Get("readonly"))
		assert.Equal(t, "0", r.URL.Query().Get("allow_ddl"))
		assert.NoError(t, r.ParseMultipartForm(1024*1024))
		assert.Equal(t, "SELECT {p1:String}", r.FormValue("query"))
		assert.Equal(t, "private-bound", r.FormValue("param_p1"))
		fmt.Fprint(w, "[\"value\"]\n[\"String\"]\n[\"private-bound\"]\n")
	})
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	in := query("SELECT {p1:String}", true)
	in.Parameters = []json.RawMessage{json.RawMessage(`"private-bound"`)}
	out, e := Execute(context.Background(), target, secret, in, nil)
	require.NoError(t, e)
	assert.Equal(t, "read_only", out.Transaction)
	assert.Equal(t, "private-bound", *out.Rows[0][0])
	assert.EqualValues(t, 1, calls.Load())
	bad := target
	bad.RootCAPEM = ""
	assert.Error(t, Ping(context.Background(), bad, secret))
	bad = target
	bad.ServerName = "wrong.invalid"
	assert.Error(t, Ping(context.Background(), bad, secret))
	redirect, cred := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://private.invalid/", 302) })
	assert.Error(t, Ping(context.Background(), redirect, cred))
}
func TestHTTPLateErrorsLimitsAndSanitizedNativeCodes(t *testing.T) {
	for _, tc := range []struct {
		name, body, code string
		want             error
	}{{"late", "[\"x\"]\n[\"UInt8\"]\n[1]\nCode: private-error", "", nil}, {"exception", `{"meta":[{"name":"x"}],"data":[[1]],"exception":"private-error"}`, "", nil}, {"wire", strings.Repeat("x", maxWireBytes+1), "", sqlclient.ErrResultLimit}, {"readonly", "private-error", "164", sqlclient.ErrDenied}, {"rows", "private-error", "158", sqlclient.ErrResultLimit}, {"cancel", "private-error", "394", context.DeadlineExceeded}, {"code", "private-error", "bad-private-error", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			target, secret := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.code != "" {
					w.Header().Set("X-ClickHouse-Exception-Code", tc.code)
				}
				io.WriteString(w, tc.body)
			})
			out, e := Execute(context.Background(), target, secret, query("SELECT 1", false), nil)
			require.Error(t, e)
			if tc.want != nil {
				assert.ErrorIs(t, e, tc.want)
			}
			assert.NotContains(t, e.Error(), "private")
			assert.Equal(t, "unknown", out.Transaction)
			if tc.code == "164" {
				assert.Equal(t, "164", out.DatabaseCode)
			}
		})
	}
}
func TestCancellationKillsOnlyGeneratedQueryAndRevocationClearsRows(t *testing.T) {
	started := make(chan struct{})
	killed := make(chan string, 1)
	var id string
	target, secret := tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseMultipartForm(1024*1024))
		sql := r.FormValue("query")
		if strings.HasPrefix(sql, "KILL QUERY") {
			killed <- sql
			fmt.Fprint(w, "[\"status\"]\n[\"String\"]\n")
			return
		}
		id = r.URL.Query().Get("query_id")
		close(started)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := Execute(ctx, target, secret, query("SELECT 1", true), nil); done <- e }()
	<-started
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	select {
	case sql := <-killed:
		assert.Equal(t, "KILL QUERY WHERE query_id = '"+id+"' SYNC", sql)
		assert.Regexp(t, `^jms233-[a-f0-9]{32}$`, id)
	case <-time.After(3 * time.Second):
		t.Fatal("query was not killed")
	}
	target, secret = tlsFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[\"v\"]\n[\"String\"]\n[\"private-row\"]\n")
	})
	var checks atomic.Int32
	out, e := Execute(context.Background(), target, secret, query("SELECT 1", true), func() error {
		if checks.Add(1) > 1 {
			return errors.New("denied")
		}
		return nil
	})
	assert.ErrorIs(t, e, sqlclient.ErrDenied)
	assert.Empty(t, out.Rows)
}
func TestRawCellsPreserveNullBinaryPrecisionAndUnicode(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{{`"hello\t中"`, "hello\t中"}, {`"\uD83D\uDE80"`, "🚀"}, {`"\u0000\u00ff"`, "0x00c3bf"}, {"\"\xff\"", "0xff"}, {"18446744073709551615", "18446744073709551615"}} {
		value, e := cell([]byte(tc.raw))
		require.NoError(t, e)
		assert.Equal(t, tc.want, value)
	}
}
