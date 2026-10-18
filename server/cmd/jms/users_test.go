package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/sessionclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUserCLIAllCommandsAndInvalidFlags(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; fmt.Fprint(w, `{"results":[],"total":0}`) }))
	defer s.Close()
	c, e := sessionclient.New(s.URL, "synthetic-user-cli")
	require.NoError(t, e)
	for _, args := range [][]string{{}, {"unknown"}, {"show"}, {"show", "../escape"}, {"list", "--file", "-"}, {"list", "--limit", "101"}, {"revoke", "user-test"}, {"update", "user-test", "--revision", "2"}, {"list", "extra"}} {
		var out bytes.Buffer
		assert.Error(t, executeUsers(context.Background(), c, args, strings.NewReader(`{}`), &out))
		assert.Empty(t, out.String())
	}
	assert.Zero(t, calls)
	for _, args := range [][]string{{"list"}, {"show", "user-test"}, {"audit"}, {"update", "user-test", "--file", "-"}, {"archive", "user-test", "--revision", "2"}, {"restore", "user-test", "--revision", "2"}, {"revoke", "user-test", "--revision", "2"}, {"batch", "--file", "-"}} {
		raw := `{"revision":2,"name":"name"}`
		if args[0] == "batch" {
			raw = `{"changes":[{"id":"user-test","action":"revoke","revision":2}]}`
		}
		var out bytes.Buffer
		require.NoError(t, executeUsers(context.Background(), c, args, strings.NewReader(raw), &out), args)
		assert.NotEmpty(t, out.String())
	}
	assert.Equal(t, 8, calls)
	for _, raw := range []string{`null`, `{} {}`, `{"unknown":1}`} {
		var out bytes.Buffer
		assert.Error(t, executeUsers(context.Background(), c, []string{"update", "user-test", "--file", "-"}, strings.NewReader(raw), &out))
	}
	assert.Equal(t, 8, calls)
}
