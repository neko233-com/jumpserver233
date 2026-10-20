package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/config"
	"github.com/neko233-com/jumpserver233/server/internal/core/executionhistory"
	"github.com/neko233-com/jumpserver233/server/internal/core/organizations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"modernc.org/sqlite"
)

func TestHistoryPreflightIncludesDisabledArchivedAndDefaultStores(t *testing.T) {
	data := t.TempDir()
	key := make([]byte, 32)
	orgs, e := organizations.Open(filepath.Join(data, "organizations.json"), nil)
	require.NoError(t, e)
	disabled, e := orgs.Save("", organizations.Input{Name: "Disabled", Enabled: false}, "qa-owner")
	require.NoError(t, e)
	archived, e := orgs.Save("", organizations.Input{Name: "Archived", Enabled: true}, "qa-owner")
	require.NoError(t, e)
	require.NoError(t, orgs.Archive(archived.ID, archived.Revision, false, "qa-owner"))
	r := &organizationRuntimes{cfg: &config.Config{DataDir: data, CheckData: true}, key: key, store: orgs}
	require.NoError(t, r.checkHistory(t.Context()))
	_, e = os.Stat(filepath.Join(data, "execution-history.sqlite"))
	assert.True(t, os.IsNotExist(e), "checking an older installation cannot create an empty history")
	for _, id := range []string{organizations.DefaultID, disabled.ID, archived.ID} {
		path := filepath.Join(data, "execution-history.sqlite")
		orgKey := key
		if id != organizations.DefaultID {
			path = filepath.Join(data, "organizations", id, "execution-history.sqlite")
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte("jms233/organization-vault/v1\x00" + id))
			orgKey = mac.Sum(nil)
		}
		s, e := executionhistory.Open(path, orgKey, nil)
		require.NoError(t, e)
		require.NoError(t, s.Put(t.Context(), executionhistory.Record{Kind: "job", ID: "one", Owner: "qa-owner", CreatedAt: time.Now().UTC(), Summary: json.RawMessage(`{"state":"succeeded"}`), Payload: json.RawMessage(`{"state":"succeeded","output":"synthetic-archived-output"}`)}))
		require.NoError(t, s.Close())
	}
	require.NoError(t, r.checkHistory(t.Context()))
	path := filepath.Join(data, "organizations", archived.ID, "execution-history.sqlite")
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	connector, e := sqlite.NewConnector(uri.String())
	require.NoError(t, e)
	db := sql.OpenDB(connector)
	_, e = db.Exec("UPDATE jms233_history_records SET body=zeroblob(64) WHERE id='one'")
	require.NoError(t, e)
	require.NoError(t, db.Close())
	before, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.ErrorIs(t, r.checkHistory(t.Context()), executionhistory.ErrInvalid)
	after, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, sha256.Sum256(before), sha256.Sum256(after), "preflight must not repair or discard damaged archived evidence")
}
