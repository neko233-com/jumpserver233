package accountdiscovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func discoveryFixture(t *testing.T) (*Store, Source, Actor, []hostagent.Account) {
	t.Helper()
	s, e := Open(t.TempDir(), []byte(strings.Repeat("k", 32)), nil)
	require.NoError(t, e)
	return s, Source{AssetID: "asset-qa", Binding: strings.Repeat("a", 64), Account: "ops"}, Actor{ID: "u", Name: "Collector"}, []hostagent.Account{{Username: "ops", UID: 1000, GID: 1000, Home: "/home/ops", Shell: "/bin/bash"}, {Username: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"}}
}
func jobID(n int) string { return fmt.Sprintf("job-%032x", n) }
func TestDiscoveryFindingRejectsMissingReusedUIDAndChangedHost(t *testing.T) {
	s, src, actor, rows := discoveryFixture(t)
	_, e := s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	id := findingID(src.Binding, rows[0])
	f, e := s.Finding(src, id)
	require.NoError(t, e)
	assert.Equal(t, rows[0], f.Account)
	rows[0].UID++
	_, e = s.Import(src, actor, jobID(2), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	_, e = s.Finding(src, id)
	assert.ErrorIs(t, e, ErrInvalid)
	_, e = s.Finding(src, findingID(src.Binding, rows[0]))
	require.NoError(t, e)
	src.Binding = strings.Repeat("b", 64)
	_, e = s.Finding(src, id)
	assert.ErrorIs(t, e, ErrConflict)
}
func TestDiscoveryPersistsReviewsMissingAccountsAndStableIdentity(t *testing.T) {
	s, src, actor, rows := discoveryFixture(t)
	summary, e := s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	assert.Equal(t, 2, summary.New)
	page, e := s.Findings(src, 0, 1)
	require.NoError(t, e)
	assert.Equal(t, 2, page.Total)
	require.Len(t, page.Results, 1)
	id := page.Results[0].ID
	_, e = s.Review(src, actor, id, "ignored", "service account", page.Revision)
	require.NoError(t, e)
	_, e = s.Review(src, actor, id, "acknowledged", "stale", page.Revision)
	assert.ErrorIs(t, e, ErrConflict)
	duplicate, e := s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	assert.Equal(t, summary, duplicate)
	// Same username with a new UID creates a fresh identity, never inheriting ignore.
	rows[0].UID = 1001
	summary, e = s.Import(src, actor, jobID(2), hostagent.AccountDigest(rows[:1]), rows[:1])
	require.NoError(t, e)
	assert.Equal(t, 1, summary.New)
	assert.Equal(t, 2, summary.Missing)
	page, e = s.Findings(src, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 3, page.Total)
	assert.Equal(t, "unreviewed", page.Results[0].Review)
	assert.True(t, page.Results[0].Present)
	old := src
	src.Binding = strings.Repeat("b", 64)
	_, e = s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	assert.ErrorIs(t, e, ErrConflict)
	_, e = s.Import(src, actor, jobID(3), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	page, e = s.Findings(src, 0, 100)
	require.NoError(t, e)
	assert.Equal(t, 2, page.Total)
	assert.NotEqual(t, id, page.Results[0].ID)
	past, e := s.Findings(old, 0, 100)
	require.NoError(t, e)
	assert.Nil(t, past.Last)
	for _, f := range past.Results {
		assert.False(t, f.Present)
	}
	raw, e := os.ReadFile(filepath.Join(s.dir, src.AssetID+".json"))
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "service account")
	assert.NotContains(t, string(raw), "/home/ops")
	reopened, e := Open(s.dir, []byte(strings.Repeat("k", 32)), nil)
	require.NoError(t, e)
	audit, total, e := reopened.Audit(src.AssetID, 0, 10)
	require.NoError(t, e)
	assert.Equal(t, 4, total)
	assert.Equal(t, "collected", audit[0].Action)
	wrong, e := Open(s.dir, []byte(strings.Repeat("w", 32)), nil)
	require.NoError(t, e)
	_, e = wrong.Findings(src, 0, 10)
	require.Error(t, e)
}
func TestDiscoveryFailureCapacityAndOwnerCancellationNeverPublish(t *testing.T) {
	s, src, actor, rows := discoveryFixture(t)
	s.saveHook = func([]byte) error { return errors.New("synthetic storage refusal") }
	_, e := s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	require.Error(t, e)
	s.saveHook = nil
	page, e := s.Findings(src, 0, 20)
	require.NoError(t, e)
	assert.Zero(t, page.Revision)
	assert.Empty(t, page.Results)
	_, e = s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	v, e := s.load(src.AssetID)
	require.NoError(t, e)
	v.Audit = make([]Audit, maxAudit)
	require.NoError(t, s.save(v))
	_, e = s.Import(src, actor, jobID(2), hostagent.AccountDigest(rows), rows)
	assert.ErrorIs(t, e, ErrCapacity)
	page, e = s.Findings(src, 0, 20)
	require.NoError(t, e)
	assert.Equal(t, 1, page.Revision)
	ctx, cancel := context.WithCancel(context.Background())
	s.BindOwner(ctx)
	cancel()
	_, e = s.Findings(src, 0, 10)
	assert.ErrorIs(t, e, ErrClosed)
	for _, bad := range []Source{{AssetID: "../escape", Binding: src.Binding, Account: "ops"}, {AssetID: src.AssetID, Binding: "bad", Account: "ops"}} {
		_, e = s.Findings(bad, 0, 10)
		assert.ErrorIs(t, e, ErrInvalid)
	}
}

func TestDiscoveryReviewAcceptsBilingualNotesAndRejectsControlCharacters(t *testing.T) {
	s, src, actor, rows := discoveryFixture(t)
	_, e := s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	page, e := s.Findings(src, 0, 10)
	require.NoError(t, e)
	note := strings.Repeat("已核对", 170)
	f, e := s.Review(src, actor, page.Results[0].ID, "acknowledged", note, page.Revision)
	require.NoError(t, e)
	assert.Equal(t, note, f.Note)
	_, e = s.Review(src, actor, f.ID, "ignored", "line\nbreak", page.Revision+1)
	assert.ErrorIs(t, e, ErrInvalid)
}
func TestDiscoveryPostgresImportTakeoverAndOrganizationIsolation(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for account discovery state integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	docs, e := storage.OpenPostgres(ctx, dsn, fmt.Sprintf("discovery-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	s, src, actor, rows := discoveryFixture(t)
	_, e = s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	scope, e := docs.Scoped("org-a")
	require.NoError(t, e)
	shared, e := Open(s.dir, []byte(strings.Repeat("k", 32)), scope)
	require.NoError(t, e)
	p, e := shared.Findings(src, 0, 10)
	require.NoError(t, e)
	assert.Equal(t, 2, p.Total)
	takeover, e := Open(t.TempDir(), []byte(strings.Repeat("k", 32)), scope)
	require.NoError(t, e)
	p, e = takeover.Findings(src, 0, 10)
	require.NoError(t, e)
	assert.Equal(t, 2, p.Total)
	other, e := docs.Scoped("org-b")
	require.NoError(t, e)
	isolated, e := Open(t.TempDir(), []byte(strings.Repeat("k", 32)), other)
	require.NoError(t, e)
	p, e = isolated.Findings(src, 0, 10)
	require.NoError(t, e)
	assert.Zero(t, p.Total)
}
