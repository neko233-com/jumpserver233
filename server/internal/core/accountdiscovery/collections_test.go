package accountdiscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/agentevents"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScheduledImportPreservesFullHumanAuditAndDeduplicatesLastResult(t *testing.T) {
	s, src, actor, rows := discoveryFixture(t)
	_, e := s.Import(src, actor, jobID(1), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	v, e := s.load(src.AssetID)
	require.NoError(t, e)
	entry := v.Audit[0]
	v.Audit = make([]Audit, maxAudit)
	for i := range v.Audit {
		v.Audit[i] = entry
	}
	require.NoError(t, s.save(v))
	_, e = s.Import(src, actor, jobID(2), hostagent.AccountDigest(rows), rows)
	assert.ErrorIs(t, e, ErrCapacity)
	result, e := s.ImportScheduled(src, actor, jobID(2), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	assert.Equal(t, 2, result.Revision)
	duplicate, e := s.ImportScheduled(src, actor, jobID(2), hostagent.AccountDigest(rows), rows)
	require.NoError(t, e)
	assert.Equal(t, result, duplicate)
	v, e = s.load(src.AssetID)
	require.NoError(t, e)
	assert.Len(t, v.Audit, maxAudit)
	assert.Equal(t, entry, v.Audit[0])
	rows[0].GID++
	_, e = s.ImportScheduled(src, actor, jobID(2), hostagent.AccountDigest(rows), rows)
	assert.ErrorIs(t, e, ErrConflict)
}

func TestCollectionArchiveUsesIndependentAADNamespaceAndOwnerLifecycle(t *testing.T) {
	dir := t.TempDir()
	key := []byte(strings.Repeat("k", 32))
	s, e := Open(dir, key, nil)
	require.NoError(t, e)
	src := Source{AssetID: "asset-qa", Binding: strings.Repeat("a", 64), Account: "ops"}
	actor := Actor{ID: "operator", Name: "Operator"}
	receipt := agentevents.Receipt{PlanID: "plan-00000000000000000000000000000001", Sequence: 1, RunID: "run-first", OwnerID: actor.ID, State: "succeeded", Run: json.RawMessage(`{"state":"succeeded"}`)}
	require.NoError(t, s.ArchiveCollection(src, "Linux", actor, receipt))
	require.NoError(t, s.ArchiveCollection(src, "Linux", actor, receipt))
	p, e := s.Collections(src.AssetID, 0, 10)
	require.NoError(t, e)
	require.Len(t, p.Results, 1)
	assert.Equal(t, actor.ID, p.Results[0].Collector.ID)
	_, e = agentevents.OpenNamespace(filepath.Join(dir, "collections"), key, nil, "agent-events")
	require.Error(t, e)
	reopened, e := Open(dir, key, nil)
	require.NoError(t, e)
	p, e = reopened.Collections(src.AssetID, 0, 10)
	require.NoError(t, e)
	require.Len(t, p.Results, 1)
	ctx, cancel := context.WithCancel(context.Background())
	reopened.BindOwner(ctx)
	cancel()
	receipt.Sequence = 2
	receipt.RunID = "run-second"
	assert.Error(t, reopened.ArchiveCollection(src, "Linux", actor, receipt))
	s.Close()
	_, e = s.Collections(src.AssetID, 0, 10)
	assert.Error(t, e)
}

func TestCollectionArchivePostgresTakeoverDoesNotMixAgentHistoryOrOrganizations(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for scheduled discovery archive takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("scheduled-archive-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	scope, e := docs.Scoped("org-a")
	require.NoError(t, e)
	key := make([]byte, 32)
	s, e := Open(t.TempDir(), key, scope)
	require.NoError(t, e)
	src := Source{AssetID: "asset-qa", Binding: strings.Repeat("a", 64), Account: "ops"}
	actor := Actor{ID: "operator", Name: "Operator"}
	r := agentevents.Receipt{PlanID: "plan-00000000000000000000000000000001", Sequence: 1, RunID: "run-one", OwnerID: actor.ID, State: "succeeded", Run: json.RawMessage(`{"state":"succeeded"}`)}
	require.NoError(t, s.ArchiveCollection(src, "Linux", actor, r))
	s.Close()
	next, e := Open(t.TempDir(), key, scope)
	require.NoError(t, e)
	defer next.Close()
	page, e := next.Collections(src.AssetID, 0, 10)
	require.NoError(t, e)
	require.Len(t, page.Results, 1)
	events, e := agentevents.Open(t.TempDir(), key, scope)
	require.NoError(t, e)
	defer events.Close()
	p, e := events.List(0, 10, func(agentevents.Source) bool { return true })
	require.NoError(t, e)
	assert.Empty(t, p.Results)
	other, e := docs.Scoped("org-b")
	require.NoError(t, e)
	isolated, e := Open(t.TempDir(), key, other)
	require.NoError(t, e)
	defer isolated.Close()
	page, e = isolated.Collections(src.AssetID, 0, 10)
	require.NoError(t, e)
	assert.Empty(t, page.Results)
}
