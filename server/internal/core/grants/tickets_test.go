package grants

import (
	"encoding/json"
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ticketInputs() []Input {
	start, end := time.Now().UTC().Add(-time.Second), time.Now().UTC().Add(time.Hour)
	return []Input{{UserID: "requester", AssetID: "asset-a", Account: "synthetic-account", Actions: []string{"connect"}, StartsAt: &start, EndsAt: &end}, {UserID: "requester", NodeID: "node-a", Account: "synthetic-account", Actions: []string{"sftp"}, StartsAt: &start, EndsAt: &end}}
}
func TestTicketGrantAtomicReceiptRequiresWorkflowGateAndNeverRecreatesDeletedGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	s, e := OpenStore(path)
	require.NoError(t, e)
	inputs := ticketInputs()
	id, digest := "ticket-"+strings.Repeat("a", 32), strings.Repeat("b", 64)
	first, e := s.IssueTicket(id, digest, inputs, "synthetic-reviewer")
	require.NoError(t, e)
	require.Len(t, first.GrantIDs, 2)
	assert.False(t, s.Allows("requester", "asset-a", "synthetic-account", "connect", time.Now()))
	s.SetTicketGuard(func(g Grant, _ time.Time) bool { return g.SourceTicketID == id })
	assert.True(t, s.Allows("requester", "asset-a", "synthetic-account", "connect", time.Now()))
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Contains(t, string(raw), `"format": 2`)
	var legacy []Grant
	assert.Error(t, json.Unmarshal(raw, &legacy))
	again, e := s.IssueTicket(id, digest, inputs, "synthetic-reviewer")
	require.NoError(t, e)
	assert.Equal(t, first, again)
	require.Len(t, s.List(), 2)
	require.NoError(t, s.Delete(first.GrantIDs[0]))
	again, e = s.IssueTicket(id, digest, inputs, "synthetic-reviewer")
	require.NoError(t, e)
	assert.Equal(t, "missing", again.State)
	require.Len(t, s.List(), 1)
	peer, e := OpenStore(path)
	require.NoError(t, e)
	recovered, e := peer.TicketReceipt(id)
	require.NoError(t, e)
	assert.Equal(t, "missing", recovered.State)
	revoked, e := peer.RevokeTicket(id, digest, first.ExpiresAt)
	require.NoError(t, e)
	assert.Equal(t, "revoked", revoked.State)
	assert.Empty(t, peer.List())
	_, e = peer.IssueTicket(id, digest, inputs, "synthetic-reviewer")
	assert.ErrorIs(t, e, ErrTicketRevoked)
}
func TestTicketGrantWriteFailureRollsBackWholeBatchAndRevocationTombstoneFencesOldIssuer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	s, e := OpenStore(path)
	require.NoError(t, e)
	id, digest := "ticket-"+strings.Repeat("c", 32), strings.Repeat("d", 64)
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(path), "blocker"), []byte("owned test blocker"), 0600))
	s.path = filepath.Join(filepath.Dir(path), "blocker", "invalid.json")
	_, e = s.IssueTicket(id, digest, ticketInputs(), "synthetic-reviewer")
	require.Error(t, e)
	assert.Empty(t, s.List())
	_, e = s.TicketReceipt(id)
	assert.ErrorIs(t, e, ErrNotFound)
	s.path = path
	receipt, e := s.RevokeTicket(id, digest, time.Now().Add(time.Hour))
	require.NoError(t, e)
	assert.Equal(t, "revoked", receipt.State)
	_, e = s.IssueTicket(id, digest, ticketInputs(), "synthetic-reviewer")
	assert.True(t, errors.Is(e, ErrTicketRevoked))
	_, e = s.IssueTicket(id, strings.Repeat("e", 64), ticketInputs(), "synthetic-reviewer")
	assert.ErrorIs(t, e, ErrTicketConflict)
}
func TestTicketReceiptRetentionPreservesActiveAndRecentBatches(t *testing.T) {
	s, e := OpenStore(filepath.Join(t.TempDir(), "grants.json"))
	require.NoError(t, e)
	id, digest := "ticket-"+strings.Repeat("f", 32), strings.Repeat("a", 64)
	_, e = s.IssueTicket(id, digest, ticketInputs(), "synthetic-reviewer")
	require.NoError(t, e)
	future := time.Now().Add(400 * 24 * time.Hour)
	require.NoError(t, s.PruneTicketReceipts(future))
	_, e = s.TicketReceipt(id)
	require.NoError(t, e)
	_, e = s.RevokeTicket(id, digest, time.Now().Add(time.Hour))
	require.NoError(t, e)
	require.NoError(t, s.PruneTicketReceipts(time.Now().Add(179*24*time.Hour)))
	_, e = s.TicketReceipt(id)
	require.NoError(t, e)
	require.NoError(t, s.PruneTicketReceipts(future))
	_, e = s.TicketReceipt(id)
	assert.ErrorIs(t, e, ErrNotFound)
	assert.Empty(t, s.List())
}
