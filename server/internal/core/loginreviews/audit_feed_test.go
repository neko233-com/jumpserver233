package loginreviews

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAuditMetadataCursorGapAndCredentialExclusion(t *testing.T) {
	s, _ := testStore(t)
	r, ticket := testBegin(t, s)
	rows, cursor, gap, e := s.AuditMetadataAfter("")
	require.NoError(t, e)
	require.Len(t, rows, 1)
	assert.False(t, gap)
	assert.Equal(t, "local", rows[0].AuthSource)
	raw, e := json.Marshal(rows)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), ticket)
	assert.NotContains(t, string(raw), "opaque-proof")
	assert.NotContains(t, string(raw), "session_hash")
	approveTest(t, s, r)
	rows, next, gap, e := s.AuditMetadataAfter(cursor)
	require.NoError(t, e)
	require.Len(t, rows, 1)
	assert.Equal(t, Approved, rows[0].Action)
	assert.False(t, gap)
	rows, after, gap, e := s.AuditMetadataAfter(next)
	require.NoError(t, e)
	assert.Empty(t, rows)
	assert.Equal(t, next, after)
	assert.False(t, gap)
	rows, _, gap, e = s.AuditMetadataAfter("expired-anchor")
	require.NoError(t, e)
	assert.Len(t, rows, 2)
	assert.True(t, gap)
}
