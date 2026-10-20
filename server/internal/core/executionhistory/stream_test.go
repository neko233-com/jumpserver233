package executionhistory

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummaryStreamKeysetTiesCurrentOwnerAndExclude(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "history.sqlite"), make([]byte, 32), nil)
	require.NoError(t, e)
	defer s.Close()
	at := time.Now().UTC()
	records := make([]Record, 0, 64)
	for i := 0; i < 2401; i++ {
		owner := "owner"
		if i%5 == 0 {
			owner = "other"
		}
		records = append(records, sampleRecord(fmt.Sprintf("job-%06d", i), owner, fmt.Sprintf("request-%06d", i), at))
		if len(records) == 64 {
			require.NoError(t, s.Put(t.Context(), records...))
			records = records[:0]
		}
	}
	if len(records) > 0 {
		require.NoError(t, s.Put(t.Context(), records...))
	}
	n := 0
	previous := ""
	require.NoError(t, s.ReadSummaries(t.Context(), Query{Kind: "job", Exclude: []string{"job-002400"}}, func(v Record) error {
		n++
		if previous != "" {
			assert.Greater(t, previous, v.ID)
		}
		previous = v.ID
		assert.Empty(t, v.Payload)
		return nil
	}))
	assert.Equal(t, 2400, n)
	n = 0
	require.NoError(t, s.ReadSummaries(t.Context(), Query{Kind: "job", Owner: "other"}, func(v Record) error { n++; assert.Equal(t, "other", v.Owner); return nil }))
	assert.Equal(t, 481, n)
}
