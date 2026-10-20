package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistoryRefusesOrphanSidecarsWithoutReinitializingData(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm"} {
		for _, emptyMain := range []bool{false, true} {
			t.Run(suffix+map[bool]string{false: "missing", true: "empty"}[emptyMain], func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "history.sqlite")
				if emptyMain {
					require.NoError(t, os.WriteFile(path, nil, 0600))
				}
				raw := []byte("synthetic-uncheckpointed-history")
				require.NoError(t, os.WriteFile(path+suffix, raw, 0600))
				_, e := OpenLocalHistory(t.Context(), path)
				assert.ErrorIs(t, e, ErrHistoryInvalid)
				after, e := os.ReadFile(path + suffix)
				require.NoError(t, e)
				assert.Equal(t, raw, after)
				if emptyMain {
					st, e := os.Stat(path)
					require.NoError(t, e)
					assert.Zero(t, st.Size())
				} else {
					_, e := os.Stat(path)
					assert.True(t, os.IsNotExist(e))
				}
			})
		}
	}
}
