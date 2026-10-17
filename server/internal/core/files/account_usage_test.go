package files

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAccountUsageCountsOnlySuccessfulFileActionsAndRejectsBrokenAudit(t *testing.T) {
	audit, e := OpenAuditStore(filepath.Join(t.TempDir(), "audit.jsonl"))
	require.NoError(t, e)
	s := NewService(nil, audit)
	at := time.Now().UTC()
	for _, v := range []Transfer{{AssetID: "account", At: at, Success: true}, {AssetID: "account", At: at.Add(time.Hour), Success: false}, {AssetID: "other", At: at, Success: true}} {
		require.NoError(t, audit.Append(v))
	}
	out, e := s.AccountUsage(context.Background(), map[string]bool{"account": true})
	require.NoError(t, e)
	assert.Equal(t, at, out["account"])
	assert.Len(t, out, 1)
	require.NoError(t, os.WriteFile(audit.path, []byte("{}\n"), 0600))
	_, e = s.AccountUsage(context.Background(), map[string]bool{"account": true})
	assert.Error(t, e)
}
