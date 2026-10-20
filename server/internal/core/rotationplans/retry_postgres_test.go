package rotationplans

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotationPlanRetryPostgresTakeoverReplaysReceiptWithoutRepeatingSuccess(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("retry-rotation-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	a, e := docs.Scoped("organization-a")
	require.NoError(t, e)
	b, e := docs.Scoped("organization-b")
	require.NoError(t, e)
	t.Cleanup(func() { _ = a.Delete("rotation-plans"); _ = b.Delete("rotation-plans"); _ = docs.Close() })
	_, f, _ := newFixture(t)
	path := filepath.Join(t.TempDir(), "plans.json")
	s, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	s.SetRunner(f.runner())
	p := saveManual(t, s, "account-a", "account-b")
	parent, e := s.Submit(context.Background(), testActor(), p.ID, "retry-pg-source", false)
	require.NoError(t, e)
	f.allowed.Store(false)
	parent = drive(t, s, parent.ID)
	require.Equal(t, "failed", parent.State)
	f.allowed.Store(true)
	input := RetryInput{RequestID: "retry-pg-child", PlanRevision: p.Revision, ItemIDs: []string{parent.Items[0].ID}}
	child, e := s.Retry(context.Background(), testActor(), parent.ID, input, false)
	require.NoError(t, e)
	writes := 0
	s.saveHook = func([]byte) error {
		writes++
		if writes >= 2 {
			return errors.New("owned retry result sink failure")
		}
		return nil
	}
	s.Tick()
	waitIdle(t, s)
	assert.Equal(t, 1, f.calls)
	s.Close()
	peer, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(f.runner())
	again, e := peer.Retry(context.Background(), testActor(), parent.ID, input, false)
	require.NoError(t, e)
	assert.Equal(t, child.ID, again.ID)
	completed := drive(t, peer, child.ID)
	assert.Equal(t, "succeeded", completed.State)
	assert.Equal(t, 1, f.calls)
	original, e := peer.Run(parent.ID)
	require.NoError(t, e)
	assert.Equal(t, child.ID, original.Items[0].RetryRunID)
	assert.Empty(t, original.Items[1].RetryRunID)
	other, e := Open(path, make([]byte, 32), b)
	require.NoError(t, e)
	defer other.Close()
	other.SetRunner(f.runner())
	_, e = other.Retry(context.Background(), testActor(), parent.ID, input, false)
	assert.ErrorIs(t, e, ErrNotFound)
}
