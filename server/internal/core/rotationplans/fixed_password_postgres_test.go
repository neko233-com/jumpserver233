package rotationplans

import (
	"context"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFixedPasswordPostgresTakeoverPreservesSecretAndSaveReceipt(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires PostgreSQL state fixture")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("fixed-rotation-%d", time.Now().UnixNano()))
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
	runner := f.runner()
	runner.AuthorizeFixed = func(Actor) error { return nil }
	execute := runner.Execute
	runner.Execute = func(ctx context.Context, in Intent, guard func() error) (Outcome, error) {
		assert.True(t, in.FixedPassword == fixedInput("").FixedPassword)
		return execute(ctx, in, guard)
	}
	s.SetRunner(runner)
	input := fixedInput("fixed-postgres-receipt")
	p, e := s.SaveRequest(context.Background(), testActor(), "", input, false, true)
	require.NoError(t, e)
	run, e := s.Submit(context.Background(), testActor(), p.ID, "fixed-postgres-run", false)
	require.NoError(t, e)
	writes := 0
	s.saveHook = func([]byte) error {
		writes++
		if writes >= 2 {
			return errors.New("synthetic owned result failure")
		}
		return nil
	}
	s.Tick()
	waitIdle(t, s)
	assert.Equal(t, 1, f.calls)
	s.Close()
	raw, e := a.Load("rotation-plans")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), input.FixedPassword)
	peer, e := Open(path, make([]byte, 32), a)
	require.NoError(t, e)
	defer peer.Close()
	peer.SetRunner(runner)
	replay, e := peer.SaveRequest(context.Background(), testActor(), "", input, false, true)
	require.NoError(t, e)
	assert.Equal(t, p.ID, replay.ID)
	assert.Equal(t, 1, replay.Revision)
	result := drive(t, peer, run.ID)
	assert.Equal(t, "succeeded", result.State)
	assert.Empty(t, peer.data.Runs[run.ID].FixedPassword)
	assert.Equal(t, 1, f.calls)
	other, e := Open(path, make([]byte, 32), b)
	require.NoError(t, e)
	defer other.Close()
	_, e = other.Plan(p.ID)
	assert.ErrorIs(t, e, ErrNotFound)
}
