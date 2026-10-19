package workgate

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestAdmissionLeaseFinishesAcrossDrainAndCannotBeReusedAfterRelease(t *testing.T) {
	g := New()
	ctx, release, e := g.Enter(context.Background(), "operation")
	require.NoError(t, e)
	assert.Same(t, g, FromContext(ctx))
	g.SetClosed(true)
	_, _, e = g.Enter(context.Background(), "ssh")
	require.ErrorIs(t, e, ErrDraining)
	child, done, e := g.Enter(ctx, "ssh")
	require.NoError(t, e)
	release()
	release()
	_, _, e = g.Enter(ctx, "replay")
	require.ErrorIs(t, e, ErrDraining)
	_, nested, e := g.Enter(child, "verification")
	require.NoError(t, e)
	nested()
	done()
	done()
	assert.Empty(t, g.Snapshot())
	other := New()
	other.SetClosed(true)
	_, _, e = other.Enter(child, "foreign")
	assert.ErrorIs(t, e, ErrDraining)
	g.SetClosed(false)
	r, e := g.Acquire("new")
	require.NoError(t, e)
	r()
	assert.Empty(t, g.Snapshot())
}
func TestAdmissionConcurrentReleaseAndCloseNeverLosesAnOperation(t *testing.T) {
	g := New()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				release, e := g.Acquire("ssh")
				if e == nil {
					release()
					release()
				} else {
					assert.ErrorIs(t, e, ErrDraining)
				}
			}
		}()
	}
	g.SetClosed(true)
	wg.Wait()
	assert.Empty(t, g.Snapshot())
}
