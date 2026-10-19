package servicemaintenance

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/require"
)

func TestDrainStopRequiresReadyBindsActorAndSealsCancellation(t *testing.T) {
	g := workgate.New()
	var events []Event
	c, e := New(g, true, func(v Event) error { events = append(events, v); return nil })
	require.NoError(t, e)
	var stopped atomic.Int32
	c.SetStop(func() { stopped.Add(1) })
	in := Input{Instance: c.Snapshot().Instance, Revision: 1, RequestID: "stop-request-001", Draining: true}
	_, _, e = c.Stop(in, "admin", "admin")
	require.ErrorIs(t, e, ErrConflict)
	release, e := g.Acquire("ssh_routes")
	require.NoError(t, e)
	drain := in
	drain.RequestID = "start-request-001"
	_, e = c.Change(drain, "admin", "admin")
	require.NoError(t, e)
	in.Revision = 2
	_, _, e = c.Stop(in, "admin", "admin")
	require.ErrorIs(t, e, ErrConflict)
	release()
	v, fn, e := c.Stop(in, "admin", "admin")
	require.NoError(t, e)
	require.True(t, v.Stopping)
	require.Equal(t, 3, v.Revision)
	require.Zero(t, stopped.Load())
	fn()
	_, _, e = c.Stop(in, "other", "other")
	require.ErrorIs(t, e, ErrConflict)
	v, fn, e = c.Stop(in, "admin", "admin")
	require.NoError(t, e)
	require.True(t, v.Replayed)
	fn()
	require.EqualValues(t, 1, stopped.Load())
	require.Len(t, events, 2)
	require.True(t, events[1].Stopping)
	_, e = c.Change(Input{Instance: in.Instance, Revision: 3, RequestID: "cancel-request-001", Draining: false}, "admin", "admin")
	require.ErrorIs(t, e, ErrConflict)
	require.True(t, g.Closed())
	_, e = c.Change(in, "admin", "admin")
	require.ErrorIs(t, e, ErrConflict)
}
func TestDrainStopAuditFailureAndUnsupportedNeverStop(t *testing.T) {
	fail := false
	c, e := New(workgate.New(), true, func(Event) error {
		if fail {
			return errors.New("unavailable")
		}
		return nil
	})
	require.NoError(t, e)
	in := Input{Instance: c.Snapshot().Instance, Revision: 1, RequestID: "start-request-001", Draining: true}
	_, e = c.Change(in, "a", "a")
	require.NoError(t, e)
	in.Revision = 2
	in.RequestID = "stop-request-001"
	_, _, e = c.Stop(in, "a", "a")
	require.ErrorIs(t, e, ErrUnsupported)
	c.SetStop(func() { t.Fatal("stop callback ran without caller acceptance") })
	fail = true
	_, _, e = c.Stop(in, "a", "a")
	require.Error(t, e)
	require.False(t, c.Snapshot().Stopping)
	require.Equal(t, 2, c.Snapshot().Revision)
}
func TestDrainStopCancelRaceHasExactlyOneWinner(t *testing.T) {
	for i := 0; i < 20; i++ {
		c, e := New(workgate.New(), true, func(Event) error { return nil })
		require.NoError(t, e)
		c.SetStop(func() {})
		in := Input{Instance: c.Snapshot().Instance, Revision: 1, RequestID: "start-request-001", Draining: true}
		_, e = c.Change(in, "a", "a")
		require.NoError(t, e)
		in.Revision = 2
		var wg sync.WaitGroup
		var wins atomic.Int32
		wg.Add(2)
		go func() {
			defer wg.Done()
			v := in
			v.RequestID = "stop-request-001"
			if _, _, e := c.Stop(v, "a", "a"); e == nil {
				wins.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			v := in
			v.RequestID = "cancel-request-001"
			v.Draining = false
			if _, e := c.Change(v, "a", "a"); e == nil {
				wins.Add(1)
			}
		}()
		wg.Wait()
		require.EqualValues(t, 1, wins.Load())
	}
}
