package servicemaintenance

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestDrainRevisionsIdempotenceActorBindingAndReadiness(t *testing.T) {
	g := workgate.New()
	events := []Event{}
	c, e := New(g, true, func(v Event) error { events = append(events, v); return nil })
	require.NoError(t, e)
	count := 1
	c.SetActivity(func() map[string]int { return map[string]int{"terminal_sessions": count} })
	in := Input{Instance: c.Snapshot().Instance, Revision: 1, RequestID: "drain-request-01", Draining: true}
	out, e := c.Change(in, "admin", "Administrator")
	require.NoError(t, e)
	assert.True(t, out.Draining)
	assert.False(t, out.Ready)
	assert.Equal(t, 2, out.Revision)
	for i := 0; i < 2; i++ {
		out, e = c.Change(in, "admin", "Administrator")
		require.NoError(t, e)
		assert.True(t, out.Replayed)
	}
	assert.Len(t, events, 1)
	_, e = c.Change(in, "other", "Other")
	assert.ErrorIs(t, e, ErrConflict)
	wrong := in
	wrong.Draining = false
	_, e = c.Change(wrong, "admin", "Administrator")
	assert.ErrorIs(t, e, ErrConflict)
	stale := in
	stale.RequestID = "drain-request-02"
	_, e = c.Change(stale, "admin", "Administrator")
	assert.ErrorIs(t, e, ErrConflict)
	count = 0
	assert.True(t, c.Snapshot().Ready)
	cancel := Input{Instance: in.Instance, Revision: 2, RequestID: "drain-cancel-001", Draining: false}
	out, e = c.Change(cancel, "admin", "Administrator")
	require.NoError(t, e)
	assert.False(t, out.Draining)
	out, e = c.Change(in, "admin", "Administrator")
	require.NoError(t, e)
	assert.True(t, out.Replayed)
	assert.False(t, out.Draining)
	assert.Equal(t, 2, out.AppliedRevision)
	assert.Equal(t, 3, out.Revision)
	restarted, e := New(workgate.New(), true, func(Event) error { return nil })
	require.NoError(t, e)
	assert.False(t, restarted.Snapshot().Draining)
	_, e = restarted.Change(in, "admin", "Administrator")
	assert.ErrorIs(t, e, ErrConflict)
}
func TestDrainAuditFailureAndUnsupportedModeLeaveGateOpen(t *testing.T) {
	for _, supported := range []bool{false, true} {
		g := workgate.New()
		c, e := New(g, supported, func(Event) error { return errors.New("disk unavailable") })
		require.NoError(t, e)
		_, e = c.Change(Input{Instance: c.Snapshot().Instance, Revision: 1, RequestID: "drain-request-01", Draining: true}, "admin", "admin")
		require.Error(t, e)
		assert.False(t, g.Closed())
		assert.Equal(t, 1, c.Snapshot().Revision)
	}
}
func TestConcurrentDrainRetriesWriteExactlyOneAuditEvent(t *testing.T) {
	n := 0
	c, e := New(workgate.New(), true, func(Event) error { n++; return nil })
	require.NoError(t, e)
	in := Input{Instance: c.Snapshot().Instance, Revision: 1, RequestID: "concurrent-request", Draining: true}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, e := c.Change(in, "admin", "admin")
			assert.NoError(t, e)
			assert.True(t, out.Draining)
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, n)
}
