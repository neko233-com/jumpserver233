package updates

import (
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
)

func TestMaintenanceAuditPersistsAndFailureCannotCloseGate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updates.json")
	feed := NewFeed("v1.0.0", "linux", "amd64", nil)
	s, e := Open(path, nil, feed)
	require.NoError(t, e)
	g := workgate.New()
	c, e := servicemaintenance.New(g, true, s.RecordMaintenance)
	require.NoError(t, e)
	in := servicemaintenance.Input{Instance: c.Snapshot().Instance, Revision: 1, RequestID: "audit-drain-request", Draining: true}
	s.saveHook = func([]byte) error { return errors.New("disk failure") }
	_, e = c.Change(in, "admin", "admin")
	require.Error(t, e)
	assert.False(t, g.Closed())
	assert.Empty(t, s.Audit())
	s.saveHook = nil
	_, e = c.Change(in, "admin", "admin")
	require.NoError(t, e)
	_, e = c.Change(in, "admin", "admin")
	require.NoError(t, e)
	reopened, e := Open(path, nil, feed)
	require.NoError(t, e)
	require.Len(t, reopened.Audit(), 1)
	assert.Equal(t, "maintenance", reopened.Audit()[0].Action)
	rows := reopened.Audit()
	rows[0].Maintenance.Actor = "modified"
	assert.Equal(t, "admin", reopened.Audit()[0].Maintenance.Actor)
}
