//go:build linux

package hostagent

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestJournalRotationInterruptionAndReadOnlyPagination(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plugins", "banhack233")
	require.NoError(t, os.MkdirAll(dir, 0700))
	s, e := ReadEvents(dir, EventCursor{}, 64)
	require.NoError(t, e)
	require.True(t, s.Missing)
	_, e = os.Stat(filepath.Join(dir, "agent-events.json"))
	require.True(t, os.IsNotExist(e))
	start, e := beginRepairEvent(dir, SHA([]byte("qa")), "supervisor", 3)
	require.NoError(t, e)
	next, e := beginRepairEvent(dir, SHA([]byte("qa")), "lifecycle", 3)
	require.NoError(t, e)
	require.NotEqual(t, start.Attempt, next.Attempt)
	s, e = ReadEvents(dir, EventCursor{}, 64)
	require.NoError(t, e)
	require.Len(t, s.Events, 3)
	require.Equal(t, "repair_interrupted", s.Events[1].Kind)
	require.Equal(t, start.Attempt, s.Events[1].Attempt)
	for i := 0; i < JournalLimit; i++ {
		_, e = appendEvent(dir, Event{Kind: "repair_completed", Attempt: fmt.Sprintf("%032x", i+1), Trigger: "supervisor", ConfigSHA: SHA([]byte("qa"))})
		require.NoError(t, e)
	}
	s, e = ReadEvents(dir, EventCursor{}, 64)
	require.NoError(t, e)
	require.Equal(t, uint64(4), s.FirstSequence)
	require.True(t, s.More)
	raw, e := os.ReadFile(filepath.Join(dir, "agent-events.json"))
	require.NoError(t, e)
	c := EventCursor{Stream: s.Stream, Sequence: s.Events[63].Sequence, Hash: s.Events[63].Hash}
	s, e = ReadEvents(dir, c, 64)
	require.NoError(t, e)
	require.Equal(t, c.Sequence+1, s.Events[0].Sequence)
	after, e := os.ReadFile(filepath.Join(dir, "agent-events.json"))
	require.NoError(t, e)
	require.Equal(t, raw, after)
}
func TestJournalRefusesFIFOAndSymlinkWithoutBlocking(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plugins", "banhack233")
	require.NoError(t, os.MkdirAll(dir, 0700))
	file := filepath.Join(dir, "agent-events.json")
	require.NoError(t, syscall.Mkfifo(file, 0600))
	_, e := ReadEvents(dir, EventCursor{}, 64)
	require.ErrorIs(t, e, ErrJournal)
	require.NoError(t, os.Remove(file))
	outside := filepath.Join(t.TempDir(), "other")
	require.NoError(t, os.WriteFile(outside, []byte(`{}`), 0600))
	require.NoError(t, os.Symlink(outside, file))
	_, e = ReadEvents(dir, EventCursor{}, 64)
	require.ErrorIs(t, e, ErrJournal)
}
