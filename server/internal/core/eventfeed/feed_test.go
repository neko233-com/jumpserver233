package eventfeed

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestReadRetainedCursorCutoffAndBoundedReplay(t *testing.T) {
	now := time.Now()
	rows := []Event{{ID: Digest("old"), At: now.Add(-time.Hour)}, {ID: Digest("a"), At: now}, {ID: Digest("b"), At: now}}
	first := Read(rows, "", now, 1)
	assert.Equal(t, []Event{rows[1]}, first.Events)
	assert.Equal(t, rows[1].ID, first.Cursor)
	assert.False(t, first.Gap)
	second := Read(rows, first.Cursor, now, 1)
	assert.Equal(t, []Event{rows[2]}, second.Events)
	assert.Empty(t, Read(rows, second.Cursor, now, 1).Events)
	gap := Read(rows, Digest("lost"), now, 10)
	assert.True(t, gap.Gap)
	assert.Len(t, gap.Events, 2)
	assert.Empty(t, Read(rows, "", now, 0).Events)
	allOld := Read(rows, "", now.Add(time.Hour), 10)
	assert.Empty(t, allOld.Events)
	assert.Equal(t, rows[2].ID, allOld.Cursor)
}
func TestSnapshotCyclesForLateInsertsAndDisappearingAnchors(t *testing.T) {
	now := time.Now()
	rows := []Event{{ID: "b", At: now}, {ID: "c", At: now}}
	first := Snapshot(rows, "", now, 1)
	assert.Equal(t, "b", first.Cursor)
	assert.Equal(t, []Event{rows[0]}, first.Events)
	second := Snapshot(rows[1:], first.Cursor, now, 1)
	assert.Equal(t, "", second.Cursor)
	assert.Equal(t, []Event{rows[1]}, second.Events)
	rows = append([]Event{{ID: "a", At: now}}, rows...)
	cycle := Snapshot(rows, second.Cursor, now, 1)
	assert.Equal(t, "a", cycle.Events[0].ID)
	assert.Equal(t, "a b", MetadataText("a\nb", 10))
	assert.Equal(t, "中", MetadataText("中文", 4))
	assert.Empty(t, MetadataText("anything", 0))
}
