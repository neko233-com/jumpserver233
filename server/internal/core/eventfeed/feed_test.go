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
