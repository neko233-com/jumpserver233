package operations

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestDiscoveryAdvanceScheduleKeepsIntervalOnceAndDSTFoldContracts(t *testing.T) {
	now := instant("2026-10-19T00:00:00Z")
	next, wall, e := AdvanceSchedule(Schedule{Kind: "once", RunAt: now.Add(time.Minute)}, now.Add(time.Minute), now.Add(time.Minute), "")
	require.NoError(t, e)
	assert.True(t, next.IsZero())
	assert.Empty(t, wall)
	next, _, e = AdvanceSchedule(Schedule{Kind: "interval", RunAt: now, IntervalSeconds: 60}, now.Add(190*time.Second), now, "")
	require.NoError(t, e)
	assert.True(t, next.After(now.Add(190*time.Second)))
	first := instant("2026-11-01T05:30:00Z")
	second := instant("2026-11-01T06:30:00Z")
	config := Schedule{Kind: "cron", CronExpression: "30 1 * * *", Timezone: "America/New_York", MisfirePolicy: "coalesce", GraceSeconds: 60, FoldPolicy: "once"}
	next, watermark, e := AdvanceSchedule(config, first, first, "")
	require.NoError(t, e)
	assert.True(t, next.After(second))
	assert.NotEmpty(t, watermark)
	config.FoldPolicy = "both"
	next, _, e = AdvanceSchedule(config, first, first, "")
	require.NoError(t, e)
	assert.Equal(t, second, next)
}
