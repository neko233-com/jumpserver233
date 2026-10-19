package assetdiscovery

import (
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPolicyMetadataEditPreservesNextOccurrenceAndExhaustedOnce(t *testing.T) {
	st, _, source, _ := fixture(t, Hooks{})
	p := policyFor(t, st, source, false)
	now := time.Now().UTC()
	p.Schedule = &operations.Schedule{Kind: "interval", IntervalSeconds: 60}
	p, e := st.SavePolicy(p.ID, p.PolicyInput, actor(), now)
	require.NoError(t, e)
	original := p.NextRunAt
	p.Name = "renamed interval"
	p, e = st.SavePolicy(p.ID, p.PolicyInput, actor(), now.Add(20*time.Second))
	require.NoError(t, e)
	assert.Equal(t, original, p.NextRunAt)
	p.Schedule = &operations.Schedule{Kind: "once", RunAt: now.Add(time.Minute)}
	p, e = st.SavePolicy(p.ID, p.PolicyInput, actor(), now)
	require.NoError(t, e)
	st.mu.Lock()
	next := copyJSON(st.data)
	done := next.Policies[p.ID]
	done.NextRunAt = time.Time{}
	done.SkippedTriggers = 3
	next.Policies[p.ID] = done
	require.NoError(t, st.saveLocked(next))
	st.mu.Unlock()
	p.Name = "renamed completed once"
	p, e = st.SavePolicy(p.ID, p.PolicyInput, actor(), now.Add(2*time.Minute))
	require.NoError(t, e)
	assert.True(t, p.NextRunAt.IsZero())
	assert.Equal(t, 3, p.SkippedTriggers)
}
func TestPolicyMetadataEditAndReenableNeverReplayDSTFold(t *testing.T) {
	st, _, source, _ := fixture(t, Hooks{})
	p := policyFor(t, st, source, false)
	before := time.Date(2026, 11, 1, 5, 0, 0, 0, time.UTC)
	first := before.Add(30 * time.Minute)
	second := before.Add(90 * time.Minute)
	p.Schedule = &operations.Schedule{Kind: "cron", CronExpression: "30 1 * * *", Timezone: "America/New_York", MisfirePolicy: "coalesce", GraceSeconds: 60, FoldPolicy: "once"}
	p, e := st.SavePolicy(p.ID, p.PolicyInput, actor(), before)
	require.NoError(t, e)
	nextAt, wall, e := operations.AdvanceSchedule(*p.Schedule, first, first, "")
	require.NoError(t, e)
	st.mu.Lock()
	next := copyJSON(st.data)
	consumed := next.Policies[p.ID]
	consumed.NextRunAt = nextAt
	consumed.CalendarWatermark = wall
	next.Policies[p.ID] = consumed
	require.NoError(t, st.saveLocked(next))
	st.mu.Unlock()
	p.Name = "renamed cron"
	p, e = st.SavePolicy(p.ID, p.PolicyInput, actor(), before.Add(time.Hour))
	require.NoError(t, e)
	assert.Equal(t, nextAt, p.NextRunAt)
	assert.Equal(t, wall, p.CalendarWatermark)
	assert.True(t, p.NextRunAt.After(second))
	p.Enabled = false
	p, e = st.SavePolicy(p.ID, p.PolicyInput, actor(), before.Add(time.Hour))
	require.NoError(t, e)
	p.Enabled = true
	p, e = st.SavePolicy(p.ID, p.PolicyInput, actor(), before.Add(time.Hour))
	require.NoError(t, e)
	assert.True(t, p.NextRunAt.After(second))
	assert.Equal(t, wall, p.CalendarWatermark)
}
