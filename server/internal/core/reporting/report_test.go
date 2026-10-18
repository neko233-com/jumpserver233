package reporting

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func testQuery() Query {
	now := time.Now().UTC()
	return Query{From: now.Add(-48 * time.Hour).Truncate(24 * time.Hour), To: now}
}
func source(id string, rows []Entry) Source {
	return Source{ID: id, Scope: "mine", Mode: "history", Read: func(ctx context.Context, emit func(Entry) error) error {
		for _, r := range rows {
			if e := emit(r); e != nil {
				return e
			}
		}
		return nil
	}}
}
func TestAggregationRangeUTCInventoryAndNoFabricatedFailureCounts(t *testing.T) {
	q := testQuery()
	at := q.From.Add(time.Hour)
	s := source("ssh_jobs", []Entry{{at, "succeeded"}, {q.To, "failed"}, {q.From.Add(-time.Second), "failed"}})
	inventory := source("assets", []Entry{{time.Time{}, "unknown"}, {q.To.Add(time.Hour), "offline"}})
	inventory.Mode = "inventory"
	bad := Source{ID: "rdp_sessions", Scope: "mine", Mode: "history", Read: func(context.Context, func(Entry) error) error {
		return errors.New("synthetic private transport detail")
	}}
	out, e := Build(context.Background(), q, []Source{s, inventory, bad}, time.Now())
	require.NoError(t, e)
	assert.True(t, out.Partial)
	require.NotNil(t, out.Sources[0].Matched)
	assert.Equal(t, 1, *out.Sources[0].Matched)
	assert.Equal(t, 3, *out.Sources[0].Retained)
	assert.Equal(t, Count{"succeeded", 1}, out.Sources[0].States[0])
	assert.Equal(t, 2, *out.Sources[1].Matched)
	assert.Empty(t, out.Sources[1].Days)
	assert.Nil(t, out.Sources[2].Matched)
	assert.Empty(t, out.Sources[2].Days)
	var csv bytes.Buffer
	require.NoError(t, CSV(&csv, out))
	assert.NotContains(t, csv.String(), "synthetic private")
	assert.Contains(t, csv.String(), "rdp_sessions,mine,history,unavailable")
}
func TestValidationSourceBoundsContextAndSubset(t *testing.T) {
	q := testQuery()
	bad := q
	bad.Sources = []string{"../secret"}
	require.ErrorIs(t, Validate(bad, time.Now()), ErrInvalid)
	bad = q
	bad.To = bad.From
	require.ErrorIs(t, Validate(bad, time.Now()), ErrInvalid)
	q.Sources = []string{"ssh_jobs"}
	out, e := Build(context.Background(), q, []Source{source("ssh_jobs", nil), source("assets", nil)}, time.Now())
	require.NoError(t, e)
	require.Len(t, out.Sources, 1)
	assert.Equal(t, 0, *out.Sources[0].Matched)
	q.Sources = []string{"unknown"}
	_, e = Build(context.Background(), q, []Source{source("ssh_jobs", nil)}, time.Now())
	require.ErrorIs(t, e, ErrInvalid)
	q = testQuery()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = Build(ctx, q, []Source{source("ssh_jobs", nil)}, time.Now())
	require.ErrorIs(t, e, context.Canceled)
	malicious := source("ssh_jobs", []Entry{{q.From, "password=synthetic-secret"}})
	out, e = Build(context.Background(), q, []Source{malicious}, time.Now())
	require.NoError(t, e)
	assert.Nil(t, out.Sources[0].Matched)
	assert.Empty(t, out.Sources[0].States)
}
func TestCapacityLimitedStreamAndDeniedAreExplicit(t *testing.T) {
	q := testQuery()
	big := Source{ID: "ssh_jobs", Scope: "all", Mode: "history", Read: func(ctx context.Context, emit func(Entry) error) error {
		for range MaxEntries + 1 {
			if e := emit(Entry{q.From, "failed"}); e != nil {
				return e
			}
		}
		return nil
	}}
	out, e := Build(context.Background(), q, []Source{big}, time.Now())
	require.NoError(t, e)
	assert.True(t, out.Partial)
	assert.Equal(t, "limited", out.Sources[0].Status)
	assert.Equal(t, MaxEntries, *out.Sources[0].Matched)
	big.Read = func(context.Context, func(Entry) error) error { return ErrLimit }
	out, e = Build(context.Background(), q, []Source{big}, time.Now())
	require.NoError(t, e)
	assert.Nil(t, out.Sources[0].Matched)
	denied := Source{ID: "account_risks", Scope: "visible", Mode: "history", Status: "denied"}
	out, e = Build(context.Background(), q, []Source{denied}, time.Now())
	require.NoError(t, e)
	assert.False(t, out.Partial)
	assert.Nil(t, out.Sources[0].Retained)
}
func TestDailyBucketsUseUTCAndExclusiveEndpoint(t *testing.T) {
	q := Query{From: time.Date(2026, 10, 1, 23, 30, 0, 0, time.FixedZone("plus8", 8*3600)), To: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)}
	rows := []Entry{{time.Date(2026, 10, 2, 0, 15, 0, 0, time.FixedZone("plus8", 8*3600)), "succeeded"}, {q.To, "succeeded"}}
	out, e := Build(context.Background(), q, []Source{source("ssh_jobs", rows)}, time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC))
	require.NoError(t, e)
	assert.Equal(t, []Day{{"2026-10-01", 1}, {"2026-10-02", 0}}, out.Sources[0].Days)
}
func BenchmarkAggregate100000(b *testing.B) {
	q := testQuery()
	rows := make([]Entry, MaxEntries)
	for i := range rows {
		rows[i] = Entry{q.From.Add(time.Duration(i%3600) * time.Second), fmt.Sprintf("state_%d", i%4)}
	}
	s := source("ssh_jobs", rows)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, e := Build(context.Background(), q, []Source{s}, time.Now()); e != nil {
			b.Fatal(e)
		}
	}
}

func TestReportFinalSourceCancellationAndCSVValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := source("ssh_jobs", nil)
	s.Read = func(context.Context, func(Entry) error) error { cancel(); return ctx.Err() }
	_, e := Build(ctx, testQuery(), []Source{s}, time.Now())
	require.ErrorIs(t, e, context.Canceled)
	var buf bytes.Buffer
	r := Report{Sources: []Stats{{ID: "=formula", Scope: "all", Mode: "history", Status: "ok"}}}
	require.ErrorIs(t, CSV(&buf, r), ErrInvalid)
	assert.Zero(t, buf.Len())
}
