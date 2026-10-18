package monitoralerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRestartRejectsCorruptEncryptedState(t *testing.T) {
	for _, kind := range []string{"threshold", "instance", "duplicate_event", "audit", "envelope", "key"} {
		t.Run(kind, func(t *testing.T) {
			s, f, path := setup(t)
			in := ruleInput()
			in.ForSamples = 1
			r := save(t, s, in)
			sample(t, s, f, 95)
			switch kind {
			case "threshold":
				a := allAlerts(t, s)[0]
				a.RecoveryThreshold = a.Threshold
				s.data.Alerts[a.ID] = a
			case "instance":
				v := s.data.Instances[instanceKey(r.ID, f.source.AssetID)]
				v.Definition++
				s.data.Instances[instanceKey(r.ID, f.source.AssetID)] = v
			case "duplicate_event":
				s.data.Events = append(s.data.Events, s.data.Events[0])
			case "audit":
				s.data.Audit[0].Action = "unknown"
			}
			require.NoError(t, s.persist(s.data))
			s.Close()
			key := make([]byte, 32)
			if kind == "key" {
				key[0] = 1
			}
			if kind == "envelope" {
				require.NoError(t, os.WriteFile(path, []byte("{"), 0600))
			}
			_, e := Open(path, key, nil)
			require.ErrorIs(t, e, ErrInvalid)
		})
	}
}
func TestSourceErrorCancellationAndCloseNeverPublish(t *testing.T) {
	s, _, _ := setup(t)
	save(t, s, ruleInput())
	s.SetRunner(Runner{Sources: func(context.Context) ([]Source, error) { return nil, errors.New("synthetic private source failure") }, Authorized: func(context.Context, Actor) bool { return true }})
	require.Error(t, s.Tick())
	assert.Equal(t, "unavailable", s.Health().ErrorCode)
	assert.Empty(t, events(t, s))
	entered := make(chan struct{})
	s.SetRunner(Runner{Sources: func(ctx context.Context) ([]Source, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() }, Authorized: func(context.Context, Actor) bool { return true }})
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Tick() }()
	<-entered
	s.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close did not join evaluation")
	}
	require.ErrorIs(t, s.Tick(), ErrClosed)
	_, e := s.SaveRule("", ruleInput(), owner())
	assert.ErrorIs(t, e, ErrClosed)
}
func TestDefinitionMuteDeleteScopeAndRetention(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.ForSamples = 1
	in.Scope = Scope{NodeIDs: []string{"parent"}}
	r := save(t, s, in)
	sample(t, s, f, 95)
	require.Empty(t, allAlerts(t, s))
	f.source.Nodes = []string{"child", "parent"}
	sample(t, s, f, 95)
	require.Len(t, allAlerts(t, s), 1)
	r, e := s.MuteRule(r.ID, r.Revision, f.now.Add(time.Minute), "Synthetic maintenance", owner())
	require.NoError(t, e)
	assert.Equal(t, 1, r.Definition)
	in = r.Input
	in.Threshold = 99
	r, e = s.SaveRule(r.ID, in, owner())
	require.NoError(t, e)
	a := allAlerts(t, s)[0]
	assert.Equal(t, "retired", a.State)
	assert.Equal(t, "rule_changed", a.Reason)
	assert.Len(t, events(t, s), 1)
	require.NoError(t, s.DeleteRule(r.ID, r.Revision, owner()))
	f.now = f.now.Add(31 * 24 * time.Hour)
	require.NoError(t, s.mutate(func(*state) error { return nil }))
	assert.Empty(t, allAlerts(t, s))
	assert.Empty(t, events(t, s))
	assert.NotEmpty(t, s.data.Audit)
}
func TestCapacityAndConcurrentCASRemainAtomic(t *testing.T) {
	s, _, _ := setup(t)
	r := save(t, s, ruleInput())
	var wg sync.WaitGroup
	results := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.MuteRule(r.ID, r.Revision, time.Time{}, "", owner()); results <- e }()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else {
			require.ErrorIs(t, e, ErrConflict)
		}
	}
	assert.Equal(t, 1, success)
	for i := 1; i < MaxRules; i++ {
		copy := r
		copy.ID = fmt.Sprintf("rule-%d", i)
		s.data.Rules[copy.ID] = copy
	}
	_, e := s.SaveRule("", ruleInput(), owner())
	assert.ErrorIs(t, e, ErrCapacity)
	assert.Len(t, s.Rules(), MaxRules)
}
func TestPostgresTakeoverAndOrganizationIsolation(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for monitoring takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("monitor-test-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	scoped, e := docs.Scoped("org-monitor")
	require.NoError(t, e)
	defer scoped.Delete("monitor-alerts")
	s, e := Open(filepath.Join(t.TempDir(), "a"), make([]byte, 32), scoped)
	require.NoError(t, e)
	r, e := s.SaveRule("", ruleInput(), owner())
	require.NoError(t, e)
	s.Close()
	peer, e := Open(filepath.Join(t.TempDir(), "b"), make([]byte, 32), scoped)
	require.NoError(t, e)
	defer peer.Close()
	actual, ok := peer.Rule(r.ID)
	require.True(t, ok)
	assert.Equal(t, r, actual)
	other, e := Open(filepath.Join(t.TempDir(), "c"), make([]byte, 32), docs)
	require.NoError(t, e)
	defer other.Close()
	assert.Empty(t, other.Rules())
	raw, e := scoped.LoadOrImport("monitor-alerts", "")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), r.Name)
}
func TestMetadataFeedNeverIncludesMetricsOrComments(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.ForSamples = 1
	save(t, s, in)
	sample(t, s, f, 97)
	a := allAlerts(t, s)[0]
	_, e := s.Acknowledge(a.ID, a.Revision, "Synthetic private investigation", owner())
	require.NoError(t, e)
	b, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	raw, e := json.Marshal(b)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "\"value\"")
	assert.NotContains(t, string(raw), "investigation")
	assert.NotContains(t, string(raw), "threshold")
	b, e = s.NotificationFeed(context.Background(), b.Cursor, time.Time{}, 100)
	require.NoError(t, e)
	assert.Empty(t, b.Events)
}
func TestMultipleRulesShareWatermarkWithoutConsumingEachOthersSamples(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.ForSamples = 2
	save(t, s, in)
	in.Name = "Second synthetic rule"
	save(t, s, in)
	sample(t, s, f, 95)
	assert.Empty(t, allAlerts(t, s))
	require.NoError(t, s.Tick())
	assert.Empty(t, allAlerts(t, s))
	sample(t, s, f, 95)
	require.Len(t, allAlerts(t, s), 2)
	require.NoError(t, s.Tick())
	assert.Len(t, events(t, s), 2)
}
func TestActiveCapacityDefersNewEpisodeButCommitsRecovery(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.ForSamples = 1
	in.RecoverySamples = 1
	r := save(t, s, in)
	sample(t, s, f, 95)
	a := allAlerts(t, s)[0]
	v := s.data.Instances[instanceKey(r.ID, f.source.AssetID)]
	for i := 1; i < MaxAlerts; i++ {
		other := a
		other.ID = fmt.Sprintf("synthetic-alert-%d", i)
		other.AssetID = fmt.Sprintf("synthetic-asset-%d", i)
		s.data.Alerts[other.ID] = other
		track := v
		track.AssetID = other.AssetID
		track.AlertID = other.ID
		s.data.Instances[instanceKey(r.ID, other.AssetID)] = track
	}
	f.now = f.now.Add(time.Second)
	f.source.At = f.now
	f.source.Values = map[string]float64{"cpu_percent": 10}
	newer := f.source
	newer.AssetID = "new-target"
	newer.Binding = eventfeed.Digest("new-target")
	newer.Values = map[string]float64{"cpu_percent": 95}
	s.SetRunner(Runner{Sources: func(context.Context) ([]Source, error) { return []Source{newer, f.source}, nil }, Authorized: func(context.Context, Actor) bool { return true }})
	require.ErrorIs(t, s.Tick(), ErrCapacity)
	recovered, e := s.Alert(a.ID)
	require.NoError(t, e)
	assert.Equal(t, "resolved", recovered.State)
	assert.Equal(t, "capacity", s.Health().ErrorCode)
	require.NoError(t, validState(s.data))
	f.now = f.now.Add(time.Second)
	newer.At = f.now
	require.NoError(t, s.Tick())
	assert.Len(t, s.data.Alerts, MaxAlerts)
	assert.Equal(t, 1, s.Health().Firing)
}
func TestReturnedRuleAndAlertValuesDoNotMutateLiveState(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.ForSamples = 1
	in.Scope = Scope{AssetIDs: []string{f.source.AssetID}}
	r := save(t, s, in)
	r.Scope.AssetIDs[0] = "other"
	actual, _ := s.Rule(r.ID)
	assert.Equal(t, f.source.AssetID, actual.Scope.AssetIDs[0])
	sample(t, s, f, 95)
	a := allAlerts(t, s)[0]
	ack, e := s.Acknowledge(a.ID, a.Revision, "", owner())
	require.NoError(t, e)
	*ack.Value = 0
	actualAlert, e := s.Alert(a.ID)
	require.NoError(t, e)
	assert.Equal(t, 95.0, *actualAlert.Value)
	_, e = s.Acknowledge(a.ID, ack.Revision, "overwrite", owner())
	assert.ErrorIs(t, e, ErrConflict)
}
func BenchmarkMonitoringIdle100Rules500Hosts(b *testing.B) {
	s, e := Open(filepath.Join(b.TempDir(), "a"), make([]byte, 32), nil)
	if e != nil {
		b.Fatal(e)
	}
	defer s.Close()
	now := time.Now().UTC()
	sources := make([]Source, 500)
	for i := range sources {
		sources[i] = Source{AssetID: fmt.Sprintf("asset-%d", i), AssetName: "Synthetic host", Binding: eventfeed.Digest(i), State: "online", At: now, Values: map[string]float64{"cpu_percent": 1}}
	}
	for i := range MaxRules {
		r := Rule{ID: fmt.Sprintf("rule-%d", i), Definition: 1, Input: ruleInput(), Owner: owner(), UpdatedAt: now}
		r.Revision = 1
		s.data.Rules[r.ID] = r
	}
	s.SetRunner(Runner{Sources: func(context.Context) ([]Source, error) { return sources, nil }, Authorized: func(context.Context, Actor) bool { return true }})
	if e = s.Tick(); e != nil {
		b.Fatal(e)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if e = s.Tick(); e != nil {
			b.Fatal(e)
		}
	}
}
