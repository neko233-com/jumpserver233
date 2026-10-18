package monitoralerts

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/eventfeed"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixture struct {
	now     time.Time
	source  Source
	allowed bool
}

func setup(t *testing.T) (*Service, *fixture, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "monitor.json")
	s, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	t.Cleanup(s.Close)
	f := &fixture{now: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), allowed: true}
	f.source = Source{AssetID: "asset-1", AssetName: "Synthetic host", Binding: eventfeed.Digest("binding-1"), State: "online", At: f.now, Values: map[string]float64{"cpu_percent": 0}}
	s.now = func() time.Time { return f.now }
	s.start = f.now
	s.SetRunner(Runner{Sources: func(context.Context) ([]Source, error) { return []Source{f.source}, nil }, Authorized: func(context.Context, Actor) bool { return f.allowed }})
	return s, f, path
}
func owner() Actor { return Actor{ID: "synthetic-owner", Name: "Synthetic owner"} }
func ruleInput() Input {
	return Input{Name: "Synthetic CPU", Enabled: true, Metric: "cpu_percent", Scope: Scope{All: true}, Threshold: 80, RecoveryThreshold: 50, ForSamples: 2, RecoverySamples: 2, MaxAgeSeconds: 60, RepeatSeconds: 60}
}
func save(t *testing.T, s *Service, in Input) Rule {
	t.Helper()
	r, e := s.SaveRule("", in, owner())
	require.NoError(t, e)
	return r
}
func sample(t *testing.T, s *Service, f *fixture, value float64) {
	t.Helper()
	f.now = f.now.Add(time.Second)
	f.source.At = f.now
	f.source.Values["cpu_percent"] = value
	require.NoError(t, s.Tick())
}
func allAlerts(t *testing.T, s *Service) []Alert {
	t.Helper()
	p, e := s.Alerts(0, 200, "", nil)
	require.NoError(t, e)
	return p.Results
}
func events(t *testing.T, s *Service) []eventfeed.Event {
	t.Helper()
	b, e := s.NotificationFeed(context.Background(), "", time.Time{}, 100)
	require.NoError(t, e)
	return b.Events
}
func TestDistinctSamplesHysteresisAndRecovery(t *testing.T) {
	s, f, _ := setup(t)
	save(t, s, ruleInput())
	sample(t, s, f, 90)
	require.Empty(t, allAlerts(t, s))
	for range 5 {
		require.NoError(t, s.Tick())
	}
	assert.Empty(t, allAlerts(t, s))
	sample(t, s, f, 70)
	sample(t, s, f, 90)
	assert.Empty(t, allAlerts(t, s))
	sample(t, s, f, 95)
	list := allAlerts(t, s)
	require.Len(t, list, 1)
	assert.Equal(t, "firing", list[0].State)
	assert.Len(t, events(t, s), 1)
	sample(t, s, f, 60)
	assert.Equal(t, "firing", allAlerts(t, s)[0].State)
	sample(t, s, f, 40)
	require.NoError(t, s.Tick())
	assert.Equal(t, "firing", allAlerts(t, s)[0].State)
	sample(t, s, f, 45)
	a := allAlerts(t, s)[0]
	assert.Equal(t, "resolved", a.State)
	require.Len(t, events(t, s), 2)
	assert.Equal(t, "monitoring_resolved", events(t, s)[1].State)
	assert.NotEqual(t, a.StartedAt, a.EndedAt)
}
func TestDurationRequiresFreshSamplesAndStaleDataCannotRecover(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.ForSamples = 1
	in.ForSeconds = 10
	save(t, s, in)
	sample(t, s, f, 90)
	f.now = f.now.Add(10 * time.Second)
	require.NoError(t, s.Tick())
	assert.Empty(t, allAlerts(t, s))
	sample(t, s, f, 90)
	require.Len(t, allAlerts(t, s), 1)
	f.now = f.now.Add(61 * time.Second)
	f.source.Values["cpu_percent"] = 1
	require.NoError(t, s.Tick())
	assert.Equal(t, "firing", allAlerts(t, s)[0].State)
	sample(t, s, f, 1)
	assert.Equal(t, "firing", allAlerts(t, s)[0].State)
	sample(t, s, f, 1)
	assert.Equal(t, "resolved", allAlerts(t, s)[0].State)
}
func TestNoDataWarmupAndActualFreshRecovery(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.Metric = "no_data"
	in.Threshold = 1
	in.RecoveryThreshold = 0
	in.ForSamples = 1
	in.RecoverySamples = 1
	in.ForSeconds = 5
	in.MaxAgeSeconds = 30
	f.source.State = "unknown"
	f.source.At = time.Time{}
	save(t, s, in)
	require.NoError(t, s.Tick())
	f.now = f.now.Add(29 * time.Second)
	require.NoError(t, s.Tick())
	assert.Empty(t, allAlerts(t, s))
	f.now = f.now.Add(time.Second)
	require.NoError(t, s.Tick())
	f.now = f.now.Add(5 * time.Second)
	require.NoError(t, s.Tick())
	require.Len(t, allAlerts(t, s), 1)
	assert.Equal(t, "firing", allAlerts(t, s)[0].State)
	f.source.State = "online"
	f.now = f.now.Add(time.Second)
	f.source.At = f.now
	require.NoError(t, s.Tick())
	assert.Equal(t, "resolved", allAlerts(t, s)[0].State)
}
func TestMuteResumeAcknowledgementAndRepeat(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.ForSamples = 1
	r := save(t, s, in)
	r, e := s.MuteRule(r.ID, r.Revision, f.now.Add(20*time.Second), "Synthetic maintenance", owner())
	require.NoError(t, e)
	sample(t, s, f, 90)
	require.Len(t, allAlerts(t, s), 1)
	assert.Empty(t, events(t, s))
	f.now = f.now.Add(20 * time.Second)
	f.source.At = f.now
	require.NoError(t, s.Tick())
	require.Len(t, events(t, s), 1)
	f.now = f.now.Add(60 * time.Second)
	f.source.At = f.now
	require.NoError(t, s.Tick())
	assert.Len(t, events(t, s), 2)
	a := allAlerts(t, s)[0]
	ack, e := s.Acknowledge(a.ID, a.Revision, "Investigating synthetic case", owner())
	require.NoError(t, e)
	assert.Equal(t, owner(), ack.AcknowledgedBy)
	f.now = f.now.Add(60 * time.Second)
	f.source.At = f.now
	require.NoError(t, s.Tick())
	assert.Len(t, events(t, s), 2)
	assert.Equal(t, 1, r.Definition)
}
func TestTargetRevisionAndAuthorityStopTrackingWithoutRecovery(t *testing.T) {
	s, f, _ := setup(t)
	in := ruleInput()
	in.ForSamples = 1
	r := save(t, s, in)
	sample(t, s, f, 90)
	a := allAlerts(t, s)[0]
	f.source.Binding = eventfeed.Digest("binding-2")
	require.NoError(t, s.Tick())
	retired, e := s.Alert(a.ID)
	require.NoError(t, e)
	assert.Equal(t, "retired", retired.State)
	assert.Equal(t, "target_changed", retired.Reason)
	assert.Len(t, events(t, s), 1)
	sample(t, s, f, 90)
	require.Len(t, allAlerts(t, s), 2)
	f.allowed = false
	require.NoError(t, s.Tick())
	assert.Zero(t, s.Health().Firing)
	current, ok := s.Rule(r.ID)
	require.True(t, ok)
	assert.Equal(t, "permission_changed", current.LastError)
	for _, a := range allAlerts(t, s) {
		assert.Equal(t, "retired", a.State)
	}
	assert.Len(t, events(t, s), 2)
}
func TestAtomicStateAndConsumedCursorRollback(t *testing.T) {
	s, f, path := setup(t)
	in := ruleInput()
	in.ForSamples = 1
	save(t, s, in)
	before, e := os.ReadFile(path)
	require.NoError(t, e)
	s.saveHook = func([]byte) error { return errors.New("synthetic disk fault") }
	f.now = f.now.Add(time.Second)
	f.source.At = f.now
	f.source.Values["cpu_percent"] = 90
	require.ErrorContains(t, s.Tick(), "synthetic disk fault")
	assert.Empty(t, allAlerts(t, s))
	assert.Empty(t, events(t, s))
	after, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	s.saveHook = nil
	require.NoError(t, s.Tick())
	require.Len(t, allAlerts(t, s), 1)
	before, e = os.ReadFile(path)
	require.NoError(t, e)
	for range 3 {
		require.NoError(t, s.Tick())
	}
	after, e = os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, before, after)
}
func TestInvalidSamplesNoPartialCommitAndRuleCAS(t *testing.T) {
	s, f, path := setup(t)
	r := save(t, s, ruleInput())
	_, e := s.SaveRule(r.ID, ruleInput(), owner())
	require.ErrorIs(t, e, ErrConflict)
	before, e := os.ReadFile(path)
	require.NoError(t, e)
	f.source.Values["cpu_percent"] = math.NaN()
	require.ErrorIs(t, s.Tick(), ErrInvalid)
	after, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.Equal(t, before, after)
	f.source.Values["cpu_percent"] = 101
	require.ErrorIs(t, s.Tick(), ErrInvalid)
	for _, mutate := range []func(*Input){func(i *Input) { i.RecoveryThreshold = i.Threshold }, func(i *Input) { i.ForSamples = 0 }, func(i *Input) { i.Scope.AssetIDs = []string{"asset"} }, func(i *Input) { i.Metric = "unknown" }, func(i *Input) { i.MaxAgeSeconds = 0 }} {
		in := ruleInput()
		mutate(&in)
		_, e = s.SaveRule("", in, owner())
		require.ErrorIs(t, e, ErrInvalid)
	}
}
func TestEncryptedRestartKeepsFiringAndResetsUnprovenStreaks(t *testing.T) {
	s, f, path := setup(t)
	save(t, s, ruleInput())
	sample(t, s, f, 90)
	raw, e := os.ReadFile(path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "Synthetic CPU")
	assert.NotContains(t, string(raw), "Synthetic host")
	s.Close()
	peer, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer.Close()
	assert.Empty(t, peer.data.Instances)
	s, f, path = setup(t)
	in := ruleInput()
	in.ForSamples = 1
	save(t, s, in)
	sample(t, s, f, 90)
	sample(t, s, f, 20)
	s.Close()
	peer2, e := Open(path, make([]byte, 32), nil)
	require.NoError(t, e)
	defer peer2.Close()
	assert.Equal(t, "firing", allAlerts(t, peer2)[0].State)
	for _, v := range peer2.data.Instances {
		assert.Zero(t, v.RecoverCount)
	}
}
