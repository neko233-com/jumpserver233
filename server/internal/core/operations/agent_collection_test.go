package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func collectorOp() hostplugins.Operation {
	return hostplugins.Operation{Plugin: "banhack233", Action: "events_collect", Version: "0.2.3", Binding: strings.Repeat("a", 64), Selection: "installed"}
}
func TestCollectorMetadataCannotBeInjectedByPublicPlanJSON(t *testing.T) {
	s, _, _ := setup(t, nil)
	op := collectorOp()
	in := PlanInput{Name: "collector", AssetIDs: []string{"a"}, Kind: "interval", IntervalSeconds: 60, RequestID: "collector"}
	p, e := s.CreateCollector("owner", "owner", in, op, "ops", "QA")
	require.NoError(t, e)
	require.NotNil(t, p.HostPlugin)
	p.HostPlugin.Binding = strings.Repeat("b", 64)
	stored, e := s.Plan(p.ID)
	require.NoError(t, e)
	require.Equal(t, op.Binding, stored.HostPlugin.Binding)
	prepared, revision, e := s.Prepare("owner", PlanInput{Name: stored.Name, AssetIDs: stored.AssetIDs, Command: stored.Command, Kind: stored.Kind, TimeoutSeconds: 60, IntervalSeconds: 60, RequestID: stored.RequestID})
	require.NoError(t, e)
	_, e = s.CreatePlan("owner", "owner", prepared, revision)
	require.ErrorIs(t, e, ErrConflict)
	raw, _ := json.Marshal(map[string]any{"host_plugin": op})
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	require.Error(t, d.Decode(&PlanInput{}))
}
func TestCollectorArchivesBeforeFreeingHotRunsAndContinuesPastCapacity(t *testing.T) {
	s, _, now := setup(t, nil)
	op := collectorOp()
	p, e := s.CreateCollector("owner", "owner", PlanInput{Name: "collector", AssetIDs: []string{"a"}, Kind: "interval", IntervalSeconds: 60, RequestID: "collector"}, op, "ops", "QA")
	require.NoError(t, e)
	require.NoError(t, s.mutate(func(next *state) error {
		for i := 1; i <= 1000; i++ {
			id := fmt.Sprintf("run-%d", i)
			next.Runs[id] = Run{ID: id, PlanID: p.ID, OwnerID: "owner", HostPlugin: clonePlugin(&op), CollectionSequence: uint64(i), CollectionAccount: "ops", Items: []Item{{AssetID: "a", State: "denied"}}, State: "failed"}
		}
		v := next.Plans[p.ID]
		v.CollectionSequence = 1000
		next.Plans[p.ID] = v
		return nil
	}))
	fail := true
	archived := 0
	s.SetCollectorHooks(nil, func(r Run, _ *jobs.Job) error {
		if fail {
			return errors.New("synthetic archive failure")
		}
		archived++
		return nil
	})
	s.Tick()
	_, total := s.Runs("", 0, 1000)
	require.Equal(t, 1000, total)
	fail = false
	*now = now.Add(time.Minute)
	s.Tick()
	require.Equal(t, 1000, archived)
	p, e = s.Plan(p.ID)
	require.NoError(t, e)
	require.True(t, p.Enabled)
	require.Empty(t, p.ErrorCode)
	require.Equal(t, uint64(1001), p.CollectionSequence)
}
func TestCollectorResolvesCredentialBindingBeforeDurableDispatch(t *testing.T) {
	s, js, now := setup(t, nil)
	op := collectorOp()
	js.SetPluginExecutor(func(context.Context, jobs.Job) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{ExitCode: 0}, nil
	})
	p, e := s.CreateCollector("owner", "owner", PlanInput{Name: "collector", AssetIDs: []string{"a"}, Kind: "interval", IntervalSeconds: 60, RequestID: "collector"}, op, "ops", "QA")
	require.NoError(t, e)
	rebound := strings.Repeat("b", 64)
	s.SetCollectorHooks(func(in jobs.Input) (jobs.Input, error) {
		o := in.Plugin.Clone()
		o.Binding = rebound
		in.Plugin = &o
		in.Command = o.Command()
		return in, nil
	}, func(Run, *jobs.Job) error { return errors.New("retain for assertion") })
	*now = now.Add(time.Minute)
	s.Tick()
	r, e := s.Run(func() string { v, _ := s.Plan(p.ID); return v.LastRunID }())
	require.NoError(t, e)
	require.Equal(t, rebound, r.HostPlugin.Binding)
	require.Equal(t, r.HostPlugin.Command(), r.Command)
	require.NotEmpty(t, r.Items[0].JobID)
	j, e := js.Get(r.Items[0].JobID)
	require.NoError(t, e)
	require.Equal(t, rebound, j.Plugin.Binding)
	require.Equal(t, j.Command, r.Command)
}
