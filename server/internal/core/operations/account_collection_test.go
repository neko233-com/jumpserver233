package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/jobs"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func discoveryPlan(t *testing.T, s *Service, request string) Plan {
	t.Helper()
	p, e := s.CreateDiscoveryCollector("owner", "Operator", PlanInput{Name: "Discovery", AssetIDs: []string{"endpoint"}, Kind: "interval", IntervalSeconds: 60, RequestID: request}, accountdiscovery.Operation{Binding: strings.Repeat("a", 64), Target: strings.Repeat("b", 64)}, "asset-physical", "ops", "Linux")
	require.NoError(t, e)
	return p
}

func TestDiscoveryCollectorPinsIdentityClonesMetadataAndRejectsPublicInjection(t *testing.T) {
	s, _, now := setup(t, nil)
	p := discoveryPlan(t, s, "first")
	assert.Equal(t, *now, p.NextRun)
	assert.Equal(t, 1, p.ConfigRevision)
	require.NotNil(t, p.Discovery)
	assert.Equal(t, p.ID, p.Discovery.PlanID)
	assert.Zero(t, p.Discovery.Sequence)
	assert.Equal(t, "asset-physical", p.Discovery.ParentAssetID)
	duplicate := discoveryPlan(t, s, "first")
	assert.Equal(t, p.ID, duplicate.ID)
	_, e := s.CreateDiscoveryCollector("owner", "Operator", PlanInput{Name: "Other account", AssetIDs: []string{"another-endpoint"}, Kind: "interval", IntervalSeconds: 60, RequestID: "second"}, accountdiscovery.Operation{Binding: strings.Repeat("a", 64), Target: strings.Repeat("b", 64)}, "asset-physical", "other", "Linux")
	assert.ErrorIs(t, e, ErrConflict)
	p.Discovery.Target = strings.Repeat("c", 64)
	p.AssetIDs[0] = "forged"
	stored, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.Equal(t, "endpoint", stored.AssetIDs[0])
	assert.Equal(t, strings.Repeat("b", 64), stored.Discovery.Target)
	raw, _ := json.Marshal(map[string]any{"account_discovery": stored.Discovery})
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	assert.Error(t, decoder.Decode(&PlanInput{}))
	prepared, revision, e := s.Prepare("owner", stored.PlanInput)
	require.NoError(t, e)
	_, e = s.CreatePlan("owner", "Operator", prepared, revision)
	assert.ErrorIs(t, e, ErrConflict)
	assert.ErrorIs(t, s.SetEnabled(p.ID, false), ErrConflict)
}

func TestDiscoveryCollectorRebindsCredentialsDispatchesTypedJobAndArchivesBeforePruning(t *testing.T) {
	var shellCalls atomic.Int32
	s, js, now := setup(t, func(context.Context, string, string) (sshclient.ExecResult, error) {
		shellCalls.Add(1)
		return sshclient.ExecResult{}, errors.New("typed discovery must not use shell executor")
	})
	js.SetDiscoveryExecutor(func(_ context.Context, j jobs.Job) (sshclient.ExecResult, error) {
		require.NotNil(t, j.Discovery)
		assert.NotEmpty(t, j.Discovery.PlanID)
		assert.Equal(t, uint64(1), j.Discovery.Sequence)
		return sshclient.ExecResult{ExitCode: 0, Stdout: `{"observed":2}`}, nil
	})
	p := discoveryPlan(t, s, "run")
	js.SetExecutionGuard(func(j jobs.Job) error {
		if !s.DiscoveryAllowed(j.OperatorID, j.AssetID, j.Discovery) {
			return jobs.ErrAccessDenied
		}
		return nil
	})
	blocked := true
	archived := 0
	s.SetCollectorHooks(func(in jobs.Input) (jobs.Input, error) {
		in.Discovery = cloneDiscovery(in.Discovery)
		in.Discovery.Binding = strings.Repeat("d", 64)
		in.Command = in.Discovery.Command()
		return in, nil
	}, func(r Run, j *jobs.Job) error {
		if blocked {
			return errors.New("archive unavailable")
		}
		require.NotNil(t, j)
		assert.Equal(t, strings.Repeat("d", 64), r.Discovery.Binding)
		assert.Equal(t, r.CollectionSequence, j.Discovery.Sequence)
		archived++
		return nil
	})
	s.Tick()
	stored, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.Equal(t, now.Add(time.Minute), stored.NextRun)
	r, e := s.Run(stored.LastRunID)
	require.NoError(t, e)
	require.NotEmpty(t, r.Items[0].JobID)
	require.Eventually(t, func() bool { j, _ := js.Get(r.Items[0].JobID); return j.State == "succeeded" }, time.Second, time.Millisecond)
	s.Tick()
	s.Tick()
	_, e = js.Get(r.Items[0].JobID)
	require.NoError(t, e)
	_, total := s.Runs("owner", 0, 1000)
	assert.Equal(t, 1, total)
	blocked = false
	s.Tick()
	_, e = js.Get(r.Items[0].JobID)
	assert.ErrorIs(t, e, jobs.ErrNotFound)
	_, total = s.Runs("owner", 0, 1000)
	assert.Zero(t, total)
	assert.Equal(t, 1, archived)
	assert.Zero(t, shellCalls.Load())
}

func TestDiscoveryCollectorPauseCancelsRunningJobAndResumeIsImmediate(t *testing.T) {
	s, js, now := setup(t, nil)
	var started atomic.Bool
	js.SetDiscoveryExecutor(func(ctx context.Context, _ jobs.Job) (sshclient.ExecResult, error) {
		started.Store(true)
		<-ctx.Done()
		return sshclient.ExecResult{ExitCode: 1}, ctx.Err()
	})
	p := discoveryPlan(t, s, "pause")
	js.SetExecutionGuard(func(j jobs.Job) error {
		if !s.DiscoveryAllowed(j.OperatorID, j.AssetID, j.Discovery) {
			return jobs.ErrAccessDenied
		}
		return nil
	})
	s.Tick()
	require.Eventually(t, started.Load, time.Second, time.Millisecond)
	p, e := s.Plan(p.ID)
	require.NoError(t, e)
	r, e := s.Run(p.LastRunID)
	require.NoError(t, e)
	j, e := js.Get(r.Items[0].JobID)
	require.NoError(t, e)
	assert.True(t, s.DiscoveryAllowed("owner", "endpoint", j.Discovery))
	paused, e := s.UpdateDiscoveryCollector(p.ID, 1, false, 60)
	require.NoError(t, e)
	assert.False(t, paused.Enabled)
	assert.Equal(t, 2, paused.ConfigRevision)
	assert.False(t, s.DiscoveryAllowed("owner", "endpoint", j.Discovery))
	require.Eventually(t, func() bool { v, _ := js.Get(j.ID); return v.State == "cancelled" }, time.Second, time.Millisecond)
	r, e = s.Run(r.ID)
	require.NoError(t, e)
	assert.True(t, r.Cancelled)
	_, e = s.UpdateDiscoveryCollector(p.ID, 1, true, 60)
	assert.ErrorIs(t, e, ErrConflict)
	resumed, e := s.UpdateDiscoveryCollector(p.ID, 2, true, 120)
	require.NoError(t, e)
	assert.Equal(t, *now, resumed.NextRun)
	resumed.Discovery.Account = "forged"
	stored, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.Equal(t, "ops", stored.Discovery.Account)
}

func TestDiscoveryCollectorRevocationPausesWithoutSubmittingAndOldEnvelopeCannotReadIt(t *testing.T) {
	s, js, _ := setup(t, nil)
	p := discoveryPlan(t, s, "denied")
	s.submit = func(string, jobs.Input, string) (Submission, error) { return Submission{}, ErrDenied }
	s.Tick()
	p, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.False(t, p.Enabled)
	assert.Equal(t, "access_denied", p.ErrorCode)
	assert.Equal(t, 2, p.ConfigRevision)
	r, e := s.Run(p.LastRunID)
	require.NoError(t, e)
	assert.Equal(t, "failed", r.State)
	assert.Empty(t, r.Items[0].JobID)
	raw, e := os.ReadFile(s.path)
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "asset-physical")
	var box envelope
	require.NoError(t, json.Unmarshal(raw, &box))
	assert.Equal(t, 3, box.Version)
	_, e = s.aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/operations/v1"))
	require.Error(t, e)
	box.Version = 1
	raw, e = json.Marshal(box)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(s.path, raw, 0600))
	_, e = Open(s.path, make([]byte, 32), nil, js)
	require.Error(t, e)
}

func TestDiscoveryCollectorRestartRecoversTypedClaimWithoutReplayingSSH(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(fmt.Sprint(known), func(t *testing.T) {
			s, js, _ := setup(t, nil)
			p := discoveryPlan(t, s, "restart")
			s.submit = nil
			s.Tick()
			r := lastRun(t, s, p)
			var jobID string
			if known {
				j, e := js.Submit(jobInput(r, "endpoint"), "owner", "Operator", "Linux", "ops", "review", "")
				require.NoError(t, e)
				jobID = j.ID
			}
			require.NoError(t, s.mutate(func(next *state) error {
				v := next.Runs[r.ID]
				v.Items[0].State = "dispatching"
				next.Runs[v.ID] = v
				return nil
			}))
			s.Close()
			restored, e := Open(s.path, make([]byte, 32), nil, js)
			require.NoError(t, e)
			defer restored.Close()
			v, e := restored.Run(r.ID)
			require.NoError(t, e)
			assert.Equal(t, r.Discovery, v.Discovery)
			if known {
				assert.Equal(t, jobID, v.Items[0].JobID)
				assert.Equal(t, "pending_review", v.Items[0].State)
			} else {
				assert.Equal(t, "interrupted", v.Items[0].State)
			}
			calls := 0
			restored.submit = func(string, jobs.Input, string) (Submission, error) { calls++; return Submission{}, nil }
			restored.Tick()
			assert.Zero(t, calls)
		})
	}
}

func TestDiscoveryCollectorCanArchiveAFullHotRunWindowBeforeNextDispatch(t *testing.T) {
	s, _, now := setup(t, nil)
	p := discoveryPlan(t, s, "capacity")
	require.NoError(t, s.mutate(func(next *state) error {
		for i := 1; i <= 1000; i++ {
			op := p.Discovery.Clone()
			op.Sequence = uint64(i)
			id := fmt.Sprintf("run-%d", i)
			next.Runs[id] = Run{ID: id, PlanID: p.ID, OwnerID: "owner", Discovery: &op, CollectionSequence: uint64(i), CollectionAccount: "ops", Command: op.Command(), Items: []Item{{AssetID: "endpoint", State: "denied"}}, State: "failed"}
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
			return errors.New("synthetic archive outage")
		}
		assert.NotNil(t, r.Discovery)
		archived++
		return nil
	})
	s.Tick()
	_, total := s.Runs("", 0, 1000)
	assert.Equal(t, 1000, total)
	assert.Zero(t, archived)
	fail = false
	*now = now.Add(time.Minute)
	s.Tick()
	assert.Equal(t, 1000, archived)
	v, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.EqualValues(t, 1001, v.CollectionSequence)
	assert.Empty(t, v.ErrorCode)
}

func TestDiscoveryCollectorPostgresTakeoverPreservesTypedJobsAndOrganizationIsolation(t *testing.T) {
	dsn := os.Getenv("JMS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set JMS_TEST_DATABASE_URL for scheduled discovery takeover")
	}
	docs, e := storage.OpenPostgres(context.Background(), dsn, fmt.Sprintf("scheduled-discovery-%d", time.Now().UnixNano()))
	require.NoError(t, e)
	defer docs.Close()
	scope, e := docs.Scoped("org-a")
	require.NoError(t, e)
	key := make([]byte, 32)
	executor := func(context.Context, string, string) (sshclient.ExecResult, error) {
		return sshclient.ExecResult{}, nil
	}
	js, e := jobs.Open(filepath.Join(t.TempDir(), "jobs"), key, scope, executor)
	require.NoError(t, e)
	defer js.Close()
	s, e := Open(filepath.Join(t.TempDir(), "operations"), key, scope, js)
	require.NoError(t, e)
	p := discoveryPlan(t, s, "postgres")
	s.submit = func(owner string, in jobs.Input, _ string) (Submission, error) {
		j, e := js.Submit(in, owner, "Operator", "Linux", "ops", "review", "")
		return Submission{Job: j}, e
	}
	s.Tick()
	r := lastRun(t, s, p)
	require.NotEmpty(t, r.Items[0].JobID)
	s.Close()
	js.Close()
	js2, e := jobs.Open(filepath.Join(t.TempDir(), "jobs"), key, scope, executor)
	require.NoError(t, e)
	defer js2.Close()
	s2, e := Open(filepath.Join(t.TempDir(), "operations"), key, scope, js2)
	require.NoError(t, e)
	defer s2.Close()
	got, e := s2.Run(r.ID)
	require.NoError(t, e)
	assert.Equal(t, r.Discovery, got.Discovery)
	assert.Equal(t, "pending_review", got.Items[0].State)
	j, e := js2.Get(got.Items[0].JobID)
	require.NoError(t, e)
	assert.Equal(t, got.Discovery, j.Discovery)
	raw, e := scope.Load("operations")
	require.NoError(t, e)
	assert.NotContains(t, string(raw), "asset-physical")
	other, e := docs.Scoped("org-b")
	require.NoError(t, e)
	empty, e := Open(filepath.Join(t.TempDir(), "operations"), key, other, js2)
	require.NoError(t, e)
	defer empty.Close()
	assert.Empty(t, empty.Plans(""))
}

func TestDiscoveryCollectorPauseDuringDispatchRetainsReviewForCancellationOutbox(t *testing.T) {
	s, _, _ := setup(t, nil)
	p := discoveryPlan(t, s, "pause-dispatch")
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s.submit = func(string, jobs.Input, string) (Submission, error) {
		close(entered)
		<-release
		return Submission{ReviewID: "access-review-late"}, nil
	}
	go func() { s.Tick(); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not start")
	}
	_, e := s.UpdateDiscoveryCollector(p.ID, 1, false, 60)
	require.NoError(t, e)
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatch did not finish")
	}
	r := lastRun(t, s, p)
	assert.True(t, r.Cancelled)
	assert.Equal(t, "access-review-late", r.Items[0].ReviewID)
	archived := false
	s.SetCollectorHooks(nil, func(v Run, _ *jobs.Job) error {
		assert.Equal(t, "access-review-late", v.Items[0].ReviewID)
		archived = true
		return nil
	})
	s.Tick()
	assert.True(t, archived)
}

func TestDiscoveryCollectorCommandReviewDenialPausesFutureRuns(t *testing.T) {
	s, js, _ := setup(t, nil)
	p := discoveryPlan(t, s, "command-denial")
	s.submit = func(owner string, in jobs.Input, _ string) (Submission, error) {
		j, e := js.Submit(in, owner, "Operator", "Linux", "ops", "review", "")
		return Submission{Job: j}, e
	}
	s.Tick()
	r := lastRun(t, s, p)
	_, e := js.Review(r.Items[0].JobID, "Reviewer", false)
	require.NoError(t, e)
	s.Tick()
	v, e := s.Plan(p.ID)
	require.NoError(t, e)
	assert.False(t, v.Enabled)
	assert.Equal(t, "access_denied", v.ErrorCode)
}
