package releasebundle

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
	"github.com/stretchr/testify/require"
)

func automaticFixture(t *testing.T, mode string) (InstallOptions, AutomaticState, updates.Result, string) {
	t.Helper()
	opt, in := scheduleFixture(t)
	ctx := context.Background()
	v, e := AutomaticStatus(ctx, opt.Root)
	require.NoError(t, e)
	p := v.Policy
	p.Mode = mode
	p.HourUTC = time.Now().UTC().Hour()
	p.MinuteUTC = time.Now().UTC().Minute()
	v, e = SaveAutomaticPolicy(ctx, opt.Root, AutomaticPolicyInput{RequestID: "automatic-policy-001", Policy: p}, "admin", "Admin")
	require.NoError(t, e)
	archive, sha := fixture(t, "install-v1.2.4")
	require.NotEmpty(t, in.ArchiveSHA256)
	// Each fixture includes a timestamp. The feed uses this second complete
	// archive's exact digest, independent of the pre-staged helper candidate.
	result := updates.Result{Status: "update_available", Version: "v1.2.4", ReleaseURL: "https://github.com/" + updates.Repository + "/releases/tag/v1.2.4", PublishedAt: time.Now().UTC(), Artifact: &updates.Artifact{Name: updates.ArchiveName("v1.2.4", runtime.GOOS, runtime.GOARCH), URL: "https://github.com/" + updates.Repository + "/releases/download/v1.2.4/" + updates.ArchiveName("v1.2.4", runtime.GOOS, runtime.GOARCH), SHA256: sha, Bytes: fileSize(t, archive)}}
	return opt, v, result, archive
}
func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	v, e := os.Stat(path)
	require.NoError(t, e)
	return v.Size()
}

type automaticTestFeed struct {
	result            updates.Result
	archive           string
	checkError        error
	download          func(context.Context, string) (updates.Artifact, error)
	checks, downloads int
}

func (f *automaticTestFeed) Check(context.Context, string) (updates.Result, error) {
	f.checks++
	return f.result, f.checkError
}
func (f *automaticTestFeed) Download(ctx context.Context, _ string, path string) (updates.Artifact, error) {
	f.downloads++
	if f.download != nil {
		return f.download(ctx, path)
	}
	data, e := os.ReadFile(f.archive)
	if e != nil {
		return updates.Artifact{}, e
	}
	e = os.WriteFile(path, data, 0600)
	return *f.result.Artifact, e
}
func TestAutomaticPolicyDefaultRevisionReceiptsAndActorBinding(t *testing.T) {
	ctx := context.Background()
	opt, _ := scheduleFixture(t)
	v, e := AutomaticStatus(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, "off", v.Policy.Mode)
	require.Equal(t, 1, v.Policy.Revision)
	in := AutomaticPolicyInput{RequestID: "automatic-policy-001", Policy: v.Policy}
	in.Policy.Mode = "prepare"
	v, e = SaveAutomaticPolicy(ctx, opt.Root, in, "admin", "Admin")
	require.NoError(t, e)
	require.Equal(t, 2, v.Policy.Revision)
	again, e := SaveAutomaticPolicy(ctx, opt.Root, in, "admin", "Admin")
	require.NoError(t, e)
	require.Equal(t, v.Policy, again.Policy)
	require.Len(t, again.Events, 1)
	_, e = SaveAutomaticPolicy(ctx, opt.Root, in, "other", "Other")
	require.ErrorIs(t, e, ErrInstallConflict)
	changed := in
	changed.Policy.Mode = "install"
	_, e = SaveAutomaticPolicy(ctx, opt.Root, changed, "admin", "Admin")
	require.ErrorIs(t, e, ErrInstallConflict)
	in.RequestID = "automatic-policy-002"
	_, e = SaveAutomaticPolicy(ctx, opt.Root, in, "admin", "Admin")
	require.ErrorIs(t, e, ErrInstallConflict)
	in.Policy = v.Policy
	in.Policy.Mode = "off"
	_, e = SaveAutomaticPolicy(ctx, opt.Root, in, "admin", "Admin")
	require.NoError(t, e)
	old := AutomaticPolicyInput{RequestID: "automatic-policy-001", Policy: changed.Policy}
	old.Policy.Mode = "prepare"
	v, e = SaveAutomaticPolicy(ctx, opt.Root, old, "admin", "Admin")
	require.NoError(t, e)
	require.Equal(t, "off", v.Policy.Mode)
}
func TestAutomaticWindowCrossesMidnightAndUsesUTC(t *testing.T) {
	p := AutomaticPolicy{HourUTC: 23, MinuteUTC: 50, WindowMinutes: 30}
	for _, tt := range []struct {
		at   string
		want bool
	}{{"2026-10-20T23:49:59Z", false}, {"2026-10-20T23:50:00Z", true}, {"2026-10-21T00:19:59Z", true}, {"2026-10-21T00:20:00Z", false}, {"2026-10-21T08:10:00+08:00", true}} {
		at, e := time.Parse(time.RFC3339, tt.at)
		require.NoError(t, e)
		require.Equal(t, tt.want, automaticWindow(p, at), tt.at)
	}
}
func TestAutomaticPreparationVerifiesPinnedBytesAndCleansIdempotently(t *testing.T) {
	ctx := context.Background()
	opt, _, result, archive := automaticFixture(t, "prepare")
	v, installed, e := claimAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	feed := &automaticTestFeed{result: result, archive: archive}
	require.NoError(t, prepareAutomatic(ctx, opt.Root, v, installed, feed))
	state, e := AutomaticStatus(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, "ready", state.Phase)
	require.Equal(t, result.Artifact.SHA256, state.Candidate.ArchiveSHA256)
	require.Equal(t, 1, feed.downloads)
	current, e := InstallationStatus(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, opt.ArchiveSHA256, current.Current.ArchiveSHA256)
	require.Empty(t, current.PendingUpgrade)
	require.NoError(t, cleanAutomaticDownloads(ctx, opt.Root))
	require.NoError(t, cleanAutomaticDownloads(ctx, opt.Root))
	s, e := ScheduleState(ctx, opt.Root)
	require.NoError(t, e)
	require.Nil(t, s.Plan)
	_, _, e = claimAutomatic(ctx, opt.Root, time.Now())
	require.ErrorIs(t, e, updates.ErrBusy)
}
func TestAutomaticPreparationFailsClosedOnMetadataBytesAndProtocols(t *testing.T) {
	for _, kind := range []string{"network", "draft-like-version", "missing-artifact", "foreign-url", "changed-digest", "bad-bytes", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			opt, _, result, archive := automaticFixture(t, "prepare")
			feed := &automaticTestFeed{result: result, archive: archive}
			switch kind {
			case "network":
				feed.checkError = updates.ErrNetwork
			case "draft-like-version":
				feed.result.Version = "v1.2.4-beta"
			case "missing-artifact":
				feed.result.Artifact = nil
			case "foreign-url":
				a := *feed.result.Artifact
				a.URL = "https://example.com/package.tar.gz"
				feed.result.Artifact = &a
			case "changed-digest":
				feed.download = func(context.Context, string) (updates.Artifact, error) {
					a := *result.Artifact
					a.SHA256 = strings.Repeat("f", 64)
					return a, nil
				}
			case "bad-bytes":
				feed.download = func(_ context.Context, path string) (updates.Artifact, error) {
					return *result.Artifact, os.WriteFile(path, []byte("changed"), 0600)
				}
			case "legacy":
				a, sha := fixture(t, "install-future-legacy")
				feed.archive = a
				feed.result.Version = "v1.2.4"
				feed.result.Artifact.SHA256 = sha
				feed.result.Artifact.Bytes = fileSize(t, a)
			}
			v, installed, e := claimAutomatic(ctx, opt.Root, time.Now())
			require.NoError(t, e)
			require.NoError(t, prepareAutomatic(ctx, opt.Root, v, installed, feed))
			state, e := AutomaticStatus(ctx, opt.Root)
			require.NoError(t, e)
			require.Equal(t, "failed", state.Phase)
			require.Nil(t, state.Candidate)
			require.NoError(t, cleanAutomaticDownloads(ctx, opt.Root))
			current, e := InstallationStatus(ctx, opt.Root)
			require.NoError(t, e)
			require.Equal(t, opt.ArchiveSHA256, current.Current.ArchiveSHA256)
		})
	}
}
func TestAutomaticPolicyChangeCancelsUnpublishedPreparation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opt, _, result, _ := automaticFixture(t, "prepare")
	run, i, e := claimAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	feed := &automaticTestFeed{result: result, download: func(ctx context.Context, path string) (updates.Artifact, error) {
		state, e := AutomaticStatus(ctx, opt.Root)
		require.NoError(t, e)
		p := state.Policy
		p.Mode = "off"
		_, e = SaveAutomaticPolicy(ctx, opt.Root, AutomaticPolicyInput{RequestID: "automatic-policy-off", Policy: p}, "admin", "Admin")
		require.NoError(t, e)
		cancel()
		return updates.Artifact{}, ctx.Err()
	}}
	require.NoError(t, prepareAutomatic(ctx, opt.Root, run, i, feed))
	state, e := AutomaticStatus(context.Background(), opt.Root)
	require.NoError(t, e)
	require.Equal(t, "off", state.Policy.Mode)
	require.Nil(t, state.Candidate)
	require.NoError(t, cleanAutomaticDownloads(context.Background(), opt.Root))
}
func TestAutomaticQueueBindsPolicyAndNeverReplaysAnAttempt(t *testing.T) {
	ctx := context.Background()
	opt, _, result, archive := automaticFixture(t, "install")
	run, i, e := claimAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	require.NoError(t, prepareAutomatic(ctx, opt.Root, run, i, &automaticTestFeed{result: result, archive: archive}))
	queued, e := queueAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	require.True(t, queued)
	s, e := ScheduleState(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, 2, s.Plan.AutomaticRevision)
	id := s.Plan.ID
	_, e = transitionSchedule(ctx, opt.Root, id, strings.Repeat("a", 32), "scheduled", "failed", "synthetic")
	require.NoError(t, e)
	queued, e = queueAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	require.False(t, queued)
	a, e := AutomaticStatus(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, "attempted", a.Phase)
	s, e = ScheduleState(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, id, s.Plan.ID)
}
func TestAutomaticAttemptSurvivesScheduleReceiptRetention(t *testing.T) {
	ctx := context.Background()
	opt, _, result, archive := automaticFixture(t, "install")
	run, i, e := claimAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	require.NoError(t, prepareAutomatic(ctx, opt.Root, run, i, &automaticTestFeed{result: result, archive: archive}))
	queued, e := queueAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	require.True(t, queued)
	s := installRoot(t, opt.Root)
	schedule, e := s.readSchedule()
	require.NoError(t, e)
	id := schedule.Plan.ID
	schedule.Plan.Phase = "failed"
	schedule.Receipts = nil
	require.NoError(t, s.saveSchedule(schedule))
	v, e := s.readAutomatic()
	require.NoError(t, e)
	v.Phase = "ready"
	require.NoError(t, s.saveAutomatic(v))
	s.close()
	queued, e = queueAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	require.False(t, queued)
	current, e := ScheduleState(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, id, current.Plan.ID)
	v, e = AutomaticStatus(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, "attempted", v.Phase)
	require.Len(t, v.AttemptedDigests, 1)
}
func TestAutomaticRevocationAndCommittedStopPolicyBoundary(t *testing.T) {
	for _, phase := range []string{"scheduled", "draining", "stopping"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			opt, _, result, archive := automaticFixture(t, "install")
			run, i, e := claimAutomatic(ctx, opt.Root, time.Now())
			require.NoError(t, e)
			require.NoError(t, prepareAutomatic(ctx, opt.Root, run, i, &automaticTestFeed{result: result, archive: archive}))
			_, e = queueAutomatic(ctx, opt.Root, time.Now())
			require.NoError(t, e)
			s, e := ScheduleState(ctx, opt.Root)
			require.NoError(t, e)
			worker := strings.Repeat("b", 32)
			if phase != "scheduled" {
				_, e = transitionSchedule(ctx, opt.Root, s.Plan.ID, worker, "scheduled", "draining", "")
				require.NoError(t, e)
			}
			if phase == "stopping" {
				_, e = transitionSchedule(ctx, opt.Root, s.Plan.ID, worker, "draining", "stopping", "")
				require.NoError(t, e)
			}
			a, e := AutomaticStatus(ctx, opt.Root)
			require.NoError(t, e)
			p := a.Policy
			p.Mode = "off"
			_, e = SaveAutomaticPolicy(ctx, opt.Root, AutomaticPolicyInput{RequestID: "automatic-policy-off", Policy: p}, "admin", "Admin")
			if phase == "stopping" {
				require.ErrorIs(t, e, ErrInstallPending)
				return
			}
			require.NoError(t, e)
			_, e = queueAutomatic(ctx, opt.Root, time.Now())
			require.NoError(t, e)
			s, e = ScheduleState(ctx, opt.Root)
			require.NoError(t, e)
			require.Equal(t, "cancelled", s.Plan.Phase)
		})
	}
}
func TestAutomaticRecoveryRefusesForeignDownloadsAndRespectsOwnedReceipts(t *testing.T) {
	ctx := context.Background()
	opt, _, result, _ := automaticFixture(t, "prepare")
	run, _, e := claimAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	path, e := newAutomaticDownload(ctx, opt.Root, run.RunID, result.Artifact.SHA256)
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(path, []byte("partial"), 0600))
	require.NoError(t, cleanAutomaticDownloads(ctx, opt.Root))
	require.NoError(t, cleanAutomaticDownloads(ctx, opt.Root))
	require.NoError(t, recoverAutomatic(ctx, opt.Root))
	state, e := AutomaticStatus(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, "interrupted", state.Error)
	foreign := filepath.Join(opt.Root, ".jms233-maintenance", "prepare-"+strings.Repeat("e", 32))
	require.NoError(t, os.Mkdir(foreign, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(foreign, "retain"), []byte("foreign"), 0600))
	require.ErrorIs(t, cleanAutomaticDownloads(ctx, opt.Root), ErrStageConflict)
	require.FileExists(t, filepath.Join(foreign, "retain"))
}
func TestAutomaticRejectsInvalidPolicy(t *testing.T) {
	opt, original, _, _ := automaticFixture(t, "prepare")
	for _, mutate := range []func(*AutomaticPolicy){func(p *AutomaticPolicy) { p.Mode = "latest" }, func(p *AutomaticPolicy) { p.IntervalHours = 0 }, func(p *AutomaticPolicy) { p.HourUTC = 24 }, func(p *AutomaticPolicy) { p.MinuteUTC = 60 }, func(p *AutomaticPolicy) { p.WindowMinutes = 0 }, func(p *AutomaticPolicy) { p.DrainTimeoutSeconds = 1 }} {
		p := original.Policy
		mutate(&p)
		_, e := SaveAutomaticPolicy(context.Background(), opt.Root, AutomaticPolicyInput{RequestID: "automatic-invalid", Policy: p}, "admin", "Admin")
		require.ErrorIs(t, e, ErrInvalid)
	}
}
func TestAutomaticPolicyStopRaceHasOneAuthoritativeWinner(t *testing.T) {
	ctx := context.Background()
	opt, _, result, archive := automaticFixture(t, "install")
	run, i, e := claimAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	require.NoError(t, prepareAutomatic(ctx, opt.Root, run, i, &automaticTestFeed{result: result, archive: archive}))
	_, e = queueAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	s, e := ScheduleState(ctx, opt.Root)
	require.NoError(t, e)
	worker := strings.Repeat("c", 32)
	_, e = transitionSchedule(ctx, opt.Root, s.Plan.ID, worker, "scheduled", "draining", "")
	require.NoError(t, e)
	a, e := AutomaticStatus(ctx, opt.Root)
	require.NoError(t, e)
	p := a.Policy
	p.Mode = "off"
	var changeError, stopError error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, changeError = SaveAutomaticPolicy(ctx, opt.Root, AutomaticPolicyInput{RequestID: "automatic-race-off", Policy: p}, "admin", "Admin")
	}()
	go func() {
		defer wg.Done()
		_, stopError = transitionSchedule(ctx, opt.Root, s.Plan.ID, worker, "draining", "stopping", "")
	}()
	wg.Wait()
	require.NotEqual(t, changeError == nil, stopError == nil)
	s, e = ScheduleState(ctx, opt.Root)
	require.NoError(t, e)
	if stopError == nil {
		require.Equal(t, "stopping", s.Plan.Phase)
	} else {
		require.Equal(t, "cancelled", s.Plan.Phase)
	}
}
func TestAutomaticWindowExpiryRevokesWaitingPlan(t *testing.T) {
	ctx := context.Background()
	opt, _, result, archive := automaticFixture(t, "install")
	run, i, e := claimAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	require.NoError(t, prepareAutomatic(ctx, opt.Root, run, i, &automaticTestFeed{result: result, archive: archive}))
	_, e = queueAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	_, e = queueAutomatic(ctx, opt.Root, time.Now().Add(4*time.Hour))
	require.NoError(t, e)
	s, e := ScheduleState(ctx, opt.Root)
	require.NoError(t, e)
	require.Equal(t, "cancelled", s.Plan.Phase)
}
func TestAutomaticDownloadCleanupRejectsLinks(t *testing.T) {
	ctx := context.Background()
	opt, _, result, _ := automaticFixture(t, "prepare")
	run, _, e := claimAutomatic(ctx, opt.Root, time.Now())
	require.NoError(t, e)
	path, e := newAutomaticDownload(ctx, opt.Root, run.RunID, result.Artifact.SHA256)
	require.NoError(t, e)
	outside := filepath.Join(t.TempDir(), "preserve")
	require.NoError(t, os.WriteFile(outside, []byte("preserve"), 0600))
	if e = os.Symlink(outside, path); e != nil {
		t.Skip("symlink creation unavailable")
	}
	require.ErrorIs(t, cleanAutomaticDownloads(ctx, opt.Root), ErrStageConflict)
	data, e := os.ReadFile(outside)
	require.NoError(t, e)
	require.Equal(t, "preserve", string(data))
}
