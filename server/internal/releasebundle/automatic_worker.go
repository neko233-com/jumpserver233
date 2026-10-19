package releasebundle

import (
	"context"
	"errors"
	"io"
	"runtime"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/updates"
	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
)

type automaticFeed interface {
	Check(context.Context, string) (updates.Result, error)
	Download(context.Context, string, string) (updates.Artifact, error)
}
type automaticTask struct {
	revision int
	cancel   context.CancelFunc
	done     chan error
}
type automaticWorker struct {
	task              *automaticTask
	nextAuthorization time.Time
	nextPoll          time.Time
}

func (w *automaticWorker) stop() {
	if w.task != nil {
		w.task.cancel()
		<-w.task.done
		w.task = nil
	}
}
func (w *automaticWorker) tick(ctx context.Context, opt SupervisorOptions, child observedChild) error {
	if time.Now().Before(w.nextPoll) {
		return nil
	}
	w.nextPoll = time.Now().Add(2 * time.Second)
	if w.task != nil {
		select {
		case e := <-w.task.done:
			w.task = nil
			return e
		default:
		}
		v, e := AutomaticStatus(ctx, opt.Root)
		if e != nil {
			return e
		}
		s, e := ScheduleState(ctx, opt.Root)
		if e != nil {
			return e
		}
		if v.Policy.Revision != w.task.revision || v.Policy.Mode == "off" || activePlan(s.Plan) {
			w.task.cancel()
		}
		return nil
	}
	v, e := AutomaticStatus(ctx, opt.Root)
	if e != nil {
		return e
	}
	s, e := ScheduleState(ctx, opt.Root)
	if e != nil {
		return e
	}
	// Revoking a waiting automatic plan does not require an external request.
	if p := s.Plan; p != nil && p.AutomaticRevision > 0 && (p.Phase == "scheduled" || p.Phase == "draining") && (v.Policy.Mode != "install" || v.Policy.Revision != p.AutomaticRevision) {
		_, e = queueAutomatic(ctx, opt.Root, time.Now())
		return e
	}
	if v.Policy.Mode == "off" || activePlan(s.Plan) || time.Now().Before(w.nextAuthorization) {
		return nil
	}
	wantQueue := v.Phase == "ready" && v.Candidate != nil && v.Policy.Mode == "install" && automaticWindow(v.Policy, time.Now())
	if !wantQueue && !v.NextAttempt.IsZero() && time.Now().Before(v.NextAttempt) {
		return nil
	}
	status, e := maintenanceCall(ctx, opt.Client.MaintenanceStatus)
	if e != nil || !status.Supported || status.PID != child.pid {
		w.nextAuthorization = time.Now().Add(time.Minute)
		return automaticAuthorizationFailure(ctx, opt.Root)
	}
	if status.Draining || status.Stopping {
		return nil
	}
	if wantQueue {
		queued, e := queueAutomatic(ctx, opt.Root, time.Now())
		if e != nil || queued {
			return e
		}
	}
	v, installed, e := claimAutomatic(ctx, opt.Root, time.Now())
	if errors.Is(e, updates.ErrBusy) || errors.Is(e, maintenance.ErrBusy) {
		return nil
	}
	if e != nil {
		return e
	}
	if installed.Current != child.selection {
		return finishAutomatic(ctx, opt.Root, v.RunID, v.Policy.Revision, updates.Result{Status: "not_checked"}, nil, 0, ErrInstallConflict)
	}
	taskCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	task := &automaticTask{revision: v.Policy.Revision, cancel: cancel, done: make(chan error, 1)}
	w.task = task
	factory := opt.automaticFeed
	if factory == nil {
		factory = func(current string) automaticFeed { return updates.NewFeed(current, runtime.GOOS, runtime.GOARCH, nil) }
	}
	go func() {
		defer cancel()
		task.done <- prepareAutomatic(taskCtx, opt.Root, v, installed, factory(installed.Current.Version))
	}()
	return nil
}

func prepareAutomatic(ctx context.Context, path string, state AutomaticState, installed Installation, feed automaticFeed) (returned error) {
	result := updates.Result{Status: "not_checked"}
	var candidate *Selection
	var cause error
	defer func() {
		returned = errors.Join(returned, finishAutomatic(context.WithoutCancel(ctx), path, state.RunID, state.Policy.Revision, result, candidate, installed.Revision, cause))
	}()
	result, cause = feed.Check(ctx, "")
	if cause != nil {
		return nil
	}
	if result.Status != "update_available" {
		return nil
	}
	if result.Artifact == nil || !versionGreater(result.Version, installed.Current.Version) || !updates.ValidateArtifactURL(*result.Artifact, result.Version, runtime.GOOS, runtime.GOARCH) {
		cause = updates.ErrFeed
		return nil
	}
	a := *result.Artifact
	if cause = advanceAutomatic(ctx, path, state.RunID, state.Policy.Revision, "downloading"); cause != nil {
		return nil
	}
	archive, e := newAutomaticDownload(ctx, path, state.RunID, a.SHA256)
	if e != nil {
		cause = e
		return nil
	}
	defer func() {
		if e := cleanAutomaticDownload(context.WithoutCancel(ctx), path, state.RunID); e != nil {
			candidate = nil
			cause = e
			returned = errors.Join(returned, e)
		}
	}()
	actual, e := feed.Download(ctx, result.Version, archive)
	if e != nil {
		cause = e
		return nil
	}
	if actual != a {
		cause = updates.ErrIntegrity
		return nil
	}
	if cause = advanceAutomatic(ctx, path, state.RunID, state.Policy.Revision, "staging"); cause != nil {
		return nil
	}
	staged, e := stageAutomatic(ctx, archive, a.SHA256, path)
	if e != nil {
		cause = e
		return nil
	}
	if staged.Manifest.Version != result.Version || staged.Manifest.PreflightProtocol != 1 || staged.Manifest.ActivationProtocol != 1 {
		cause = updates.ErrIntegrity
		return nil
	}
	candidate = &Selection{a.SHA256, staged.Manifest.Version, staged.Manifest.Commit}
	return nil
}
func automaticDiagnostic(out io.Writer, e error) {
	if out != nil && e != nil && !errors.Is(e, context.Canceled) {
		_, _ = io.WriteString(out, "automatic_preparation_unavailable\n")
	}
}
func stageAutomatic(ctx context.Context, archive, sha, path string) (Staged, error) {
	for attempt := 0; ; attempt++ {
		v, e := Stage(ctx, archive, sha, runtime.GOOS, runtime.GOARCH, path)
		if !errors.Is(e, maintenance.ErrBusy) || attempt >= 50 {
			return v, e
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
