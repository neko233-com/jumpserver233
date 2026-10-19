package releasebundle

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/core/servicemaintenance"
	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
)

// MaintenanceClient uses a revocable global platform identity. It never receives
// an asset password, bypasses authorization, or kills a PID discovered over HTTP.
type MaintenanceClient interface {
	MaintenanceStatus(context.Context) (servicemaintenance.Status, error)
	SetMaintenance(context.Context, servicemaintenance.Input) (servicemaintenance.Status, error)
	StopMaintenance(context.Context, servicemaintenance.Input) (servicemaintenance.Status, error)
}
type SupervisorOptions struct {
	automaticFeed  func(string) automaticFeed
	Root           string
	Client         MaintenanceClient
	ReadPassphrase func() ([]byte, error)
	Stdout, Stderr io.Writer
}
type observedChild struct {
	pid       int
	selection Selection
}

func touchSupervisor(ctx context.Context, path string) error {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return e
	}
	defer s.close()
	if e = ctx.Err(); e != nil {
		return e
	}
	v, e := s.readSchedule()
	if e != nil {
		return e
	}
	v.SupervisorSeenAt = time.Now().UTC()
	return s.saveSchedule(v)
}

// SuperviseInstalled keeps one verified child in the foreground. An OS lock,
// durable one-shot plans and the offline installation lock prevent competing
// supervisors, replayed schedules and uncertain stops from installing twice.
func SuperviseInstalled(ctx context.Context, opt SupervisorOptions) error {
	if opt.Client == nil || opt.ReadPassphrase == nil {
		return ErrInvalid
	}
	s, e := openStagingRoot(opt.Root, runtime.GOOS, runtime.GOARCH, false)
	if e != nil {
		return e
	}
	opt.Root = s.path
	s.close()
	lock, e := maintenance.Acquire(filepath.Join(opt.Root, ".jms233-maintenance", "supervisor"))
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = cleanAutomaticDownloads(ctx, opt.Root); e != nil {
		return e
	}
	if e = recoverAutomatic(ctx, opt.Root); e != nil {
		return e
	}
	worker, e := stageID()
	if e != nil {
		return e
	}
	for {
		installed, e := InstallationStatus(ctx, opt.Root)
		if e != nil {
			return e
		}
		var password []byte
		if installed.PendingUpgrade != "" && installed.ActivationState != "active" {
			password, e = opt.ReadPassphrase()
			if e != nil {
				return errors.New("checkpoint_passphrase_unavailable")
			}
		}
		childCtx, cancel := context.WithCancel(ctx)
		started := make(chan observedChild, 2)
		done := make(chan error, 1)
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			done <- runInstalledObserved(childCtx, opt.Root, password, opt.Stdout, opt.Stderr, func(pid int, selection Selection) { started <- observedChild{pid, selection} })
		}()
		var child observedChild
		select {
		case child = <-started:
		case e = <-done:
			cancel()
			settleStartFailure(opt.Root, worker, e)
			return e
		case <-ctx.Done():
			cancel()
			<-done
			settleStartFailure(opt.Root, worker, ctx.Err())
			return ctx.Err()
		}
		// A completed activation is proof of the selected runtime. A stale plan in
		// any earlier phase is interrupted, never silently retried after restart.
		state, e := ScheduleState(ctx, opt.Root)
		if e != nil {
			cancel()
			<-done
			return e
		}
		if p := state.Plan; activePlan(p) && p.Phase != "scheduled" {
			phase, code := "failed", "supervisor_interrupted"
			if (p.Phase == "awaiting_start" || p.Phase == "installing") && child.selection == p.Target {
				phase, code = "succeeded", ""
			} else if p.Phase == "awaiting_start" {
				code = "activation_rolled_back"
			}
			if _, e = transitionSchedule(ctx, opt.Root, p.ID, worker, p.Phase, phase, code); e != nil {
				cancel()
				<-done
				return e
			}
		}
		restart, e := superviseChild(ctx, opt, worker, child, done)
		if e != nil || !restart {
			cancel()
			<-finished
			return e
		}
		cancel()
	}
}

func settleStartFailure(path, worker string, cause error) {
	ctx := context.Background()
	v, e := ScheduleState(ctx, path)
	if e != nil || !activePlan(v.Plan) || v.Plan.Phase == "scheduled" {
		return
	}
	code := "activation_failed"
	if errors.Is(cause, ErrActivationCommitted) {
		code = "activation_committed"
	}
	if errors.Is(cause, context.Canceled) {
		code = "supervisor_interrupted"
	}
	_, _ = transitionSchedule(ctx, path, v.Plan.ID, worker, v.Plan.Phase, "failed", code)
}

func superviseChild(ctx context.Context, opt SupervisorOptions, worker string, child observedChild, done <-chan error) (bool, error) {
	automatic := &automaticWorker{}
	defer automatic.stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var heartbeat time.Time
	for {
		select {
		case e := <-done:
			return false, e
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
		}
		automaticDiagnostic(opt.Stderr, automatic.tick(ctx, opt, child))
		if time.Since(heartbeat) > 5*time.Second {
			if e := touchSupervisor(ctx, opt.Root); e != nil {
				if errors.Is(e, maintenance.ErrBusy) {
					continue
				}
				return false, e
			}
			heartbeat = time.Now()
		}
		state, e := ScheduleState(ctx, opt.Root)
		if errors.Is(e, maintenance.ErrBusy) {
			continue
		}
		if e != nil {
			return false, e
		}
		p := state.Plan
		if p == nil || p.Phase != "scheduled" || time.Now().Before(p.Input.NotBefore) {
			continue
		}
		automatic.stop()
		stopped, e := performScheduledInstall(ctx, opt, worker, child, *p, done)
		if e != nil || stopped {
			return stopped, e
		}
	}
}
func maintenanceCall[T any](ctx context.Context, fn func(context.Context) (T, error)) (T, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return fn(bounded)
}
func performScheduledInstall(ctx context.Context, opt SupervisorOptions, worker string, child observedChild, p InstallPlan, done <-chan error) (bool, error) {
	fail := func(from, code string) error {
		_, e := transitionSchedule(context.WithoutCancel(ctx), opt.Root, p.ID, worker, from, "failed", code)
		return e
	}
	password, e := opt.ReadPassphrase()
	defer clear(password)
	if e != nil || len(password) < 12 || len(password) > 1024 {
		return false, fail("scheduled", "checkpoint_passphrase_unavailable")
	}
	installed, e := InstallationStatus(ctx, opt.Root)
	if errors.Is(e, maintenance.ErrBusy) {
		return false, nil
	}
	if e != nil || installed.Revision != p.Input.InstallationRevision || installed.Current != child.selection || installed.PendingUpgrade != "" {
		return false, fail("scheduled", "installation_changed")
	}
	if _, e = InspectStage(ctx, opt.Root, p.Input.ArchiveSHA256, runtime.GOOS, runtime.GOARCH); e != nil {
		if errors.Is(e, maintenance.ErrBusy) {
			return false, nil
		}
		return false, fail("scheduled", "candidate_changed")
	}
	status, e := maintenanceCall(ctx, opt.Client.MaintenanceStatus)
	if e != nil || !status.Supported || status.PID != child.pid || status.Draining || status.Stopping {
		return false, fail("scheduled", "maintenance_unavailable")
	}
	if _, e = transitionSchedule(ctx, opt.Root, p.ID, worker, "scheduled", "draining", ""); e != nil {
		if errors.Is(e, ErrInstallConflict) {
			return false, nil
		}
		return false, e
	}
	in := servicemaintenance.Input{Instance: status.Instance, Revision: status.Revision, RequestID: "schedule-" + p.ID, Draining: true}
	status, e = maintenanceCall(ctx, func(ctx context.Context) (servicemaintenance.Status, error) {
		return opt.Client.SetMaintenance(ctx, in)
	})
	if e != nil { // Retry the exact receipt once; no new capability on ambiguity.
		status, e = maintenanceCall(ctx, func(ctx context.Context) (servicemaintenance.Status, error) {
			return opt.Client.SetMaintenance(ctx, in)
		})
	}
	if e != nil || status.Instance != in.Instance || status.PID != child.pid || !status.Draining || status.Stopping || status.AppliedRevision != status.Revision {
		return false, fail("draining", "drain_start_failed")
	}
	drainRevision := status.Revision
	reopen := func() error {
		v, e := maintenanceCall(context.WithoutCancel(ctx), opt.Client.MaintenanceStatus)
		if e != nil {
			return e
		}
		if v.Instance != in.Instance || v.Revision != drainRevision || !v.Draining || v.Stopping {
			return nil
		}
		_, e = maintenanceCall(context.WithoutCancel(ctx), func(ctx context.Context) (servicemaintenance.Status, error) {
			return opt.Client.SetMaintenance(ctx, servicemaintenance.Input{Instance: in.Instance, Revision: drainRevision, RequestID: "cancel-" + p.ID, Draining: false})
		})
		return e
	}
	timer := time.NewTimer(time.Duration(p.Input.DrainTimeoutSeconds) * time.Second)
	defer timer.Stop()
	for {
		if p.AutomaticRevision > 0 {
			if _, e = queueAutomatic(ctx, opt.Root, time.Now()); e != nil {
				_ = reopen()
				return false, e
			}
		}
		current, e := ScheduleState(ctx, opt.Root)
		if e != nil {
			_ = reopen()
			return false, e
		}
		if current.Plan == nil || current.Plan.ID != p.ID || current.Plan.Phase != "draining" {
			if e = reopen(); e != nil && current.Plan != nil && current.Plan.ID == p.ID && current.Plan.Phase == "cancelled" {
				_, _ = transitionSchedule(context.WithoutCancel(ctx), opt.Root, p.ID, worker, "cancelled", "cancelled", "reopen_failed")
			}
			return false, nil
		}
		if status.Instance != in.Instance || status.PID != child.pid || status.Revision != drainRevision || !status.Draining || status.Stopping {
			return false, fail("draining", "maintenance_changed")
		}
		if status.Ready {
			break
		}
		select {
		case <-ctx.Done():
			_ = reopen()
			return false, ctx.Err()
		case e := <-done:
			return false, errors.Join(ErrInstallPending, e, fail("draining", "service_exited"))
		case <-timer.C:
			code := "drain_timeout"
			if reopen() != nil {
				code = "reopen_failed"
			}
			return false, fail("draining", code)
		case <-time.After(250 * time.Millisecond):
		}
		status, e = maintenanceCall(ctx, opt.Client.MaintenanceStatus)
		if e != nil {
			_ = reopen()
			return false, fail("draining", "maintenance_unavailable")
		}
	}
	if _, e = transitionSchedule(ctx, opt.Root, p.ID, worker, "draining", "stopping", ""); e != nil {
		_ = reopen()
		if errors.Is(e, ErrInstallConflict) {
			return false, nil
		}
		return false, e
	}
	stopIn := servicemaintenance.Input{Instance: in.Instance, Revision: drainRevision, RequestID: "stop-" + p.ID, Draining: true}
	ack, e := maintenanceCall(ctx, func(ctx context.Context) (servicemaintenance.Status, error) {
		return opt.Client.StopMaintenance(ctx, stopIn)
	})
	if e != nil || ack.Instance != in.Instance || ack.PID != child.pid || !ack.Stopping {
		_ = reopen()
		return false, fail("stopping", "stop_unconfirmed")
	}
	select {
	case e = <-done:
		if e != nil {
			return false, errors.Join(e, fail("stopping", "service_stop_failed"))
		}
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(30 * time.Second):
		return false, errors.Join(ErrInstallPending, fail("stopping", "service_stop_timeout"))
	}
	if _, e = transitionSchedule(ctx, opt.Root, p.ID, worker, "stopping", "installing", ""); e != nil {
		return false, e
	}
	r, e := Install(ctx, InstallOptions{Root: opt.Root, DataDir: installed.DataDir, ArchiveSHA256: p.Target.ArchiveSHA256, Revision: installed.Revision, RequestID: "schedule-" + p.ID, SourceVersion: installed.Current.Version, ExternalVaultKey: os.Getenv("JMS_VAULT_KEY"), Passphrase: password})
	if e != nil {
		if saveErr := fail("installing", "installation_failed"); saveErr != nil {
			return false, errors.Join(e, saveErr)
		}
		if r.Status == "rolled_back" && r.Current.valid() {
			return true, nil
		}
		return false, e
	}
	if r.Status != "selected" || r.Current != p.Target {
		return false, errors.Join(ErrInstallConflict, fail("installing", "installation_changed"))
	}
	_, e = transitionSchedule(ctx, opt.Root, p.ID, worker, "installing", "awaiting_start", "")
	return true, e
}
