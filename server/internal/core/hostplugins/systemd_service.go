package hostplugins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"path"
	"strings"
	"unicode"
)

type borrowedTransport struct{ Transport }

func (b borrowedTransport) Close() error { return nil }
func validJobID(id string) bool {
	if len(id) != 36 || !strings.HasPrefix(id, "job-") {
		return false
	}
	_, e := hex.DecodeString(id[4:])
	return e == nil
}
func lifecycleAction(s string) bool {
	switch s {
	case "install", "start", "stop", "upgrade", "rollback", "protection_apply", "protection_rollback", "agent_update", "autostart_enable", "autostart_disable", "uninstall":
		return true
	}
	return false
}

// Reject a catalog/version mismatch before stopping an otherwise healthy unit.
// Remote manifests and transition checkpoints are still verified by the core.
func (p systemdPlan) validateRequestedVersion(o Operation) error {
	if o.Action == "install" && o.Version != p.record.Version {
		return ErrConflict
	}
	if o.Action == "upgrade" && o.Version != p.record.Version && !CanUpgrade(o.Plugin, p.record.Version, o.Version) {
		return ErrInvalid
	}
	if o.Selection == "" && lifecycleAction(o.Action) && o.Action != "install" && o.Action != "upgrade" && o.Action != "rollback" && o.Version != p.record.Version {
		return ErrConflict
	}
	return nil
}
func managedResult(r Result, e error) (sshclient.ExecResult, error) {
	if e != nil {
		switch {
		case errors.Is(e, ErrSystemd):
			r.Detail = "systemd_unavailable"
		case errors.Is(e, ErrIntegrity):
			r.Detail = "integrity_failed"
		case errors.Is(e, ErrConflict):
			r.Detail = "state_conflict"
		default:
			r.Detail = "transport_or_artifact_failed"
		}
	}
	raw, _ := json.Marshal(r)
	code := 0
	if e != nil {
		code = 1
	}
	return sshclient.ExecResult{Stdout: string(raw), ExitCode: code}, e
}
func (p *systemdPlan) decorate(r *Result) {
	if p.state == "active" && !r.Running {
		p.state = "degraded"
	}
	r.SystemdState = p.state
	r.Supervisor = "systemd"
	if p.record.Desired {
		r.Autostart = true
		r.AutostartState = "enabled"
		if p.state != "active" {
			r.AutostartState = "paused"
		}
	} else if r.Autostart {
		r.Supervisor = "cron"
	}
}
func (s *Service) executeManaged(ctx context.Context, assetID, jobID string, o Operation, cursor hostagent.EventCursor, guards ...func() error) (sshclient.ExecResult, error) {
	if o.Validate() != nil || !validJobID(jobID) || len(guards) > 1 {
		return s.executeCore(ctx, assetID, jobID, o, cursor, guards...)
	}
	if len(guards) == 1 && guards[0] != nil {
		if e := guards[0](); e != nil {
			return managedResult(Result{Plugin: o.Plugin, Action: o.Action, Version: o.Version, State: "failed"}, e)
		}
	}
	h, e := s.open(ctx, assetID)
	if e != nil {
		return managedResult(Result{Plugin: o.Plugin, Action: o.Action, Version: o.Version, State: "failed"}, e)
	}
	defer h.Close()
	if len(guards) == 1 && guards[0] != nil {
		h = &guardedTransport{Transport: h, guard: guards[0]}
	}
	core := *s
	core.open = func(context.Context, string) (Transport, error) { return borrowedTransport{h}, nil }
	invoke := func(op Operation) (sshclient.ExecResult, error) {
		return core.executeCore(ctx, assetID, jobID, op, cursor, guards...)
	}
	home := h.Root()
	if !path.IsAbs(home) || path.Clean(home) != home || len(home) > 2048 || strings.IndexFunc(home, unicode.IsControl) >= 0 {
		return invoke(o)
	}
	dir := path.Join(home, ".jumpserver233/plugins", o.Plugin)
	p, e := loadSystemd(ctx, h, home, dir, o.Plugin)
	if e != nil {
		r := Result{Plugin: o.Plugin, Action: o.Action, Version: o.Version, State: "failed", SystemdState: "conflict"}
		if p != nil {
			p.decorate(&r)
		}
		return managedResult(r, e)
	}
	if p == nil && !strings.HasPrefix(o.Action, "systemd_") {
		return invoke(o)
	}
	if p != nil {
		if e := p.validateRequestedVersion(o); e != nil {
			return managedResult(Result{Plugin: o.Plugin, Action: o.Action, Version: o.Version, State: "failed", SystemdState: p.state}, e)
		}
	}
	op := o.Clone()
	special := strings.HasPrefix(o.Action, "systemd_")
	if special {
		op.Action = "status"
	}
	wasRunning := false
	wanted := p != nil && p.record.Desired
	if wanted && (o.Action == "autostart_enable" || o.Action == "autostart_disable") {
		op.Action = "status"
	}
	if p != nil && lifecycleAction(o.Action) || p != nil && o.Action == "systemd_disable" || p != nil && o.Action == "systemd_enable" {
		state, e := run(ctx, h, p.process()+"printf '%s' \"$running\"")
		if e != nil {
			return managedResult(Result{Plugin: o.Plugin, Action: o.Action, State: "failed"}, e)
		}
		wasRunning = state == "1"
		if e = p.pause(ctx, h); e != nil {
			return managedResult(Result{Plugin: o.Plugin, Action: o.Action, State: "failed"}, e)
		}
	}
	out, e := invoke(op)
	var r Result
	if json.Unmarshal([]byte(out.Stdout), &r) != nil {
		return out, e
	}
	r.Action = o.Action
	if e != nil {
		if p != nil {
			p.state = "paused"
			p.decorate(&r)
		}
		return managedResult(r, e)
	}
	if o.Action == "systemd_status" {
		if p == nil {
			record := systemdRecord{UID: r.UID, Plugin: o.Plugin}
			probe := newSystemdPlan(home, dir, record)
			r.SystemdState = "unavailable"
			available, e := probe.available(ctx, h)
			if e != nil {
				return managedResult(r, e)
			}
			if available {
				r.SystemdState = "disabled"
			}
		} else {
			p.decorate(&r)
		}
		return managedResult(r, nil)
	}
	if o.Action == "systemd_disable" || p != nil && (o.Action == "autostart_disable" || o.Action == "stop" || o.Action == "uninstall") {
		if p != nil {
			if e = p.disable(ctx, h); e != nil {
				return managedResult(r, e)
			}
		}
		if (o.Action == "systemd_disable" || o.Action == "autostart_disable") && wasRunning {
			start := o.Clone()
			start.Action = "start"
			out, e = invoke(start)
			if e != nil {
				return out, e
			}
			if json.Unmarshal([]byte(out.Stdout), &r) != nil {
				return out, ErrInvalid
			}
			r.Action = o.Action
		}
		if o.Action == "uninstall" && p != nil {
			backup := path.Join(dir, jobID+".systemd.previous")
			_, e = run(ctx, h, operationLock(dir)+p.guard()+"[ ! -e "+quote(backup)+" ]; [ ! -L "+quote(backup)+" ]; mv "+quote(path.Join(dir, "systemd.json"))+" "+quote(backup)+"; rm "+quote(p.file)+"; "+p.manager+" daemon-reload; printf removed")
			if e != nil {
				return managedResult(r, e)
			}
		}
		if p != nil {
			p.decorate(&r)
			r.Autostart = false
			r.AutostartState = "disabled"
		} else {
			r.SystemdState = "disabled"
		}
		return managedResult(r, nil)
	}
	if o.Action == "systemd_enable" || wanted && lifecycleAction(o.Action) {
		if r.Autostart {
			return managedResult(r, ErrConflict)
		}
		next, e := buildSystemd(ctx, h, s, home, dir, jobID, r, p)
		if e != nil {
			if p != nil {
				p.state = "paused"
				p.decorate(&r)
			}
			return managedResult(r, e)
		}
		r.Running = true
		r.State = "running"
		next.decorate(&r)
		if r.Protection != nil && r.Protection.Mode == "enforce" {
			b, e := nativeRecovery(r.Platform, dir, next.record.ConfigSHA)
			if e == nil {
				e = b.inspect(ctx, h, &r)
			}
			if e != nil {
				return managedResult(r, e)
			}
		}
		return managedResult(r, nil)
	}
	if p != nil {
		p.decorate(&r)
	}
	return managedResult(r, nil)
}
