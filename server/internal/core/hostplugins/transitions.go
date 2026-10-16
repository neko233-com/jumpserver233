package hostplugins

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path"
	"strings"
)

type versionCheckpoint struct {
	From      string `json:"from"`
	To        string `json:"to"`
	FromSHA   string `json:"from_sha"`
	ToSHA     string `json:"to_sha"`
	ConfigSHA string `json:"config_sha"`
	Running   bool   `json:"running"`
	Autostart bool   `json:"autostart"`
}

func checkpoint(ctx context.Context, h Transport, dir, name string) (versionCheckpoint, string, error) {
	file := quote(path.Join(dir, name))
	raw, e := run(ctx, h, "[ ! -L "+file+" ]; if [ -f "+file+" ]; then [ \"$(stat -c %s "+file+")\" -le 2048 ]; cat "+file+"; else printf none; fi")
	if e != nil || raw == "none" {
		return versionCheckpoint{}, raw, e
	}
	var c versionCheckpoint
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF || !validDigest(c.FromSHA) || !validDigest(c.ToSHA) || !validDigest(c.ConfigSHA) {
		return c, raw, ErrIntegrity
	}
	return c, raw, nil
}

func (s *Service) transition(ctx context.Context, h Transport, jobID string, o Operation, current Definition, base, dir, config, configHash string, r *Result) error {
	if !r.Installed {
		return ErrConflict
	}
	if r.Protection != nil && r.Protection.Mode == "enforce" {
		if e := protectionPreflight(ctx, h, dir, *r.Protection); e != nil {
			return e
		}
	}
	c, intent, e := checkpoint(ctx, h, dir, "upgrade.intent")
	if e != nil {
		return e
	}
	pending := intent != "none"
	if !pending && o.Action == "rollback" {
		c, _, e = checkpoint(ctx, h, dir, "upgrade.previous")
		if e != nil {
			return e
		}
		if c.From == "" {
			return ErrConflict
		}
	}
	if !pending && o.Action == "upgrade" {
		if current.Version == o.Version {
			blob, e := s.releaseBlob(ctx, current, r.Platform)
			if e != nil {
				return e
			}
			_, e = run(ctx, h, processState(dir, path.Join(dir, current.Version, current.Executable), config)+installationCheck(current, configHash)+"[ \"$expected\" = "+quote(blob.SHA256)+" ]; ")
			if e == nil {
				r.DryRun = current.ID == "banhack233" && r.ProtectionMode == "audit"
			}
			return e
		}
		if !CanUpgrade(o.Plugin, current.Version, o.Version) {
			return ErrInvalid
		}
		if r.AutostartState == "conflict" {
			return ErrConflict
		}
		c = versionCheckpoint{From: current.Version, To: o.Version, ConfigSHA: configHash, Running: r.Running, Autostart: r.Autostart}
	}
	if !CanUpgrade(o.Plugin, c.From, c.To) || c.ConfigSHA != configHash || current.Version != c.From && current.Version != c.To {
		return ErrIntegrity
	}
	from, e := LookupVersion(o.Plugin, c.From)
	if e != nil {
		return e
	}
	to, e := LookupVersion(o.Plugin, c.To)
	if e != nil {
		return e
	}
	fromBlob, e := s.releaseBlob(ctx, from, r.Platform)
	if e != nil {
		return e
	}
	toBlob, e := s.releaseBlob(ctx, to, r.Platform)
	if e != nil {
		return e
	}
	if c.FromSHA == "" {
		c.FromSHA, c.ToSHA = fromBlob.SHA256, toBlob.SHA256
	}
	if c.FromSHA != fromBlob.SHA256 || c.ToSHA != toBlob.SHA256 {
		return ErrIntegrity
	}
	target, blob := to, toBlob
	if o.Action == "rollback" {
		target, blob = from, fromBlob
	}
	if o.Action == "upgrade" && o.Version != c.To {
		return ErrConflict
	}
	currentSHA := fromBlob.SHA256
	if current.Version == c.To {
		currentSHA = toBlob.SHA256
	}
	currentBin := path.Join(dir, current.Version, current.Executable)
	currentState := processState(dir, currentBin, config)
	currentCheck := installationCheck(current, configHash) + "[ \"$expected\" = " + quote(currentSHA) + " ]; "
	if _, e = run(ctx, h, currentState+currentCheck); e != nil {
		return integrityFailure(e)
	}
	if !pending && current.Version == target.Version {
		return nil
	}
	cron := newCronPlan(dir, current.ID)
	if c.Autostart && !cron.supported() {
		return ErrAutostart
	}
	targetBin := path.Join(dir, target.Version, target.Executable)
	targetState := processState(dir, targetBin, config)
	targetCheck := installationCheck(target, configHash) + "[ \"$expected\" = " + quote(blob.SHA256) + " ]; "
	launcher := agentLauncher(cron, base, targetState, targetCheck, current.ID, r.Protection)
	var recovery recoveryBinary
	if r.Protection != nil && r.Protection.Mode == "enforce" {
		recovery, e = nativeRecovery(r.Platform, dir, configHash)
		if e != nil {
			return recoveryError(e)
		}
		if e = recovery.ensure(ctx, h, dir, jobID); e != nil {
			return e
		}
		launcher = cron.launcherScript(base, targetState, targetCheck, current.ID, recovery.step("supervisor"))
		r.RecoveryState = "installed"
		r.RecoveryVersion = recovery.Version
	}
	stage := path.Join(dir, jobID)
	if _, e = run(ctx, h, "[ ! -e "+quote(stage)+" ] && [ ! -L "+quote(stage)+" ]; mkdir -m 700 "+quote(stage)); e != nil {
		return e
	}
	file, e := os.Open(blob.Path)
	if e != nil {
		return e
	}
	e = h.Upload(ctx, path.Join(stage, "binary"), io.LimitReader(file, artifactLimit+1))
	file.Close()
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(c)
	script := operationLock(dir) + currentState + currentCheck + absentIntents("protection.intent")
	if !pending {
		script += snapshotStateGuard(r.Running, r.Autostart)
	}
	script += "[ ! -L \"$d/upgrade.intent\" ] && [ ! -L \"$d/upgrade.next\" ] && [ ! -L \"$d/upgrade.previous\" ]; "
	if pending {
		script += "[ \"$(cat \"$d/upgrade.intent\")\" = " + quote(intent) + " ]; "
	} else {
		script += "[ ! -e \"$d/upgrade.intent\" ]; "
	}
	if c.Autostart {
		script += cron.replace(base, true)
	}
	script += "stage=" + quote(stage) + "; [ \"$(sha256sum \"$stage/binary\" | cut -d ' ' -f 1)\" = " + quote(blob.SHA256) + " ]; "
	script += "printf '%s' " + quote(string(raw)) + " > \"$d/upgrade.next\"; mv \"$d/upgrade.next\" \"$d/upgrade.intent\"; rm -f \"$d/autostart.enabled\"; " + agentStop()
	script += "b=" + quote(targetBin) + "; [ ! -L \"$d/" + target.Version + "\" ] && [ ! -L \"$b\" ]; if [ ! -d \"$d/" + target.Version + "\" ]; then mkdir -m 700 \"$d/" + target.Version + "\"; fi; chmod 700 \"$stage/binary\"; if [ -e \"$b\" ]; then [ \"$(sha256sum \"$b\" | cut -d ' ' -f 1)\" = " + quote(blob.SHA256) + " ]; rm \"$stage/binary\"; else mv \"$stage/binary\" \"$b\"; fi; "
	if current.ID == "banhack233" {
		script += "\"$b\" config-check -config \"$c\" >/dev/null; "
	} else {
		script += "\"$b\" --version >/dev/null 2>&1; "
	}
	script += "printf '%s %s %s\\n' " + quote(target.Version) + " " + quote(blob.SHA256) + " " + quote(configHash) + " > \"$stage/manifest\"; mv \"$stage/manifest\" \"$d/manifest\"; "
	script += "[ ! -L \"$d/agent-launcher.next\" ] && [ ! -L \"$d/agent-launcher.sh\" ]; printf '%s' " + quote(launcher) + " > \"$d/agent-launcher.next\"; chmod 700 \"$d/agent-launcher.next\"; mv \"$d/agent-launcher.next\" \"$d/agent-launcher.sh\"; "
	script += "# transition-start\n" + targetState + targetCheck
	if c.Running || c.Autostart {
		if r.Protection != nil && r.Protection.Mode == "enforce" {
			script += recovery.step()
		}
		script += agentStart(current.ID)
	}
	if c.Autostart {
		script += "[ ! -L \"$d/autostart.enabled\" ]; printf enabled > \"$d/autostart.enabled\"; "
	}
	script += "mv \"$d/upgrade.intent\" \"$d/upgrade.previous\"; rmdir \"$stage\"; printf transition-complete"
	if _, e = run(ctx, h, script); e != nil {
		transitionFailure(ctx, h, dir, "upgrade.intent", r, e)
		r.Version = ""
		r.Running = false
		r.Autostart = false
		r.AutostartState = "unknown"
		return e
	}
	r.Version, r.TransitionPending = target.Version, false
	r.Running, r.Autostart = c.Running || c.Autostart, c.Autostart
	r.AutostartState, r.State = "disabled", "stopped"
	if r.Autostart {
		r.AutostartState = "enabled"
	}
	if r.Running {
		r.State = "running"
	}
	r.UpgradeAvailable = CanUpgrade(o.Plugin, target.Version, r.LatestVersion)
	r.DryRun = current.ID == "banhack233" && r.ProtectionMode == "audit"
	if r.Running && r.Protection != nil && r.Protection.Mode == "enforce" {
		return recovery.inspect(ctx, h, r)
	}
	return nil
}

func transitionFailure(ctx context.Context, h Transport, dir, name string, r *Result, cause error) {
	r.State = "unknown"
	// A nonzero remote exit is terminal. Transport/cancellation failures may
	// still have effects in flight, so they retain an explicitly unknown state.
	if cause == ErrConflict {
		raw, e := readPrivateJSON(ctx, h, path.Join(dir, name), 8192)
		if e == nil {
			r.TransitionPending = raw != "none"
			r.State = "failed"
			if r.TransitionPending {
				r.State = "transition_pending"
			}
		}
	}
}

func (s *Service) releaseBlob(ctx context.Context, d Definition, platform string) (Blob, error) {
	a, e := d.Artifact(platform)
	if e != nil {
		return Blob{}, e
	}
	return s.cache.Fetch(ctx, a)
}
