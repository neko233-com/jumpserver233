package hostplugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/agentbundle"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

type recoveryBinary struct {
	agentbundle.Binary
	file      string
	configSHA string
}

func nativeRecovery(platform, dir, hash string) (recoveryBinary, error) {
	b, e := agentbundle.Get(platform)
	return recoveryBinary{Binary: b, file: path.Join(dir, "agent-recovery-"+b.SHA256), configSHA: hash}, e
}

func (b recoveryBinary) verify() string {
	return "[ ! -L " + quote(b.file) + " ]; [ -f " + quote(b.file) + " ]; [ \"$(sha256sum " + quote(b.file) + " | cut -d ' ' -f 1)\" = " + quote(b.SHA256) + " ]; "
}
func (b recoveryBinary) command(action string) string {
	return quote(b.file) + " " + action + " --directory " + quote(path.Dir(b.file)) + " --config-sha " + quote(b.configSHA)
}

func (b recoveryBinary) step(triggers ...string) string {
	trigger := "lifecycle"
	if len(triggers) > 0 {
		trigger = triggers[0]
	}
	restore := b.command("restore") + " --trigger " + quote(trigger)
	// The daemon owns the state flock for its full lifetime. Inspect its atomic
	// snapshot first; if a repair is necessary, stop it before taking that lock.
	return b.verify() + "if [ \"$running\" = 1 ]; then if " + b.command("check") + " >/dev/null; then :; else recovery_code=$?; if [ \"$recovery_code\" != 10 ] && [ \"$recovery_code\" != 11 ]; then exit \"$recovery_code\"; fi; " + agentStop() + "running=0; [ \"$recovery_code\" = 10 ]; " + restore + " >/dev/null; fi; else " + restore + " >/dev/null; fi; "
}

func (b recoveryBinary) ensure(ctx context.Context, h Transport, dir, jobID string) error {
	present, e := run(ctx, h, "[ ! -L "+quote(b.file)+" ]; if [ -e "+quote(b.file)+" ]; then "+b.verify()+"printf present; else printf missing; fi")
	if e != nil {
		return integrityFailure(e)
	}
	if present == "present" {
		return nil
	}
	stage := path.Join(dir, jobID+"-recovery")
	if _, e = run(ctx, h, "[ ! -e "+quote(stage)+" ] && [ ! -L "+quote(stage)+" ]; mkdir -m 700 "+quote(stage)); e != nil {
		return e
	}
	if e = h.Upload(ctx, path.Join(stage, "binary"), bytes.NewReader(b.Data)); e != nil {
		return e
	}
	script := operationLock(dir) + "stage=" + quote(stage) + "; [ ! -L \"$stage/binary\" ] && [ \"$(sha256sum \"$stage/binary\" | cut -d ' ' -f 1)\" = " + quote(b.SHA256) + " ]; [ ! -L " + quote(b.file) + " ]; if [ -e " + quote(b.file) + " ]; then " + b.verify() + "rm \"$stage/binary\"; else chmod 700 \"$stage/binary\"; mv \"$stage/binary\" " + quote(b.file) + "; fi; rmdir \"$stage\"; printf ready"
	_, e = run(ctx, h, script)
	return e
}

func (b recoveryBinary) inspect(ctx context.Context, h Transport, r *Result) error {
	valid, e := run(ctx, h, "[ ! -L "+quote(b.file)+" ]; if [ ! -f "+quote(b.file)+" ]; then printf missing; else "+b.verify()+"printf ready; fi")
	if e != nil {
		r.RecoveryState = "unknown"
		return integrityFailure(e)
	}
	if valid == "missing" {
		r.RecoveryState = "unavailable"
		return nil
	}
	out, e := h.Run(ctx, "set -eu; umask 077; "+b.verify()+b.command("check"))
	if e != nil {
		r.RecoveryState = "unknown"
		return e
	}
	if out.Truncated {
		r.RecoveryState = "unknown"
		return ErrIntegrity
	}
	if out.ExitCode != 0 && out.ExitCode != 10 {
		r.RecoveryState = "unknown"
		if out.ExitCode == 11 {
			return ErrConflict
		}
		var failure struct {
			Error string `json:"error"`
		}
		if json.Unmarshal([]byte(out.Stdout), &failure) == nil {
			switch failure.Error {
			case "invalid_configuration", "invalid_state":
				return ErrIntegrity
			case "agent_busy":
				return ErrConflict
			}
		}
		return ErrProtection
	}
	var report hostagent.Report
	d := json.NewDecoder(strings.NewReader(out.Stdout))
	d.DisallowUnknownFields()
	if d.Decode(&report) != nil || report.ConfigSHA != b.configSHA || report.Version != hostagent.Version || report.ActiveBans < 0 || report.ActiveBans > hostagent.MaxEntries || report.State != "ready" && report.State != "required" {
		r.RecoveryState = "unknown"
		return ErrIntegrity
	}
	r.RecoveryState = report.State
	r.ActiveBans = report.ActiveBans
	r.RecoveryVersion = report.Version
	return nil
}

// Existing pre-recovery launchers are recognized exactly. Replacing one is an
// explicit lifecycle/policy operation; status never uploads or rewrites files.
func launcherGuard(newHash, legacyHash string) string {
	return "[ ! -L \"$d/agent-launcher.sh\" ]; launcher_hash=$(sha256sum \"$d/agent-launcher.sh\" | cut -d ' ' -f 1); { [ \"$launcher_hash\" = " + quote(newHash) + " ] || [ \"$launcher_hash\" = " + quote(legacyHash) + " ]; }; "
}

func publishLauncher(launcher string) string {
	return "[ ! -L \"$d/agent-launcher.sh\" ] && [ ! -L \"$d/agent-launcher.next\" ]; printf '%s' " + quote(launcher) + " > \"$d/agent-launcher.next\"; chmod 700 \"$d/agent-launcher.next\"; mv \"$d/agent-launcher.next\" \"$d/agent-launcher.sh\"; "
}

func recoveryError(e error) error {
	if errors.Is(e, agentbundle.ErrUnavailable) {
		return ErrRecovery
	}
	return e
}

func refreshRecovery(ctx context.Context, h Transport, jobID string, d Definition, base, dir, config, hash, state, check string, r *Result) error {
	b, e := nativeRecovery(r.Platform, dir, hash)
	if e != nil {
		return recoveryError(e)
	}
	if e = b.ensure(ctx, h, dir, jobID); e != nil {
		return e
	}
	cron := newCronPlan(dir, d.ID)
	legacy := agentLauncher(cron, base, state, check, d.ID, r.Protection)
	launcher := cron.launcherScript(base, state, check, d.ID, b.step("supervisor"))
	script := operationLock(dir) + state + check + absentIntents("upgrade.intent", "protection.intent") + snapshotStateGuard(r.Running, r.Autostart)
	if r.Autostart {
		script += launcherGuard(digest([]byte(launcher)), digest([]byte(legacy))) + publishLauncher(launcher)
	}
	if r.Running || r.Autostart {
		script += b.step() + agentStart(d.ID)
	}
	if _, e = run(ctx, h, script+"printf ready"); e != nil {
		return e
	}
	r.RecoveryVersion = b.Version
	r.RecoveryState = "installed"
	if r.Running || r.Autostart {
		return b.inspect(ctx, h, r)
	}
	return nil
}

// updateRecovery is an explicit managed-component replacement. It never runs
// an old launcher or helper, and preserves an unrecognized regular launcher.
func updateRecovery(ctx context.Context, h Transport, jobID string, d Definition, base, dir, hash, state, check string, r *Result) error {
	b, e := nativeRecovery(r.Platform, dir, hash)
	if e != nil {
		return recoveryError(e)
	}
	// Reject symlinks and special files. Preserve a corrupt binary at its own
	// immutable backup path before installing the verified embedded component.
	backup := path.Join(dir, jobID+".recovery.previous")
	script := operationLock(dir) + state + check + absentIntents("upgrade.intent", "protection.intent") + "[ ! -L " + quote(b.file) + " ]; if [ -e " + quote(b.file) + " ]; then [ -f " + quote(b.file) + " ]; if [ \"$(sha256sum " + quote(b.file) + " | cut -d ' ' -f 1)\" != " + quote(b.SHA256) + " ]; then [ ! -e " + quote(backup) + " ] && [ ! -L " + quote(backup) + " ]; mv " + quote(b.file) + " " + quote(backup) + "; fi; fi; printf checked"
	if _, e = run(ctx, h, script); e != nil {
		return integrityFailure(e)
	}
	if e = b.ensure(ctx, h, dir, jobID); e != nil {
		return e
	}
	cron := newCronPlan(dir, d.ID)
	launcher := agentLauncher(cron, base, state, check, d.ID, r.Protection)
	enforcing := r.Protection != nil && r.Protection.Mode == "enforce"
	if enforcing {
		launcher = cron.launcherScript(base, state, check, d.ID, b.step("supervisor"))
	}
	script = operationLock(dir) + state + check + absentIntents("upgrade.intent", "protection.intent") + snapshotStateGuard(r.Running, r.Autostart)
	if r.AutostartState == "conflict" {
		return ErrConflict
	}
	script += "[ ! -L \"$d/agent-launcher.sh\" ]; if [ -e \"$d/agent-launcher.sh\" ]; then [ -f \"$d/agent-launcher.sh\" ] && [ \"$(stat -c %s \"$d/agent-launcher.sh\")\" -le 131072 ]; [ ! -e " + quote(path.Join(dir, jobID+".launcher.previous")) + " ]; mv \"$d/agent-launcher.sh\" " + quote(path.Join(dir, jobID+".launcher.previous")) + "; fi; " + publishLauncher(launcher)
	if enforcing && (r.Running || r.Autostart) {
		script += b.step() + agentStart(d.ID)
	}
	if _, e = run(ctx, h, script+"printf updated"); e != nil {
		return e
	}
	r.RecoveryVersion = b.Version
	r.RecoveryState = "installed"
	if enforcing && (r.Running || r.Autostart) {
		return b.inspect(ctx, h, r)
	}
	return nil
}
