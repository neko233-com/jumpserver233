package hostplugins

import (
	"context"
	"encoding/json"
	"io"
	"path"
	"slices"
	"strings"
)

type protectionCheckpoint struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Request   string `json:"request"`
	Running   bool   `json:"running"`
	Autostart bool   `json:"autostart"`
}

func readProtectionCheckpoint(ctx context.Context, h Transport, dir, name string) (protectionCheckpoint, string, error) {
	raw, e := readPrivateJSON(ctx, h, path.Join(dir, name), 2048)
	var c protectionCheckpoint
	if e != nil || raw == "none" {
		return c, raw, e
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || !validDigest(c.From) || !validDigest(c.To) || !validDigest(c.Request) {
		return c, raw, ErrIntegrity
	}
	return c, raw, nil
}

func (s *Service) applyProtection(ctx context.Context, h Transport, jobID string, o Operation, d Definition, base, dir, config, configHash string, policy *ProtectionPolicy, r *Result) error {
	if !r.Installed || d.ID != "banhack233" {
		return ErrConflict
	}
	c, intent, e := readProtectionCheckpoint(ctx, h, dir, "protection.intent")
	if e != nil {
		return e
	}
	pending := intent != "none"
	if !pending && o.Action == "protection_rollback" {
		c, _, e = readProtectionCheckpoint(ctx, h, dir, "protection.previous")
		if e != nil {
			return e
		}
		if c.From == "" {
			return ErrConflict
		}
	}
	var targetPolicy *ProtectionPolicy
	var targetConfig []byte
	var targetPath string
	if !pending && o.Action == "protection_apply" {
		p := *o.Protection
		peer, port, e := protectionPeer(ctx, h)
		if e != nil {
			return e
		}
		p.IgnoreIPs = append(append([]string{}, p.IgnoreIPs...), "127.0.0.0/8", "::1", peer.String())
		p.SSHPorts = append(append([]int{}, p.SSHPorts...), port)
		p, e = p.Normalize()
		if e != nil {
			return e
		}
		targetPolicy = &p
		targetConfig = protectionConfig(dir, p)
		if r.AutostartState == "conflict" {
			return ErrConflict
		}
		c = protectionCheckpoint{From: configHash, To: digest(targetConfig), Request: o.Protection.hash(), Running: r.Running, Autostart: r.Autostart}
		targetPath = path.Join(dir, "config-"+c.To+".json")
	}
	if configHash != c.From && configHash != c.To {
		return ErrIntegrity
	}
	if pending || o.Action == "protection_rollback" {
		if o.Action == "protection_apply" && o.Protection.hash() != c.Request {
			return ErrConflict
		}
		targetHash := c.To
		if o.Action == "protection_rollback" {
			targetHash = c.From
		}
		targetConfig, targetPath, targetPolicy, e = loadProtection(ctx, h, dir, targetHash)
		if e != nil {
			return e
		}
	}
	if targetPolicy != nil && targetPolicy.Mode == "enforce" {
		if e = protectionPreflight(ctx, h, dir, *targetPolicy); e != nil {
			return e
		}
	}
	if policy != nil && policy.Mode == "enforce" {
		ownership, inspectErr := firewallInspect(ctx, h, dir)
		if inspectErr != nil {
			return inspectErr
		}
		if ownership == "foreign" {
			return ErrConflict
		}
	}
	blob, e := s.releaseBlob(ctx, d, r.Platform)
	if e != nil {
		return e
	}
	bin := path.Join(dir, d.Version, d.Executable)
	state := processState(dir, bin, config)
	check := installationCheck(d, configHash) + "[ \"$expected\" = " + quote(blob.SHA256) + " ]; "
	if _, e = run(ctx, h, state+check); e != nil {
		return integrityFailure(e)
	}
	if !pending && digest(targetConfig) == configHash {
		r.DryRun = r.ProtectionMode == "audit"
		if targetPolicy != nil && targetPolicy.Mode == "enforce" {
			return refreshRecovery(ctx, h, jobID, d, base, dir, config, configHash, state, check, r)
		}
		return nil
	}
	cron := newCronPlan(dir, d.ID)
	if c.Autostart && !cron.supported() {
		return ErrAutostart
	}
	targetHash := digest(targetConfig)
	targetState := processState(dir, bin, targetPath)
	targetCheck := installationCheck(d, targetHash) + "[ \"$expected\" = " + quote(blob.SHA256) + " ]; "
	launcher := agentLauncher(cron, base, targetState, targetCheck, d.ID, targetPolicy)
	var recovery recoveryBinary
	if targetPolicy != nil && targetPolicy.Mode == "enforce" {
		recovery, e = nativeRecovery(r.Platform, dir, targetHash)
		if e != nil {
			return recoveryError(e)
		}
		if e = recovery.ensure(ctx, h, dir, jobID); e != nil {
			return e
		}
		launcher = cron.launcherScript(base, targetState, targetCheck, d.ID, recovery.step("supervisor"))
		r.RecoveryState = "installed"
		r.RecoveryVersion = recovery.Version
	}
	stage := path.Join(dir, jobID)
	if _, e = run(ctx, h, "[ ! -e "+quote(stage)+" ] && [ ! -L "+quote(stage)+" ]; mkdir -m 700 "+quote(stage)); e != nil {
		return e
	}
	if e = h.Upload(ctx, path.Join(stage, "config"), strings.NewReader(string(targetConfig))); e != nil {
		return e
	}
	var policyJSON []byte
	if targetPolicy != nil {
		policyJSON, _ = json.Marshal(targetPolicy)
		if e = h.Upload(ctx, path.Join(stage, "policy"), strings.NewReader(string(policyJSON))); e != nil {
			return e
		}
	}
	raw, _ := json.Marshal(c)
	script := operationLock(dir) + state + check + absentIntents("upgrade.intent")
	if !pending {
		script += snapshotStateGuard(r.Running, r.Autostart)
	}
	script += "[ ! -L \"$d/protection.intent\" ] && [ ! -L \"$d/protection.next\" ] && [ ! -L \"$d/protection.previous\" ]; "
	if pending {
		script += "[ \"$(cat \"$d/protection.intent\")\" = " + quote(intent) + " ]; "
	} else {
		script += "[ ! -e \"$d/protection.intent\" ]; "
	}
	if c.Autostart {
		script += cron.replace(base, true)
	}
	script += "stage=" + quote(stage) + "; [ \"$(sha256sum \"$stage/config\" | cut -d ' ' -f 1)\" = " + quote(targetHash) + " ]; "
	// Immutable profiles are published before the intent; the manifest remains
	// the single atomic selector, including after a process/transport failure.
	script += publishProfile(path.Join(stage, "config"), targetPath, targetHash)
	if targetPolicy != nil {
		script += publishProfile(path.Join(stage, "policy"), path.Join(dir, "policy-"+targetHash+".json"), digest(policyJSON))
	}
	script += "\"$b\" config-check -config " + quote(targetPath) + " >/dev/null; printf '%s' " + quote(string(raw)) + " > \"$d/protection.next\"; mv \"$d/protection.next\" \"$d/protection.intent\"; rm -f \"$d/autostart.enabled\"; " + agentStop()
	if targetPolicy == nil || targetPolicy.Mode != "enforce" {
		script += firewallRemove(dir)
	}
	script += "printf '%s %s %s\\n' " + quote(d.Version) + " " + quote(blob.SHA256) + " " + quote(targetHash) + " > \"$stage/manifest\"; mv \"$stage/manifest\" \"$d/manifest\"; "
	script += "[ ! -L \"$d/agent-launcher.next\" ] && [ ! -L \"$d/agent-launcher.sh\" ]; printf '%s' " + quote(launcher) + " > \"$d/agent-launcher.next\"; chmod 700 \"$d/agent-launcher.next\"; mv \"$d/agent-launcher.next\" \"$d/agent-launcher.sh\"; # protection-start\n" + targetState + targetCheck
	if c.Running || c.Autostart {
		if targetPolicy != nil && targetPolicy.Mode == "enforce" {
			script += recovery.step()
		}
		script += agentStart(d.ID)
	}
	if c.Autostart {
		script += "[ ! -L \"$d/autostart.enabled\" ]; printf enabled > \"$d/autostart.enabled\"; "
	}
	script += "mv \"$d/protection.intent\" \"$d/protection.previous\"; rmdir \"$stage\"; printf protection-complete"
	if _, e = run(ctx, h, script); e != nil {
		transitionFailure(ctx, h, dir, "protection.intent", r, e)
		r.Running = false
		r.Autostart = false
		r.AutostartState = "unknown"
		r.ProtectionMode = "unknown"
		return e
	}
	r.Protection = targetPolicy
	r.ProtectionMode = "audit"
	if targetPolicy != nil {
		r.ProtectionMode = targetPolicy.Mode
	}
	r.DryRun = r.ProtectionMode == "audit"
	r.TransitionPending = false
	r.Running, r.Autostart = c.Running || c.Autostart, c.Autostart
	r.State, r.AutostartState = "stopped", "disabled"
	if r.Running {
		r.State = "running"
	}
	if r.Autostart {
		r.AutostartState = "enabled"
	}
	if r.Running && targetPolicy != nil && targetPolicy.Mode == "enforce" {
		return recovery.inspect(ctx, h, r)
	}
	return nil
}

func publishProfile(source, target, hash string) string {
	return "[ ! -L " + quote(target) + " ]; if [ -e " + quote(target) + " ]; then [ \"$(sha256sum " + quote(target) + " | cut -d ' ' -f 1)\" = " + quote(hash) + " ]; rm " + quote(source) + "; else chmod 600 " + quote(source) + "; mv " + quote(source) + " " + quote(target) + "; fi; "
}

// Keep normalization allocations separate from persisted operation snapshots.
func copyProtection(p *ProtectionPolicy) *ProtectionPolicy {
	if p == nil {
		return nil
	}
	v := *p
	v.IgnoreIPs = slices.Clone(p.IgnoreIPs)
	v.SSHPorts = slices.Clone(p.SSHPorts)
	return &v
}
