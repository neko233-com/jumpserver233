package hostplugins

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
)

// Operation is stamped by the authenticated API, never accepted by /ops/jobs.
// Binding snapshots the account, credential and complete SSH gateway route.
type Operation struct {
	Plugin     string            `json:"plugin"`
	Action     string            `json:"action"`
	Version    string            `json:"version"`
	Binding    string            `json:"binding"`
	Selection  string            `json:"selection,omitempty"`
	Protection *ProtectionPolicy `json:"protection,omitempty"`
}

func (o Operation) Validate() error {
	d, e := LookupVersion(o.Plugin, o.Version)
	if e != nil || !d.Allows(o.Action) || !validDigest(o.Binding) {
		return ErrInvalid
	}
	if o.Selection != "" && (o.Selection != "installed" || o.Action == "install" || o.Action == "upgrade") {
		return ErrInvalid
	}
	if o.Action == "protection_apply" {
		if o.Protection == nil {
			return ErrInvalid
		}
		p, e := o.Protection.Normalize()
		if e != nil || p.hash() != o.Protection.hash() {
			return ErrInvalid
		}
	} else if o.Protection != nil {
		return ErrInvalid
	}
	return nil
}
func (o Operation) Command() string {
	command := "host-plugin " + o.Plugin + " " + o.Action + " version=" + o.Version + " binding=" + o.Binding
	if o.Selection == "installed" {
		command = "host-plugin " + o.Plugin + " " + o.Action + " version=installed catalog=" + o.Version + " binding=" + o.Binding
	}
	if o.Protection != nil {
		command += " policy=" + o.Protection.hash()
	}
	return command
}
func (o Operation) Permission() string {
	switch o.Action {
	case "systemd_status", "events", "detect", "status", "doctor", "scan", "keepalive_preview", "metrics", "protection_status":
		return "plugins.inspect"
	case "protection_apply", "protection_rollback":
		return "plugins.protect"
	}
	return "plugins.manage"
}

type Transport interface {
	Run(context.Context, string) (sshclient.ExecResult, error)
	Upload(context.Context, string, io.Reader) error
	Root() string
	DialLoopback(context.Context) (net.Conn, error)
	Close() error
}
type OpenFunc func(context.Context, string) (Transport, error)

func (o Operation) Clone() Operation {
	o.Protection = copyProtection(o.Protection)
	return o
}

// guardedTransport rechecks server authorization immediately before each SSH
// effect, including after connection setup and artifact download.
type guardedTransport struct {
	Transport
	guard func() error
}

func (h *guardedTransport) Run(ctx context.Context, command string) (sshclient.ExecResult, error) {
	if e := h.guard(); e != nil {
		return sshclient.ExecResult{ExitCode: -1}, e
	}
	return h.Transport.Run(ctx, command)
}

func (h *guardedTransport) RunInput(ctx context.Context, command string, input []byte) (sshclient.ExecResult, error) {
	if e := h.guard(); e != nil {
		return sshclient.ExecResult{ExitCode: -1}, e
	}
	runner, ok := h.Transport.(interface {
		RunInput(context.Context, string, []byte) (sshclient.ExecResult, error)
	})
	if !ok {
		return sshclient.ExecResult{ExitCode: -1}, ErrUnsupported
	}
	return runner.RunInput(ctx, command, input)
}
func (h *guardedTransport) Upload(ctx context.Context, path string, data io.Reader) error {
	if e := h.guard(); e != nil {
		return e
	}
	return h.Transport.Upload(ctx, path, data)
}
func (h *guardedTransport) DialLoopback(ctx context.Context) (net.Conn, error) {
	if e := h.guard(); e != nil {
		return nil, e
	}
	return h.Transport.DialLoopback(ctx)
}

type Fetcher interface {
	Fetch(context.Context, Artifact) (Blob, error)
}
type Service struct {
	discoveryMu     sync.Mutex
	discoveryActive map[string]bool
	open            OpenFunc
	cache           Fetcher
}

func New(open OpenFunc, cache Fetcher) *Service { return &Service{open: open, cache: cache} }

type Result struct {
	SystemdState      string                   `json:"systemd_state,omitempty"`
	Supervisor        string                   `json:"supervisor,omitempty"`
	Events            *hostagent.EventSnapshot `json:"events,omitempty"`
	Imported          int                      `json:"imported"`
	MoreEvents        bool                     `json:"more_events"`
	Plugin            string                   `json:"plugin"`
	Action            string                   `json:"action"`
	Version           string                   `json:"version"`
	LatestVersion     string                   `json:"latest_version"`
	UpgradeAvailable  bool                     `json:"upgrade_available"`
	TransitionPending bool                     `json:"transition_pending"`
	Platform          string                   `json:"platform,omitempty"`
	UID               string                   `json:"uid,omitempty"`
	ExistingPath      string                   `json:"existing_path,omitempty"`
	ManagedPath       string                   `json:"managed_path,omitempty"`
	Installed         bool                     `json:"installed"`
	Running           bool                     `json:"running"`
	State             string                   `json:"state"`
	Detail            string                   `json:"detail,omitempty"`
	Output            string                   `json:"output,omitempty"`
	Autostart         bool                     `json:"autostart"`
	AutostartState    string                   `json:"autostart_state"`
	DryRun            bool                     `json:"dry_run"`
	Protection        *ProtectionPolicy        `json:"protection,omitempty"`
	ProtectionMode    string                   `json:"protection_mode,omitempty"`
	FirewallState     string                   `json:"firewall_state,omitempty"`
	RecoveryState     string                   `json:"recovery_state,omitempty"`
	RecoveryVersion   string                   `json:"recovery_version,omitempty"`
	ActiveBans        int                      `json:"active_bans"`
}

func quote(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'" }
func run(ctx context.Context, h Transport, script string) (string, error) {
	r, e := h.Run(ctx, "set -eu; umask 077; "+script)
	if e != nil {
		return "", e
	}
	if r.ExitCode != 0 || r.Truncated {
		return "", ErrConflict
	}
	return strings.TrimSpace(r.Stdout), nil
}
func digest(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }
func integrityFailure(e error) error {
	if errors.Is(e, ErrConflict) {
		return ErrIntegrity
	}
	return e
}
func managedConfig(dir string) []byte {
	v := map[string]any{"dry_run": true, "start_at_end": true, "state_path": path.Join(dir, "state.json"), "logging": map[string]any{"enabled": true, "path": path.Join(dir, "agent.log"), "max_size_mb": 10, "max_age_days": 30}, "geoip": map[string]any{"enabled": false}, "malware": map[string]any{"enabled": true, "direct_kill": false, "report_dir": path.Join(dir, "reports"), "report_keep": 50}, "notifications": map[string]any{"console": true, "audit": false, "queue_path": path.Join(dir, "notifications.json"), "telegram": map[string]any{"enabled": false}, "feishu": map[string]any{"enabled": false}, "discord": map[string]any{"enabled": false}, "slack": map[string]any{"enabled": false}, "email": map[string]any{"enabled": false}, "webhooks": []any{}}}
	b, _ := json.Marshal(v)
	return b
}
func (s *Service) Execute(ctx context.Context, assetID, jobID string, o Operation, guards ...func() error) (sshclient.ExecResult, error) {
	return s.executeManaged(ctx, assetID, jobID, o, hostagent.EventCursor{}, guards...)
}
func (s *Service) ExecuteEvents(ctx context.Context, assetID, jobID string, o Operation, cursor hostagent.EventCursor, guard func() error) (sshclient.ExecResult, error) {
	return s.executeManaged(ctx, assetID, jobID, o, cursor, guard)
}
func (s *Service) executeCore(ctx context.Context, assetID, jobID string, o Operation, cursor hostagent.EventCursor, guards ...func() error) (sshclient.ExecResult, error) {
	r := Result{Plugin: o.Plugin, Action: o.Action, Version: o.Version, State: "failed"}
	finish := func(e error) (sshclient.ExecResult, error) {
		if e != nil {
			switch {
			case errors.Is(e, ErrUnsupported):
				r.Detail = "unsupported_platform"
			case errors.Is(e, ErrAutostart):
				r.Detail = "autostart_unavailable"
			case errors.Is(e, ErrProtection):
				r.Detail = "protection_unavailable"
			case errors.Is(e, ErrRecovery):
				r.Detail = "recovery_unavailable"
			case errors.Is(e, ErrIntegrity):
				r.Detail = "integrity_failed"
			case errors.Is(e, ErrInvalid):
				r.Detail = "invalid_operation"
			case errors.Is(e, ErrConflict):
				r.Detail = "state_conflict"
			default:
				r.Detail = "transport_or_artifact_failed"
			}
		}
		b, _ := json.Marshal(r)
		for len(b) > sshclient.MaxExecOutput-512 && len(r.Output) > 0 {
			r.Output = r.Output[:len(r.Output)*3/4]
			r.Detail = "output_truncated"
			b, _ = json.Marshal(r)
		}
		code := 0
		if e != nil {
			code = 1
		}
		return sshclient.ExecResult{Stdout: string(b), ExitCode: code}, e
	}
	if e := o.Validate(); e != nil {
		return finish(e)
	}
	// Only service-generated job identifiers are used for remote staging paths.
	if len(jobID) != 36 || !strings.HasPrefix(jobID, "job-") {
		return finish(ErrInvalid)
	}
	if _, e := hex.DecodeString(jobID[4:]); e != nil {
		return finish(ErrInvalid)
	}
	if len(guards) > 1 {
		return finish(ErrInvalid)
	}
	if len(guards) == 1 && guards[0] != nil {
		if e := guards[0](); e != nil {
			return finish(e)
		}
	}
	h, e := s.open(ctx, assetID)
	if e != nil {
		return finish(e)
	}
	defer h.Close()
	if len(guards) == 1 && guards[0] != nil {
		h = &guardedTransport{Transport: h, guard: guards[0]}
	}
	head, _ := Lookup(o.Plugin)
	d, _ := LookupVersion(o.Plugin, o.Version)
	r.LatestVersion = head.Version
	facts, e := run(ctx, h, "uname -s; uname -m; id -u; command -v "+d.Executable+" || true")
	if e != nil {
		return finish(e)
	}
	lines := strings.Split(facts, "\n")
	if len(lines) < 3 || len(lines) > 4 {
		return finish(ErrInvalid)
	}
	r.Platform, e = Platform(lines[0], lines[1])
	if e != nil {
		return finish(e)
	}
	if _, e = strconv.ParseUint(lines[2], 10, 32); e != nil {
		return finish(ErrInvalid)
	}
	r.UID = lines[2]
	if len(lines) == 4 {
		r.ExistingPath = lines[3]
	}
	// Agent lifecycle currently requires Linux /proc identity verification.
	if !strings.HasPrefix(r.Platform, "linux-") {
		return finish(ErrUnsupported)
	}
	home := h.Root()
	if !path.IsAbs(home) || path.Clean(home) != home || len(home) > 2048 || strings.IndexFunc(home, unicode.IsControl) >= 0 {
		return finish(ErrInvalid)
	}
	base := path.Join(home, ".jumpserver233")
	dir := path.Join(base, "plugins", d.ID)
	bin := path.Join(dir, d.Version, d.Executable)
	config := path.Join(dir, "config.json")
	r.ManagedPath = dir
	cron := newCronPlan(dir, d.ID)
	setup := ""
	for _, p := range []string{base, path.Join(base, "plugins"), dir} {
		q := quote(p)
		setup += "if [ -L " + q + " ]; then exit 41; fi; if [ ! -e " + q + " ]; then mkdir -m 700 " + q + "; fi; [ -d " + q + " ] && [ \"$(stat -c %u " + q + ")\" = \"$(id -u)\" ]; chmod 700 " + q + "; "
	}
	if o.Action == "install" {
		if _, e = run(ctx, h, setup); e != nil {
			return finish(e)
		}
	} else {
		if _, e = run(ctx, h, "for p in "+quote(base)+" "+quote(path.Join(base, "plugins"))+" "+quote(dir)+"; do [ ! -L \"$p\" ]; done"); e != nil {
			return finish(e)
		}
	}
	installedManifest, e := run(ctx, h, "[ ! -L "+quote(path.Join(dir, "manifest"))+" ]; if [ -f "+quote(path.Join(dir, "manifest"))+" ]; then read -r version binary_hash config_hash < "+quote(path.Join(dir, "manifest"))+"; printf '%s %s %s' \"$version\" \"$binary_hash\" \"$config_hash\"; else printf none; fi")
	if e != nil {
		return finish(e)
	}
	cfg := managedConfig(dir)
	cfgHash := digest(cfg)
	var policy *ProtectionPolicy
	if installedManifest != "none" {
		fields := strings.Fields(installedManifest)
		if len(fields) != 3 || !validDigest(fields[1]) || !validDigest(fields[2]) {
			return finish(ErrIntegrity)
		}
		d, e = LookupVersion(o.Plugin, fields[0])
		if e != nil {
			return finish(ErrIntegrity)
		}
		if o.Action == "install" && d.Version != o.Version {
			return finish(ErrConflict)
		}
		if o.Selection == "" && o.Action != "detect" && o.Action != "install" && o.Action != "upgrade" && o.Action != "rollback" && d.Version != o.Version {
			return finish(ErrConflict)
		}
		bin = path.Join(dir, d.Version, d.Executable)
		r.Version = d.Version
		r.UpgradeAvailable = CanUpgrade(d.ID, d.Version, head.Version)
		if d.ID == "banhack233" {
			cfg, config, policy, e = loadProtection(ctx, h, dir, fields[2])
			if e != nil {
				if o.Action != "stop" && o.Action != "uninstall" && o.Action != "autostart_disable" {
					return finish(e)
				}
				cfg = managedConfig(dir)
				config = path.Join(dir, "config.json")
				policy = nil
				r.ProtectionMode = "unknown"
			}
			cfgHash = fields[2]
		}
	}
	qdir, qbin := quote(dir), quote(bin)
	if d.ID == "banhack233" && r.ProtectionMode != "unknown" {
		r.ProtectionMode = "audit"
		if policy != nil {
			r.Protection = policy
			r.ProtectionMode = policy.Mode
		}
	}
	state := processState(dir, bin, config)
	check := installationCheck(d, cfgHash)
	status, e := run(ctx, h, state+"if [ -L \"$d/manifest\" ]; then exit 43; fi; if [ -f \"$d/manifest\" ]; then printf installed; else printf missing; fi; printf ' %s %s' \"$running\" \"$stale\"")
	if e != nil {
		return finish(e)
	}
	parts := strings.Fields(status)
	if len(parts) != 3 {
		return finish(ErrInvalid)
	}
	r.Installed = parts[0] == "installed"
	r.Running = parts[1] == "1"
	r.State = "missing"
	if r.Installed {
		r.State = "stopped"
	}
	if r.Running {
		r.State = "running"
	}
	if parts[2] == "1" {
		r.State = "stale_pid"
	}
	r.AutostartState, e = run(ctx, h, cron.probe(dir))
	if e != nil {
		return finish(e)
	}
	switch r.AutostartState {
	case "enabled", "disabled", "conflict", "unavailable":
	default:
		return finish(ErrInvalid)
	}
	r.Autostart = r.AutostartState == "enabled"
	pending, e := run(ctx, h, "[ ! -L "+quote(path.Join(dir, "upgrade.intent"))+" ] && [ ! -L "+quote(path.Join(dir, "protection.intent"))+" ]; if [ -f "+quote(path.Join(dir, "upgrade.intent"))+" ] || [ -f "+quote(path.Join(dir, "protection.intent"))+" ]; then printf pending; else printf clean; fi")
	if e != nil {
		return finish(e)
	}
	r.TransitionPending = pending == "pending"
	if r.TransitionPending {
		r.State = "transition_pending"
	}
	if o.Action == "detect" {
		return finish(nil)
	}
	if o.Action == "upgrade" || o.Action == "rollback" {
		if p, e := readPrivateJSON(ctx, h, path.Join(dir, "protection.intent"), 8192); e != nil || p != "none" {
			return finish(ErrConflict)
		}
		e = s.transition(ctx, h, jobID, o, d, base, dir, config, cfgHash, &r)
		return finish(e)
	}
	if o.Action == "protection_apply" || o.Action == "protection_rollback" {
		if p, e := readPrivateJSON(ctx, h, path.Join(dir, "upgrade.intent"), 2048); e != nil || p != "none" {
			return finish(ErrConflict)
		}
		e = s.applyProtection(ctx, h, jobID, o, d, base, dir, config, cfgHash, policy, &r)
		return finish(e)
	}
	if r.TransitionPending && o.Action != "status" && o.Action != "stop" && o.Action != "autostart_disable" {
		return finish(ErrConflict)
	}
	if o.Action == "install" {
		artifact, e := d.Artifact(r.Platform)
		if e != nil {
			return finish(e)
		}
		blob, e := s.cache.Fetch(ctx, artifact)
		if e != nil {
			return finish(e)
		}
		if r.Installed { // An exact managed installation is idempotent; drift is never overwritten.
			_, e = run(ctx, h, state+check+"[ \"$expected\" = "+quote(blob.SHA256)+" ]; printf ok")
			r.DryRun = e == nil && d.ID == "banhack233" && r.ProtectionMode == "audit"
			return finish(e)
		}
		stage := path.Join(dir, jobID)
		if _, e = run(ctx, h, "[ ! -e "+quote(stage)+" ] && [ ! -L "+quote(stage)+" ]; mkdir -m 700 "+quote(stage)); e != nil {
			return finish(e)
		}
		f, e := os.Open(blob.Path)
		if e != nil {
			return finish(e)
		}
		e = h.Upload(ctx, path.Join(stage, "binary"), io.LimitReader(f, artifactLimit+1))
		f.Close()
		if e != nil {
			return finish(e)
		}
		if d.ID == "banhack233" {
			if e = h.Upload(ctx, path.Join(stage, "config"), strings.NewReader(string(cfg))); e != nil {
				return finish(e)
			}
		}
		lock := "mkdir \"$d/operation.lock\"; trap 'rmdir \"$d/operation.lock\"' EXIT; "
		script := "d=" + qdir + "; " + lock + state + absentIntents("upgrade.intent", "protection.intent") + "[ ! -e \"$d/manifest\" ] && [ ! -L \"$d/manifest\" ]; [ \"$running\" = 0 ]; stage=" + quote(stage) + "; [ \"$(sha256sum \"$stage/binary\" | cut -d ' ' -f 1)\" = " + quote(blob.SHA256) + " ]; [ ! -L \"$d/" + d.Version + "\" ]; if [ ! -d \"$d/" + d.Version + "\" ]; then mkdir -m 700 \"$d/" + d.Version + "\"; fi; chmod 700 \"$stage/binary\"; if [ -e \"$b\" ] || [ -L \"$b\" ]; then [ ! -L \"$b\" ] && [ \"$(sha256sum \"$b\" | cut -d ' ' -f 1)\" = " + quote(blob.SHA256) + " ]; rm \"$stage/binary\"; else mv \"$stage/binary\" \"$b\"; fi; "
		if d.ID == "banhack233" {
			script += "[ ! -L \"$c\" ]; [ \"$(sha256sum \"$stage/config\" | cut -d ' ' -f 1)\" = " + quote(cfgHash) + " ]; if [ -e \"$c\" ]; then [ \"$(sha256sum \"$c\" | cut -d ' ' -f 1)\" = " + quote(cfgHash) + " ]; rm \"$stage/config\"; else mv \"$stage/config\" \"$c\"; fi; chmod 600 \"$c\"; \"$b\" config-check -config \"$c\" >/dev/null; "
		} else {
			script += "\"$b\" --version >/dev/null 2>&1; "
		}
		script += "printf '%s %s %s\\n' " + quote(d.Version) + " " + quote(blob.SHA256) + " " + quote(cfgHash) + " > \"$stage/manifest\"; mv \"$stage/manifest\" \"$d/manifest\"; rmdir \"$stage\"; printf installed"
		_, e = run(ctx, h, script)
		if e == nil {
			r.Installed = true
			r.State = "stopped"
			r.DryRun = d.ID == "banhack233"
		}
		return finish(e)
	}
	if !r.Installed && o.Action != "uninstall" && o.Action != "autostart_disable" {
		return finish(ErrConflict)
	}
	needsIntegrity := o.Action != "stop" && o.Action != "uninstall" && o.Action != "autostart_disable"
	if needsIntegrity {
		artifact, artifactErr := d.Artifact(r.Platform)
		if artifactErr != nil {
			return finish(artifactErr)
		}
		blob, fetchErr := s.cache.Fetch(ctx, artifact)
		if fetchErr != nil {
			return finish(fetchErr)
		}
		check += "[ \"$expected\" = " + quote(blob.SHA256) + " ]; "
	}
	if needsIntegrity {
		if _, e = run(ctx, h, state+check); e != nil {
			if errors.Is(e, ErrConflict) {
				return finish(ErrIntegrity)
			}
			return finish(e)
		}
		r.DryRun = d.ID == "banhack233" && r.ProtectionMode == "audit"
	}

	if o.Action == "events" || o.Action == "events_collect" {
		b, err := nativeRecovery(r.Platform, dir, cfgHash)
		if err != nil {
			return finish(err)
		}
		out, err := run(ctx, h, b.verify()+quote(b.file)+" events --directory "+quote(dir)+" --after "+strconv.FormatUint(cursor.Sequence, 10)+" --stream "+quote(cursor.Stream)+" --anchor "+quote(cursor.Hash)+" --limit 64")
		if err != nil {
			return finish(integrityFailure(err))
		}
		snapshot, err := hostagent.DecodeEventSnapshot([]byte(out))
		if err != nil {
			return finish(ErrIntegrity)
		}
		r.Events = &snapshot
		return finish(nil)
	}
	if o.Action == "agent_update" {
		return finish(updateRecovery(ctx, h, jobID, d, base, dir, cfgHash, state, check, &r))
	}
	launcher := agentLauncher(cron, base, state, check, d.ID, policy)
	legacyLauncherHash := digest([]byte(launcher))
	var recovery recoveryBinary
	var recoveryErr error
	if policy != nil && policy.Mode == "enforce" {
		recovery, recoveryErr = nativeRecovery(r.Platform, dir, cfgHash)
		r.RecoveryState = "unavailable"
		if recoveryErr == nil {
			r.RecoveryState = "unknown"
			launcher = cron.launcherScript(base, state, check, d.ID, recovery.step("supervisor"))
		}
	}
	launcherHash := digest([]byte(launcher))
	launcherCheck := launcherGuard(launcherHash, legacyLauncherHash)
	if needsIntegrity && r.Autostart {
		if _, e = run(ctx, h, "d="+qdir+"; "+launcherCheck); e != nil {
			return finish(integrityFailure(e))
		}
	}
	if policy != nil && policy.Mode == "enforce" && (o.Action == "start" || o.Action == "autostart_enable") {
		if recoveryErr != nil {
			return finish(recoveryError(recoveryErr))
		}
		if e = recovery.ensure(ctx, h, dir, jobID); e != nil {
			return finish(e)
		}
	}
	if policy != nil && policy.Mode == "enforce" && recoveryErr == nil && (o.Action == "status" || o.Action == "protection_status") {
		if e = recovery.inspect(ctx, h, &r); e != nil {
			return finish(e)
		}
	}
	switch o.Action {
	case "status":
		return finish(nil)
	case "start", "stop":
		script := operationLock(dir) + state + manifestVersionGuard(d.Version)
		if o.Action == "start" {
			script += check + absentIntents("upgrade.intent", "protection.intent")
		}
		if o.Action == "start" {
			if policy != nil && policy.Mode == "enforce" {
				if e = protectionPreflight(ctx, h, dir, *policy); e != nil {
					return finish(e)
				}
				script += recovery.step()
				if r.Autostart {
					script += "[ -f \"$d/autostart.enabled\" ]; " + launcherCheck + publishLauncher(launcher)
				}
			}
			script += agentStart(d.ID) + "printf running"
		} else {
			script += "rm -f \"$d/autostart.enabled\"; " + agentStop()
			if d.ID == "banhack233" {
				script += firewallRemove(dir)
			}
			if r.AutostartState != "unavailable" {
				script += cron.replace(base, false)
			}
			script += "printf stopped"
		}
		r.Output, e = run(ctx, h, script)
		if e == nil {
			r.Running = o.Action == "start"
			r.State = r.Output
			if o.Action == "stop" {
				r.Autostart = false
				r.AutostartState = "disabled"
			}
			if o.Action == "start" && policy != nil && policy.Mode == "enforce" {
				e = recovery.inspect(ctx, h, &r)
			}
		}
		return finish(e)
	case "autostart_enable":
		if policy != nil && policy.Mode == "enforce" {
			if e = protectionPreflight(ctx, h, dir, *policy); e != nil {
				return finish(e)
			}
		}
		if !cron.supported() || r.AutostartState == "unavailable" {
			return finish(ErrAutostart)
		}
		if r.AutostartState == "conflict" {
			return finish(ErrConflict)
		}
		script := operationLock(dir) + state + check + absentIntents("upgrade.intent", "protection.intent")
		if policy != nil && policy.Mode == "enforce" {
			script += recovery.step()
		}
		script += "[ ! -L \"$d/agent-launcher.sh\" ] && [ ! -L \"$d/agent-launcher.next\" ] && [ ! -L \"$d/autostart.enabled\" ]; if [ -e \"$d/agent-launcher.sh\" ]; then " + launcherCheck + "fi; printf '%s' " + quote(launcher) + " > \"$d/agent-launcher.next\"; chmod 700 \"$d/agent-launcher.next\"; mv \"$d/agent-launcher.next\" \"$d/agent-launcher.sh\"; "
		script += cron.replace(base, true)
		script += "printf enabled > \"$d/autostart.enabled\"; " + agentStart(d.ID) + "printf running"
		r.Output, e = run(ctx, h, script)
		if e == nil {
			r.Running, r.Autostart, r.AutostartState, r.State = true, true, "enabled", "running"
			if policy != nil && policy.Mode == "enforce" {
				e = recovery.inspect(ctx, h, &r)
			}
		}
		return finish(e)
	case "autostart_disable", "uninstall":
		// Missing installations remain idempotent, but an unexpected leftover
		// executable cannot be removed without its managed manifest.
		if !r.Installed {
			_, e = run(ctx, h, "[ ! -e "+qbin+" ] && [ ! -L "+qbin+" ]; [ ! -e "+qdir+" ] || [ -d "+qdir+" ]")
			if e != nil {
				return finish(e)
			}
			if r.AutostartState == "disabled" || r.AutostartState == "unavailable" {
				return finish(nil)
			}
		}
		script := operationLock(dir) + state
		if r.Installed {
			script += manifestVersionGuard(d.Version)
		}
		if o.Action == "uninstall" {
			script += absentIntents("upgrade.intent", "protection.intent")
		}
		script += "rm -f \"$d/autostart.enabled\"; "
		if o.Action == "uninstall" {
			script += agentStop()
			if d.ID == "banhack233" {
				script += firewallRemove(dir)
			}
		}
		if r.AutostartState != "unavailable" {
			script += cron.replace(base, false)
		}
		script += "rm -f \"$d/agent-launcher.sh\"; "
		if o.Action == "uninstall" {
			if r.Installed {
				script += "[ ! -L \"$d/manifest\" ] && [ ! -L \"$b\" ] && [ ! -L \"$d/" + d.Version + "\" ]; read -r version expected config_hash < \"$d/manifest\"; [ \"$version\" = " + quote(d.Version) + " ]; if [ -e \"$b\" ]; then [ \"$(sha256sum \"$b\" | cut -d ' ' -f 1)\" = \"$expected\" ]; rm \"$b\"; fi; rm \"$d/manifest\"; rmdir \"$d/" + d.Version + "\" 2>/dev/null || true; "
			}
			script += "printf missing"
		} else {
			script += "printf disabled"
		}
		r.Output, e = run(ctx, h, script)
		if e == nil {
			r.Autostart, r.AutostartState = false, "disabled"
			if o.Action == "uninstall" {
				r.Installed, r.Running, r.State = false, false, "missing"
			}
		}
		return finish(e)
	case "doctor", "scan", "keepalive_preview", "keepalive_apply":
		args := map[string]string{"doctor": "doctor -config \"$c\"", "scan": "malware-scan -config \"$c\"", "keepalive_preview": "keepalive", "keepalive_apply": "keepalive -write -ssh-hours 24"}[o.Action]
		// The protected immutable config prevents scan's config-driven direct kill.
		r.Output, e = run(ctx, h, state+check+"\"$b\" "+args)
		return finish(e)
	case "protection_status":
		if r.UID == "0" {
			ownership, inspectErr := firewallInspect(ctx, h, dir)
			if inspectErr != nil {
				r.FirewallState = "unavailable"
				if r.ProtectionMode == "enforce" {
					return finish(inspectErr)
				}
				return finish(nil)
			}
			r.FirewallState = ownership
			if ownership != "owned" && r.ProtectionMode == "enforce" {
				return finish(ErrProtection)
			}
			if ownership == "owned" {
				r.Output, e = run(ctx, h, "nft -j list table inet banhack233")
			}
		} else {
			r.FirewallState = "unavailable"
		}
		return finish(e)
	case "metrics":
		if !r.Running {
			return finish(ErrConflict)
		}
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return h.DialLoopback(ctx) }, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalid }}
		request, _ := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:19100/metrics", nil)
		response, e := client.Do(request)
		if e != nil {
			return finish(e)
		}
		defer response.Body.Close()
		b, e := io.ReadAll(io.LimitReader(response.Body, 4*1024*1024+1))
		if e != nil || response.StatusCode != 200 || len(b) > 4*1024*1024 {
			return finish(ErrConflict)
		}
		r.Output = string(b)
		return finish(nil)
	}
	return finish(fmt.Errorf("%w: action", ErrInvalid))
}
