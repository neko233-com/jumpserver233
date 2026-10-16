package hostplugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
)

var ErrSystemd = errors.New("systemd manager is unavailable")

type systemdRecord struct {
	Format      int    `json:"format"`
	UID         string `json:"uid"`
	Plugin      string `json:"plugin"`
	Version     string `json:"version"`
	ConfigSHA   string `json:"config_sha"`
	ConfigFile  string `json:"config_file"`
	HelperSHA   string `json:"helper_sha"`
	LauncherSHA string `json:"launcher_sha"`
	UnitSHA     string `json:"unit_sha"`
	Desired     bool   `json:"desired"`
}
type systemdPlan struct {
	dir, home, name, file, manager, raw string
	record                              systemdRecord
	active, enabled                     bool
	state                               string
}

func newSystemdPlan(home, dir string, r systemdRecord) systemdPlan {
	name := "jms233-agent-" + r.Plugin + "-" + digest([]byte(dir))[:16] + ".service"
	base := "/etc/systemd/system"
	manager := "LC_ALL=C /usr/bin/systemctl --system"
	if r.UID != "0" {
		base = path.Join(home, ".config/systemd/user")
		runtime := "/run/user/" + r.UID
		manager = "LC_ALL=C XDG_RUNTIME_DIR=" + quote(runtime) + " DBUS_SESSION_BUS_ADDRESS=" + quote("unix:path="+runtime+"/bus") + " /usr/bin/systemctl --user"
	}
	return systemdPlan{home: home, dir: dir, name: name, file: path.Join(base, name), manager: manager, record: r, state: "disabled"}
}
func unitQuote(s string, exec bool) string {
	s = strings.ReplaceAll(s, "%", "%%")
	if exec {
		s = strings.ReplaceAll(s, "$", "$$")
	}
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return "\"" + s + "\""
}
func (p systemdPlan) unitText() string {
	r := p.record
	wanted := "multi-user.target"
	if r.UID != "0" {
		wanted = "default.target"
	}
	helper := path.Join(p.dir, "agent-recovery-"+r.HelperSHA)
	return "[Unit]\nDescription=JumpServer233 managed " + r.Plugin + " supervisor\nAfter=network.target\nStartLimitIntervalSec=120\nStartLimitBurst=5\n\n[Service]\nType=exec\nExecStart=" + unitQuote(helper, true) + " supervise --directory " + unitQuote(p.dir, true) + " --plugin " + r.Plugin + " --launcher-sha " + r.LauncherSHA + "\nEnvironment=" + unitQuote("HOME="+p.home, false) + "\nEnvironment=PATH=/usr/sbin:/usr/bin:/sbin:/bin\nUMask=0077\nNoNewPrivileges=yes\nKillMode=control-group\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=15\n\n[Install]\nWantedBy=" + wanted + "\n"
}
func validSystemdRecord(r systemdRecord, plugin string) bool {
	uid, e := strconv.ParseUint(r.UID, 10, 32)
	if e != nil || strconv.FormatUint(uid, 10) != r.UID || r.Format != 1 || r.Plugin != plugin || !validDigest(r.ConfigSHA) || !validDigest(r.HelperSHA) || !validDigest(r.LauncherSHA) || !validDigest(r.UnitSHA) {
		return false
	}
	if _, e = LookupVersion(plugin, r.Version); e != nil {
		return false
	}
	return r.ConfigFile == "config.json" || r.ConfigFile == "config-"+r.ConfigSHA+".json"
}
func privateOwner(file, uid string) string {
	q := quote(file)
	return "[ ! -L " + q + " ]; [ -f " + q + " ]; [ \"$(stat -c %u " + q + ")\" = " + quote(uid) + " ]; case $(stat -c %a " + q + ") in 600|640|644|700) ;; *) exit 43;; esac; "
}
func (p systemdPlan) available(ctx context.Context, h Transport) (bool, error) {
	check := "[ \"$(id -u)\" = " + quote(p.record.UID) + " ]; [ -x /usr/bin/systemctl ]; "
	if p.record.UID == "0" {
		check += "[ -d /run/systemd/system ]; "
	} else {
		runtime := "/run/user/" + p.record.UID
		check += "[ -S " + quote(runtime+"/bus") + " ]; [ \"$(/usr/bin/loginctl show-user " + quote(p.record.UID) + " --property=Linger --value)\" = yes ]; "
	}
	_, e := run(ctx, h, check+p.manager+" show-environment >/dev/null; printf ready")
	if errors.Is(e, ErrConflict) {
		return false, nil
	}
	return e == nil, e
}
func (p systemdPlan) markerGuard() string {
	f := path.Join(p.dir, "systemd.enabled")
	return "[ ! -L " + quote(f) + " ]; if [ -e " + quote(f) + " ]; then " + privateOwner(f, p.record.UID) + "[ \"$(stat -c %s " + quote(f) + ")\" -le 64 ]; [ \"$(cat " + quote(f) + ")\" = enabled ]; fi; "
}
func (p systemdPlan) guard() string {
	return "[ \"$(id -u)\" = " + quote(p.record.UID) + " ]; " + privateOwner(path.Join(p.dir, "systemd.json"), p.record.UID) + "[ \"$(sha256sum " + quote(path.Join(p.dir, "systemd.json")) + " | cut -d ' ' -f 1)\" = " + quote(digest([]byte(p.raw))) + " ]; " + privateOwner(p.file, p.record.UID) + "[ \"$(sha256sum " + quote(p.file) + " | cut -d ' ' -f 1)\" = " + quote(p.record.UnitSHA) + " ]; "
}
func (p *systemdPlan) inspect(ctx context.Context, h Transport) error {
	available, availabilityError := p.available(ctx, h)
	if availabilityError != nil {
		return availabilityError
	}
	if !available {
		p.state = "unavailable"
		return ErrSystemd
	}
	if _, e := run(ctx, h, p.guard()+"printf verified"); e != nil {
		p.state = "conflict"
		return integrityFailure(e)
	}
	out, e := run(ctx, h, p.manager+" show "+quote(p.name)+" --no-pager --property=LoadState,ActiveState,UnitFileState,FragmentPath,DropInPaths")
	if e != nil {
		return e
	}
	values := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return ErrConflict
		}
		values[k] = v
	}
	if values["LoadState"] != "loaded" || values["FragmentPath"] != p.file || values["DropInPaths"] != "" || values["UnitFileState"] != "enabled" && values["UnitFileState"] != "disabled" {
		p.state = "conflict"
		return ErrConflict
	}
	p.active = values["ActiveState"] == "active"
	p.enabled = values["UnitFileState"] == "enabled"
	p.state = "disabled"
	if !p.record.Desired && p.enabled {
		p.state = "conflict"
		return ErrConflict
	}
	if p.record.Desired {
		p.state = "paused"
		if p.active && p.enabled {
			p.state = "active"
			raw, e := readPrivateJSON(ctx, h, path.Join(p.dir, "systemd-status.json"), 4096)
			var status hostagent.SupervisorStatus
			if e != nil || json.Unmarshal([]byte(raw), &status) != nil || status.LauncherSHA != p.record.LauncherSHA || status.ErrorCode != "" || time.Since(status.LastTick) > 60*time.Second {
				p.state = "degraded"
			}
		}
	}
	return nil
}
func loadSystemd(ctx context.Context, h Transport, home, dir, plugin string) (*systemdPlan, error) {
	for _, d := range []string{path.Join(home, ".jumpserver233"), path.Join(home, ".jumpserver233/plugins"), dir} {
		if _, e := run(ctx, h, "[ ! -L "+quote(d)+" ]; if [ -e "+quote(d)+" ]; then [ -d "+quote(d)+" ]; fi; printf checked"); e != nil {
			return nil, integrityFailure(e)
		}
	}
	if _, e := run(ctx, h, "f="+quote(path.Join(dir, "systemd.json"))+"; [ ! -L \"$f\" ]; if [ -e \"$f\" ]; then [ -f \"$f\" ]; fi; printf regular"); e != nil {
		return nil, integrityFailure(e)
	}
	raw, e := readPrivateJSON(ctx, h, path.Join(dir, "systemd.json"), 8192)
	if e != nil {
		return nil, integrityFailure(e)
	}
	if raw == "none" {
		return nil, nil
	}
	var r systemdRecord
	if decodeStrict([]byte(raw), &r) != nil || !validSystemdRecord(r, plugin) {
		return nil, ErrIntegrity
	}
	p := newSystemdPlan(home, dir, r)
	p.raw = raw
	if digest([]byte(p.unitText())) != r.UnitSHA {
		return nil, ErrIntegrity
	}
	return &p, p.inspect(ctx, h)
}
func decodeStrict(raw []byte, v any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func (p systemdPlan) process() string {
	d, _ := LookupVersion(p.record.Plugin, p.record.Version)
	return processState(p.dir, path.Join(p.dir, d.Version, d.Executable), path.Join(p.dir, p.record.ConfigFile))
}
func (p systemdPlan) pause(ctx context.Context, h Transport) error {
	lock := "d=" + quote(p.dir) + "; retries=0; until mkdir \"$d/operation.lock\" 2>/dev/null; do retries=$((retries+1)); [ $retries -le 100 ]; sleep 0.1; done; trap 'rmdir \"$d/operation.lock\"' EXIT; "
	_, e := run(ctx, h, lock+p.guard()+p.markerGuard()+"rm -f \"$d/systemd.enabled\"; "+p.manager+" stop "+quote(p.name)+"; printf paused")
	return e
}
func (p *systemdPlan) disable(ctx context.Context, h Transport) error {
	r := p.record
	r.Desired = false
	raw, _ := json.Marshal(r)
	script := operationLock(p.dir) + p.guard() + "[ ! -L \"$d/systemd.next\" ]; printf '%s' " + quote(string(raw)) + " > \"$d/systemd.next\"; chmod 600 \"$d/systemd.next\"; mv \"$d/systemd.next\" \"$d/systemd.json\"; " + p.manager + " disable " + quote(p.name) + " >/dev/null; printf disabled"
	if _, e := run(ctx, h, script); e != nil {
		return e
	}
	p.record = r
	p.raw = string(raw)
	p.active = false
	p.enabled = false
	p.state = "disabled"
	return nil
}
func buildSystemd(ctx context.Context, h Transport, s *Service, home, dir, jobID string, r Result, previous *systemdPlan) (*systemdPlan, error) {
	d, e := LookupVersion(r.Plugin, r.Version)
	if e != nil || !r.Installed {
		return nil, ErrConflict
	}
	manifest, e := run(ctx, h, "[ ! -L "+quote(path.Join(dir, "manifest"))+" ]; cat "+quote(path.Join(dir, "manifest")))
	if e != nil {
		return nil, e
	}
	parts := strings.Fields(manifest)
	if len(parts) != 3 || parts[0] != r.Version || !validDigest(parts[2]) {
		return nil, ErrIntegrity
	}
	artifact, e := d.Artifact(r.Platform)
	if e != nil {
		return nil, e
	}
	blob, e := s.cache.Fetch(ctx, artifact)
	if e != nil {
		return nil, e
	}
	if parts[1] != blob.SHA256 {
		return nil, ErrIntegrity
	}
	cfgPath := path.Join(dir, "config.json")
	if d.ID == "banhack233" {
		_, cfgPath, _, e = loadProtection(ctx, h, dir, parts[2])
		if e != nil {
			return nil, e
		}
	}
	b, e := nativeRecovery(r.Platform, dir, parts[2])
	if e != nil {
		return nil, e
	}
	if e = b.ensure(ctx, h, dir, jobID); e != nil {
		return nil, e
	}
	state := processState(dir, path.Join(dir, d.Version, d.Executable), cfgPath)
	check := installationCheck(d, parts[2]) + "[ \"$expected\" = " + quote(blob.SHA256) + " ]; "
	cron := newCronPlan(dir, d.ID)
	cron.launcher = path.Join(dir, "systemd-launcher.sh")
	prestart := []string{}
	if r.Protection != nil && r.Protection.Mode == "enforce" {
		prestart = append(prestart, b.step("supervisor"))
	}
	launcher := cron.launcherWithMarker(path.Dir(path.Dir(dir)), state, check, d.ID, "systemd.enabled", prestart...)
	launcher = strings.Replace(launcher, "umask 077\n", "umask 077\ntrap 'exit 143' TERM INT\n", 1)
	record := systemdRecord{Format: 1, UID: r.UID, Plugin: d.ID, Version: d.Version, ConfigSHA: parts[2], ConfigFile: path.Base(cfgPath), HelperSHA: b.SHA256, LauncherSHA: digest([]byte(launcher)), Desired: true}
	p := newSystemdPlan(home, dir, record)
	p.record.UnitSHA = digest([]byte(p.unitText()))
	raw, _ := json.Marshal(p.record)
	p.raw = string(raw)
	available, availabilityError := p.available(ctx, h)
	if availabilityError != nil {
		return nil, availabilityError
	}
	if !available {
		return nil, ErrSystemd
	}
	stage := path.Join(dir, jobID+"-systemd")
	if _, e = run(ctx, h, "[ ! -e "+quote(stage)+" ]; [ ! -L "+quote(stage)+" ]; mkdir -m 700 "+quote(stage)); e != nil {
		return nil, e
	}
	for _, v := range [][2]string{{p.name, p.unitText()}, {"launcher", launcher}, {"metadata", p.raw}} {
		if e = h.Upload(ctx, path.Join(stage, v[0]), strings.NewReader(v[1])); e != nil {
			return nil, e
		}
	}
	analyze := strings.Replace(p.manager, "/usr/bin/systemctl", "/usr/bin/systemd-analyze", 1)
	if _, e = run(ctx, h, analyze+" verify "+quote(path.Join(stage, p.name))+" >/dev/null; printf valid"); e != nil {
		return nil, e
	}
	script := operationLock(dir) + state + check + absentIntents("upgrade.intent", "protection.intent") + "[ ! -e \"$d/autostart.enabled\" ]; [ ! -L \"$d/autostart.enabled\" ]; "
	if previous != nil {
		script += previous.guard()
	} else {
		script += "[ ! -e " + quote(p.file) + " ]; [ ! -L " + quote(p.file) + " ]; load=$(" + p.manager + " show " + quote(p.name) + " --property=LoadState --value); [ \"$load\" = not-found ]; "
	}
	// Unit directories are created without altering existing account directories.
	dirs := []string{path.Dir(p.file)}
	if record.UID != "0" {
		dirs = []string{path.Join(home, ".config"), path.Join(home, ".config/systemd"), path.Dir(p.file)}
	}
	for _, dir := range dirs {
		q := quote(dir)
		script += "[ ! -L " + q + " ]; if [ ! -e " + q + " ]; then mkdir -m 700 " + q + "; fi; [ -d " + q + " ]; [ \"$(stat -c %u " + q + ")\" = " + quote(record.UID) + " ]; mode=$(stat -c %a " + q + "); [ $((0$mode & 022)) -eq 0 ]; "
	}
	backup := path.Join(dir, jobID+".systemd-launcher.previous")
	script += "[ ! -L \"$d/systemd-launcher.sh\" ]; if [ -e \"$d/systemd-launcher.sh\" ]; then " + privateOwner(path.Join(dir, "systemd-launcher.sh"), record.UID) + "[ \"$(stat -c %s \"$d/systemd-launcher.sh\")\" -le 131072 ]; [ ! -e " + quote(backup) + " ]; [ ! -L " + quote(backup) + " ]; mv \"$d/systemd-launcher.sh\" " + quote(backup) + "; fi; "
	script += p.markerGuard() + agentStop() + "stage=" + quote(stage) + "; [ \"$(sha256sum \"$stage/" + p.name + "\" | cut -d ' ' -f 1)\" = " + quote(p.record.UnitSHA) + " ]; [ \"$(sha256sum \"$stage/launcher\" | cut -d ' ' -f 1)\" = " + quote(p.record.LauncherSHA) + " ]; [ \"$(sha256sum \"$stage/metadata\" | cut -d ' ' -f 1)\" = " + quote(digest([]byte(p.raw))) + " ]; [ ! -L \"$d/systemd.json\" ]; [ ! -L \"$d/systemd.enabled\" ]; chmod 700 \"$stage/launcher\"; chmod 600 \"$stage/metadata\"; chmod 644 \"$stage/" + p.name + "\"; mv \"$stage/launcher\" \"$d/systemd-launcher.sh\"; mv \"$stage/metadata\" \"$d/systemd.json\"; mv \"$stage/" + p.name + "\" " + quote(p.file) + "; printf enabled > \"$d/systemd.enabled\"; rmdir \"$stage\"; printf published"
	if _, e = run(ctx, h, script); e != nil {
		return nil, e
	}
	if _, e = run(ctx, h, p.guard()+p.manager+" daemon-reload; printf reloaded"); e != nil {
		return nil, e
	}
	if e = p.inspect(ctx, h); e != nil {
		return nil, e
	}
	if _, e = run(ctx, h, p.guard()+p.manager+" enable --now "+quote(p.name)+" >/dev/null; printf started"); e != nil {
		return nil, e
	}
	// Waiting happens after the operation lock is released, so the native
	// supervisor can execute the launcher and publish its first verified PID.
	for i := 0; i < 30; i++ {
		out, e := run(ctx, h, state+"printf '%s' \"$running\"")
		if e == nil && out == "1" {
			if e = p.inspect(ctx, h); e != nil {
				return nil, e
			}
			if p.state == "active" {
				return &p, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, fmt.Errorf("%w: agent did not start", ErrSystemd)
}
