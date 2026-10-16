package hostagent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

type Report struct {
	Version    string    `json:"version"`
	State      string    `json:"state"`
	ActiveBans int       `json:"active_bans"`
	CheckedAt  time.Time `json:"checked_at"`
	ConfigSHA  string    `json:"config_sha"`
}

func regularRead(path string, limit int) ([]byte, error) {
	// Open the final component without following symlinks, then inspect/read
	// that one descriptor. An atomic rename by the live daemon cannot turn a
	// consistent old snapshot into an apparent integrity failure.
	f, e := openSnapshot(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || after.Mode().Perm()&0022 != 0 || !owned(after) || after.Size() > int64(limit) {
		return nil, ErrState
	}
	data, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(data) > limit {
		return nil, ErrState
	}
	return data, nil
}

func validateDirectory(dir string) error { return validateDirectoryFor(dir, "banhack233") }
func validateDirectoryFor(dir, plugin string) error {
	if os.Geteuid() < 0 {
		return ErrUnsupported
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || filepath.Base(dir) != plugin || len(dir) > 2048 || strings.IndexFunc(dir, unicode.IsControl) >= 0 {
		return ErrConfiguration
	}
	for current := dir; current != filepath.Dir(current); current = filepath.Dir(current) {
		info, e := os.Lstat(current)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrConfiguration
		}
	}
	for current, level := dir, 0; level < 3; current, level = filepath.Dir(current), level+1 {
		info, e := os.Stat(current)
		if e != nil || !owned(info) || info.Mode().Perm()&0022 != 0 {
			return ErrConfiguration
		}
	}
	return nil
}

func loadPlan(dir, hash string, now time.Time) (Plan, error) {
	if os.Geteuid() != 0 {
		return Plan{}, ErrUnsupported
	}
	decoded, e := hex.DecodeString(hash)
	if e != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != hash {
		return Plan{}, ErrConfiguration
	}
	if e = validateDirectory(dir); e != nil {
		return Plan{}, e
	}
	manifest, e := regularRead(filepath.Join(dir, "manifest"), 1024)
	if e != nil {
		return Plan{}, ErrConfiguration
	}
	parts := strings.Fields(string(manifest))
	if len(parts) != 3 || parts[0] != "0.2.2" && parts[0] != "0.2.3" || parts[2] != hash {
		return Plan{}, ErrConfiguration
	}
	config, e := regularRead(filepath.Join(dir, "config-"+hash+".json"), 65536)
	if e != nil {
		return Plan{}, ErrConfiguration
	}
	state, e := regularRead(filepath.Join(dir, "state.json"), MaxStateBytes)
	if errors.Is(e, os.ErrNotExist) {
		state = nil
	} else if e != nil {
		return Plan{}, ErrState
	}
	return BuildPlan(dir, hash, config, state, now)
}

type boundedOutput struct {
	data  []byte
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		return 0, ErrKernel
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func nft(ctx context.Context, input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Never search the SSH account's writable PATH for a privileged executable.
	var bin string
	for _, p := range []string{"/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"} {
		if s, e := os.Stat(p); e == nil && s.Mode().IsRegular() {
			bin = p
			break
		}
	}
	if bin == "" {
		return nil, ErrKernel
	}
	command := exec.CommandContext(ctx, bin, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	command.Stdin = strings.NewReader(input)
	stdout := &boundedOutput{limit: MaxStateBytes}
	stderr := &boundedOutput{limit: 4096}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if err != nil {
		return stdout.data, ErrKernel
	}
	return stdout.data, nil
}

func table(ctx context.Context, p Plan) (uint64, error) {
	// A successful table inventory distinguishes absence from a permission or
	// transport error. JSON on nft 1.0.6 omits the kernel ownership comment.
	raw, e := nft(ctx, "", "-j", "list", "tables")
	if e != nil {
		return 0, e
	}
	var v struct {
		NFTables []struct {
			Table *struct {
				Family, Name string
				Handle       uint64
			}
		}
	}
	if json.Unmarshal(raw, &v) != nil {
		return 0, ErrKernel
	}
	for _, item := range v.NFTables {
		if item.Table != nil && item.Table.Family == "inet" && item.Table.Name == "banhack233" {
			if item.Table.Handle == 0 {
				return 0, ErrKernel
			}
			raw, e = nft(ctx, "", "-t", "list", "table", "inet", "banhack233")
			if e != nil {
				return 0, e
			}
			if !TableOwned(string(raw), p.Owner) {
				return 0, ErrForeign
			}
			return item.Table.Handle, nil
		}
	}
	return 0, nil
}

func Check(ctx context.Context, dir, hash string) (Report, error) {
	now := time.Now().UTC()
	r := Report{Version: Version, State: "unknown", CheckedAt: now, ConfigSHA: hash}
	p, e := loadPlan(dir, hash, now)
	if e != nil {
		return r, e
	}
	r.ActiveBans = len(p.Bans)
	exists, e := table(ctx, p)
	if e != nil {
		return r, e
	}
	r.State = "required"
	if exists == 0 {
		return r, nil
	}
	raw, e := nft(ctx, "", "-j", "list", "table", "inet", "banhack233")
	if e != nil {
		return r, e
	}
	if p.Healthy(raw) {
		r.State = "ready"
	}
	return r, nil
}

// Restore is called only with the managed process stopped. The same advisory
// lock used by BanHack prevents any second daemon from mutating its state while
// the entire owned table is rebuilt in one atomic nft transaction.
func Restore(ctx context.Context, dir, hash string, triggers ...string) (r Report, result error) {
	now := time.Now().UTC()
	r = Report{Version: Version, State: "unknown", CheckedAt: now, ConfigSHA: hash}
	trigger := "manual"
	if len(triggers) > 1 {
		return r, ErrConfiguration
	}
	if len(triggers) == 1 {
		trigger = triggers[0]
	}
	if !validTrigger(trigger) {
		return r, ErrConfiguration
	}
	if _, e := loadPlan(dir, hash, now); e != nil {
		return r, e
	}
	unlock, e := stateLock(filepath.Join(dir, "state.json.lock"))
	if e != nil {
		return r, e
	}
	defer unlock()
	p, e := loadPlan(dir, hash, time.Now().UTC())
	if e != nil {
		return r, e
	}
	started, e := beginRepairEvent(dir, hash, trigger, len(p.Bans))
	if e != nil {
		return r, e
	}
	defer func() {
		terminal := started
		terminal.Kind = "repair_completed"
		terminal.ErrorCode = ""
		if result != nil {
			terminal.Kind = "repair_failed"
			terminal.ErrorCode = stableRepairError(result)
		}
		if _, e := appendEvent(dir, terminal); e != nil {
			result = errors.Join(result, ErrJournal)
		}
	}()
	// Preserve an unknown existing report rather than overwrite unrelated data.
	if previous, e := regularRead(filepath.Join(dir, "recovery.json"), 4096); e == nil {
		var old Report
		d := json.NewDecoder(strings.NewReader(string(previous)))
		d.DisallowUnknownFields()
		if d.Decode(&old) != nil || d.Decode(new(any)) != io.EOF || (old.Version != "1" && old.Version != "2" && old.Version != Version) || old.State != "restored" || !validHex(old.ConfigSHA, 32) || old.CheckedAt.IsZero() {
			return r, ErrState
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return r, ErrState
	}
	exists, e := table(ctx, p)
	if e != nil {
		return r, e
	}
	// Read again immediately before building the transaction. Existing bans keep
	// their original expiry rather than receiving a fresh full ban duration.
	script := p.Rules(time.Now().UTC(), exists)
	if _, e = nft(ctx, script, "-c", "-f", "-"); e != nil {
		return r, e
	}
	// Recompute remaining durations after the validation subprocess.
	script = p.Rules(time.Now().UTC(), exists)
	if _, e = nft(ctx, script, "-f", "-"); e != nil {
		return r, e
	}
	r.State = "restored"
	r.ActiveBans = len(p.Bans)
	r.CheckedAt = time.Now().UTC()
	data, _ := json.Marshal(r)
	next, e := os.CreateTemp(dir, ".recovery-*")
	if e != nil {
		return r, ErrState
	}
	name := next.Name()
	defer os.Remove(name)
	if _, e = next.Write(data); e != nil {
		next.Close()
		return r, ErrState
	}
	if e = next.Sync(); e != nil {
		next.Close()
		return r, ErrState
	}
	if e = next.Close(); e != nil {
		return r, ErrState
	}
	if s, e := os.Lstat(filepath.Join(dir, "recovery.json")); e == nil && (!s.Mode().IsRegular() || s.Mode()&os.ModeSymlink != 0) {
		return r, ErrState
	}
	if e = os.Rename(name, filepath.Join(dir, "recovery.json")); e != nil {
		return r, ErrState
	}
	return r, nil
}

func stableRepairError(e error) string {
	for _, known := range []error{ErrJournal, ErrConfiguration, ErrState, ErrForeign, ErrKernel, ErrBusy, ErrUnsupported} {
		if errors.Is(e, known) {
			return known.Error()
		}
	}
	return ErrKernel.Error()
}
