package releasebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
)

func activationGuardMatches(g maintenance.UpgradeGuard, j upgradeJournal) bool {
	if g.Schema != j.Guard.Schema || g.RootID != j.Guard.RootID || g.ID != j.Guard.ID || g.BinarySHA256 != j.Guard.BinarySHA256 {
		return false
	}
	if g.Phase == "selected" {
		return g.Attempt == ""
	}
	return (g.Phase == "trial" || g.Phase == "active") && validID(j.Attempt) && g.Attempt == j.Attempt
}

type nativeChild struct {
	command *exec.Cmd
	exited  chan struct{}
	err     error
}

func startNative(command *exec.Cmd) (*nativeChild, error) {
	if e := command.Start(); e != nil {
		return nil, e
	}
	p := &nativeChild{command: command, exited: make(chan struct{})}
	go func() { p.err = command.Wait(); close(p.exited) }()
	return p, nil
}
func (p *nativeChild) stop() {
	select {
	case <-p.exited:
		return
	default:
	}
	_ = p.command.Process.Signal(os.Interrupt)
	timer := time.NewTimer(12 * time.Second)
	defer timer.Stop()
	select {
	case <-p.exited:
		return
	case <-timer.C:
		_ = p.command.Process.Kill()
		<-p.exited
	}
}
func (p *nativeChild) wait(ctx context.Context) error {
	select {
	case <-p.exited:
		return p.err
	case <-ctx.Done():
		p.stop()
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	}
}
func nativeCommand(s *stagingRoot, v Installation, m Manifest, stdout, stderr io.Writer, args ...string) *exec.Cmd {
	dir := filepath.Join(s.path, "releases", v.Current.ArchiveSHA256)
	cmd := exec.Command(filepath.Join(dir, nativeExecutable(m)), args...)
	cmd.Env = runtimeEnvironment(v.DataDir, filepath.Join(dir, "web"))
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd
}
func activationURL(address string) (string, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return "", ErrInvalid
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", ErrInvalid
	}
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	return "http://" + net.JoinHostPort(host, port), nil
}
func probeActivation(ctx context.Context, client *http.Client, r maintenance.ActivationRecord, m Manifest, phase string) error {
	origin, e := activationURL(r.Address)
	if e != nil {
		return e
	}
	get := func(path string) ([]byte, int, http.Header, error) {
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
		if e != nil {
			return nil, 0, nil, e
		}
		response, e := client.Do(request)
		if e != nil {
			return nil, 0, nil, e
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
		if e != nil || len(body) > 8<<20 {
			return nil, 0, nil, ErrInvalid
		}
		return body, response.StatusCode, response.Header, nil
	}
	body, code, headers, e := get("/api/health")
	if e != nil || code != 200 || headers.Get("X-JMS-Activation") != r.Attempt || headers.Get("X-JMS-Activation-Phase") != phase {
		return ErrInstallPending
	}
	var health struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &health) != nil || health.Version != m.Version {
		return ErrInstallConflict
	}
	if phase == "trial" {
		body, code, headers, e = get("/")
		if e != nil || code != 200 || headers.Get("X-JMS-Activation") != r.Attempt || headers.Get("X-JMS-Activation-Phase") != "trial" {
			return ErrInstallPending
		}
		sum := sha256.Sum256(body)
		index := m.Files["web/index.html"]
		if index.Bytes <= 0 || int64(len(body)) != index.Bytes || hex.EncodeToString(sum[:]) != index.SHA256 {
			return ErrInstallConflict
		}
		for _, path := range []string{"/api/v1/assets", "/ws"} {
			body, code, _, e = get(path)
			var state struct {
				Code string `json:"code"`
			}
			if e != nil || code != 503 || json.Unmarshal(body, &state) != nil || state.Code != "upgrade_activation_pending" {
				return ErrInstallConflict
			}
		}
	}
	return nil
}
func awaitNativeHealth(ctx context.Context, child *nativeChild, data string, j upgradeJournal, m Manifest, phase string) (maintenance.ActivationRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ticker := time.NewTicker(75 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-child.exited:
			return maintenance.ActivationRecord{}, ErrInstallPending
		default:
		}
		r, e := maintenance.ReadActivation(data)
		if e == nil && r.RootID == j.RootID && r.ID == j.ID && r.Attempt == j.Attempt && r.PID == child.command.Process.Pid && r.BinarySHA256 == j.Guard.BinarySHA256 && r.Version == m.Version && r.Phase == phase {
			if e = probeActivation(ctx, client, r, m, phase); e == nil {
				select {
				case <-child.exited:
					return r, ErrInstallPending
				default:
					return r, nil
				}
			}
			if errors.Is(e, ErrInstallConflict) {
				return r, e
			}
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return r, e
		}
		select {
		case <-child.exited:
			return r, ErrInstallPending
		case <-ctx.Done():
			return r, ctx.Err()
		case <-ticker.C:
		}
	}
}

// RunInstalledWithPassphrase owns and clears password after first-start
// acceptance/rollback. Already-active restarts do not need a checkpoint key.
func RunInstalledWithPassphrase(ctx context.Context, path string, password []byte, stdout, stderr io.Writer) error {
	defer clear(password)
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	s, e := openStagingRoot(path, runtime.GOOS, runtime.GOARCH, false)
	if e != nil {
		return e
	}
	closed := false
	defer func() {
		if !closed {
			s.close()
		}
	}()
	v, e := s.installation()
	if e != nil || !v.Current.valid() {
		return ErrInstallConflict
	}
	data, e := canonicalData(s, v.DataDir)
	if e != nil {
		return e
	}
	g, e := maintenance.ReadUpgradeGuard(data)
	if e != nil || g.RootID != s.owner.ID {
		return ErrInstallConflict
	}
	j, journalErr := s.readUpgrade()
	pending := journalErr == nil
	if journalErr != nil && !errors.Is(journalErr, os.ErrNotExist) {
		return journalErr
	}
	if pending && (j.Schema != 2 || j.After.Schema == 0 || !reflect.DeepEqual(v, j.After) || !activationGuardMatches(g, j)) {
		return ErrInstallPending
	}
	if pending && g.Phase == "active" {
		lock, e := maintenance.Acquire(data)
		if e != nil {
			return e
		}
		e = s.finishInstallJournal()
		lock.Close()
		if e != nil {
			return e
		}
		pending = false
	}
	m, inspectErr := s.inspect(ctx, "releases/"+v.Current.ArchiveSHA256, v.Current.ArchiveSHA256)
	if !pending {
		if inspectErr != nil {
			return inspectErr
		}
		if g.Phase != "active" || v.Current != (Selection{v.Current.ArchiveSHA256, m.Version, m.Commit}) || g.BinarySHA256 != m.Files[nativeExecutable(m)].SHA256 {
			return ErrInstallConflict
		}
		child, e := startNative(nativeCommand(s, v, m, stdout, stderr))
		if e != nil {
			return e
		}
		s.close()
		closed = true
		clear(password)
		return child.wait(ctx)
	}
	if len(password) < 12 || len(password) > 1024 {
		return ErrActivationKeyRequired
	}
	// Check the passphrase/digest before starting or mutating an activation attempt.
	checkpoint, e := maintenance.Verify(ctx, maintenance.Options{File: j.Result.BackupFile, Passphrase: password})
	if e != nil || !reflect.DeepEqual(checkpoint, j.Result.Backup) {
		return maintenance.ErrIntegrity
	}
	var child *nativeChild
	activationErr := inspectErr
	if activationErr == nil && (m.ActivationProtocol != 1 || v.Current != (Selection{v.Current.ArchiveSHA256, m.Version, m.Commit}) || g.BinarySHA256 != m.Files[nativeExecutable(m)].SHA256) {
		activationErr = ErrInstallConflict
	}
	if activationErr == nil && j.Phase == "awaiting_start" && g.Phase == "selected" {
		lock, e := maintenance.Acquire(data)
		if e != nil {
			return e
		}
		j.Attempt, e = stageID()
		if e == nil {
			j.Phase = "starting"
			e = s.saveUpgrade(j)
		}
		if e == nil {
			g.Phase = "trial"
			g.Attempt = j.Attempt
			e = maintenance.SetUpgradeGuard(lock, g)
		}
		lock.Close()
		if e != nil {
			return e
		}
		child, activationErr = startNative(nativeCommand(s, v, m, stdout, stderr, "--activation-id", j.ID, "--activation-attempt", j.Attempt))
		if activationErr == nil {
			var record maintenance.ActivationRecord
			record, activationErr = awaitNativeHealth(ctx, child, data, j, m, "trial")
			if activationErr == nil {
				j.Phase = "activating"
				activationErr = s.saveUpgrade(j)
			}
			if activationErr == nil {
				activationErr = maintenance.ReleaseActivation(data, record)
			}
			if activationErr == nil {
				_, activationErr = awaitNativeHealth(ctx, child, data, j, m, "active")
			}
		}
		if activationErr == nil {
			if e = s.finishInstallJournal(); e != nil {
				child.stop()
				return e
			}
			s.close()
			closed = true
			clear(password)
			return child.wait(ctx)
		}
	} else if activationErr == nil {
		activationErr = ErrInstallPending
	}
	if child != nil {
		child.stop()
	}
	lock, e := maintenance.Acquire(data)
	if e != nil {
		return ErrInstallPending
	}
	guard, ge := maintenance.ReadUpgradeGuard(data)
	if ge != nil || !activationGuardMatches(guard, j) {
		lock.Close()
		return ErrInstallPending
	}
	if guard.Phase == "active" {
		e = s.finishInstallJournal()
		lock.Close()
		clear(password)
		if e != nil {
			return e
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ErrActivationCommitted
	}
	j.Result.FailureCode = "activation_failed"
	if ctx.Err() != nil {
		j.Result.FailureCode = "activation_cancelled"
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	rolled, rollbackErr := s.rollbackInstall(rollbackCtx, j, lock, password)
	lock.Close()
	clear(password)
	if !errors.Is(rollbackErr, ErrActivationRolledBack) {
		return rollbackErr
	}
	s.close()
	closed = true
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !rolled.Current.valid() {
		return ErrActivationRolledBack
	}
	_, _ = io.WriteString(stderr, "upgrade_activation_rolled_back\n")
	return RunInstalled(ctx, path, stdout, stderr)
}
