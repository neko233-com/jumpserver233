package releasebundle

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
)

const installationFile = ".jms233-installation.json"
const upgradeJournalFile = ".jms233-upgrade.json"

var installRequestID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,80}$`)
var ErrInstallConflict = errors.New("installation revision, request or data binding conflicts")
var ErrPreflightRolledBack = errors.New("target preflight failed; the original data checkpoint and version were restored")
var ErrUpgradeAborted = errors.New("upgrade preparation was aborted without running the target")
var ErrInstallPending = errors.New("upgrade recovery required; use jms update install-recover before restarting")
var ErrActivationRolledBack = errors.New("candidate startup was not accepted; the original data checkpoint and version were restored")
var ErrActivationKeyRequired = errors.New("first startup requires the upgrade checkpoint passphrase via --passphrase-file or protected terminal input")
var ErrActivationCommitted = errors.New("candidate failed after activation committed; selected version and new data were retained")

type Selection struct {
	ArchiveSHA256 string `json:"archive_sha256"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
}
type InstallResult struct {
	ID               string             `json:"transaction_id"`
	RequestID        string             `json:"request_id"`
	ExpectedRevision int                `json:"expected_revision"`
	Revision         int                `json:"revision"`
	DataDir          string             `json:"data_dir"`
	Current          Selection          `json:"current"`
	Target           Selection          `json:"target"`
	Status           string             `json:"status"`
	Backup           maintenance.Result `json:"backup"`
	BackupFile       string             `json:"backup_file,omitempty"`
	PreviousDataDir  string             `json:"previous_data_dir,omitempty"`
	Unchanged        bool               `json:"unchanged"`
	FailureCode      string             `json:"failure_code,omitempty"`
}
type Installation struct {
	Schema          int             `json:"schema"`
	RootID          string          `json:"root_id"`
	Revision        int             `json:"revision"`
	DataDir         string          `json:"data_dir"`
	Current         Selection       `json:"current"`
	Receipts        []InstallResult `json:"receipts"`
	PendingUpgrade  string          `json:"pending_upgrade,omitempty"`
	ActivationState string          `json:"activation_state,omitempty"`
}
type InstallOptions struct {
	Root, DataDir, ArchiveSHA256, RequestID, SourceVersion, ExternalVaultKey string
	Revision                                                                 int
	Passphrase                                                               []byte
}
type upgradeJournal struct {
	Schema      int                       `json:"schema"`
	RootID      string                    `json:"root_id"`
	ID          string                    `json:"transaction_id"`
	Phase       string                    `json:"phase"`
	Before      Installation              `json:"before"`
	After       Installation              `json:"after"`
	BeforeGuard *maintenance.UpgradeGuard `json:"before_guard,omitempty"`
	Guard       maintenance.UpgradeGuard  `json:"guard"`
	Result      InstallResult             `json:"result"`
	Attempt     string                    `json:"activation_attempt,omitempty"`
}
type dataChecker func(context.Context, string, string, string, string) error

func (s Selection) valid() bool {
	return digest.MatchString(s.ArchiveSHA256) && version.MatchString(s.Version) && commit.MatchString(s.Commit)
}
func (s *stagingRoot) validInstallation(v Installation) bool {
	if v.Schema != 1 || v.RootID != s.owner.ID || v.PendingUpgrade != "" || v.ActivationState != "" || v.Revision < 0 || len(v.Receipts) > 100 || v.Current != (Selection{}) && !v.Current.valid() {
		return false
	}
	if v.DataDir != "" && !filepath.IsAbs(v.DataDir) {
		return false
	}
	if v.Current.valid() && (v.DataDir == "" || v.Revision == 0) {
		return false
	}
	seen := map[string]bool{}
	for _, r := range v.Receipts {
		if !validID(r.ID) || !installRequestID.MatchString(r.RequestID) || seen[r.RequestID] || !r.Target.valid() || r.Revision < 0 || r.ExpectedRevision < 0 || r.DataDir != v.DataDir || r.Status != "selected" && r.Status != "rolled_back" && r.Status != "aborted" {
			return false
		}
		seen[r.RequestID] = true
	}
	return true
}
func (s *stagingRoot) installation() (Installation, error) {
	var v Installation
	e := readStageJSON(s.root, installationFile, &v)
	if errors.Is(e, os.ErrNotExist) {
		return Installation{Schema: 1, RootID: s.owner.ID}, nil
	}
	if e != nil {
		return v, e
	}
	if !s.validInstallation(v) {
		return v, ErrInstallConflict
	}
	return v, nil
}
func (s *stagingRoot) saveInstallation(v Installation) error {
	if !s.validInstallation(v) {
		return ErrInstallConflict
	}
	if e := writeStageJSON(s.root, installationFile, v, false); e != nil {
		return e
	}
	return syncStageDirectory(s.path)
}
func (s *stagingRoot) saveUpgrade(j upgradeJournal) error {
	if e := writeStageJSON(s.root, upgradeJournalFile, j, false); e != nil {
		return e
	}
	return syncStageDirectory(s.path)
}
func cloneInstallation(v Installation) Installation {
	v.Receipts = append([]InstallResult(nil), v.Receipts...)
	return v
}
func receiptState(v Installation, r InstallResult) Installation {
	v = cloneInstallation(v)
	v.DataDir = r.DataDir
	v.Receipts = append(v.Receipts, r)
	if len(v.Receipts) > 100 {
		v.Receipts = v.Receipts[len(v.Receipts)-100:]
	}
	return v
}
func resultError(r InstallResult) error {
	if r.Status == "rolled_back" {
		if r.FailureCode == "activation_failed" || r.FailureCode == "activation_cancelled" {
			return ErrActivationRolledBack
		}
		return ErrPreflightRolledBack
	}
	if r.Status == "aborted" {
		return ErrUpgradeAborted
	}
	return nil
}
func overlapping(a, b string) bool {
	rel, e := filepath.Rel(a, b)
	return e == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
func canonicalData(s *stagingRoot, data string) (string, error) {
	abs, e := filepath.Abs(data)
	if e != nil || data == "" {
		return "", ErrInvalid
	}
	canonical, e := filepath.EvalSymlinks(abs)
	if e != nil {
		return "", e
	}
	info, e := os.Lstat(canonical)
	if e != nil || !info.IsDir() || len(canonical) > 4096 || len(s.path) > 4096 || filepath.Dir(canonical) == canonical || overlapping(s.path, canonical) || overlapping(canonical, s.path) {
		return "", ErrInstallConflict
	}
	return canonical, nil
}
func versionGreater(a, b string) bool {
	if !version.MatchString(a) || !version.MatchString(b) {
		return false
	}
	x, y := strings.Split(a[1:], "."), strings.Split(b[1:], ".")
	for i := range x {
		av, _ := strconv.Atoi(x[i])
		bv, _ := strconv.Atoi(y[i])
		if av != bv {
			return av > bv
		}
	}
	return false
}
func nativeExecutable(m Manifest) string {
	if m.Platform == "windows" {
		return "jms233-server.exe"
	}
	return "jms233-server"
}
func runtimeEnvironment(data, web string) []string {
	var env []string
	for _, v := range os.Environ() {
		k, _, _ := strings.Cut(v, "=")
		switch strings.ToUpper(k) {
		case "JMS_DATA_DIR", "JMS_WEB_DIR", "JMS_VERSION", "JMS_CLUSTER_MODE", "JMS_DATABASE_URL", "JMS_RELEASE_ROOT":
			continue
		}
		env = append(env, v)
	}
	return append(env, "JMS_DATA_DIR="+data, "JMS_WEB_DIR="+web, "JMS_CLUSTER_MODE=false")
}
func nativeDataCheck(ctx context.Context, executable, web, data, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "--check-data", "--upgrade-id", id)
	cmd.Env = runtimeEnvironment(data, web)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return ErrPreflightRolledBack
	}
	return nil
}

// Install selects a staged native version only after a consistent encrypted
// checkpoint and the target binary's offline store preflight. It never starts
// the production listener or any external scheduler during the transaction.
func Install(ctx context.Context, opt InstallOptions) (InstallResult, error) {
	return install(ctx, opt, nativeDataCheck)
}
func install(ctx context.Context, opt InstallOptions, check dataChecker) (result InstallResult, err error) {
	if !digest.MatchString(opt.ArchiveSHA256) || !installRequestID.MatchString(opt.RequestID) || opt.Revision < 0 || len(opt.Passphrase) < 12 || len(opt.Passphrase) > 1024 || len(opt.SourceVersion) > 128 || check == nil {
		return result, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return result, e
	}
	s, e := openStagingRoot(opt.Root, runtime.GOOS, runtime.GOARCH, false)
	if e != nil {
		return result, e
	}
	defer s.close()
	pending := false
	if _, e = s.readUpgrade(); e == nil {
		pending = true
	} else if !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	data, e := canonicalData(s, opt.DataDir)
	if e != nil {
		return result, e
	}
	before, e := s.installation()
	if e != nil {
		return result, e
	}
	if before.DataDir != "" && before.DataDir != data {
		return result, ErrInstallConflict
	}
	for _, r := range before.Receipts {
		if r.RequestID == opt.RequestID {
			if r.Target.ArchiveSHA256 != opt.ArchiveSHA256 || r.ExpectedRevision != opt.Revision || r.DataDir != data {
				return result, ErrInstallConflict
			}
			r.Unchanged = true
			return r, resultError(r)
		}
	}
	if before.Revision != opt.Revision {
		return result, ErrInstallConflict
	}
	if pending {
		return result, ErrInstallPending
	}
	m, e := s.inspect(ctx, "releases/"+opt.ArchiveSHA256, opt.ArchiveSHA256)
	if e != nil {
		return result, e
	}
	if m.PreflightProtocol != 1 || m.ActivationProtocol != 1 {
		return result, ErrInvalid
	}
	if before.Current.ArchiveSHA256 == opt.ArchiveSHA256 {
		g, e := maintenance.ReadUpgradeGuard(data)
		if e != nil || before.Current != (Selection{opt.ArchiveSHA256, m.Version, m.Commit}) || g.RootID != s.owner.ID || g.Phase != "active" || g.BinarySHA256 != m.Files[nativeExecutable(m)].SHA256 {
			return result, ErrInstallConflict
		}
		return InstallResult{Current: before.Current, Target: before.Current, Revision: before.Revision, ExpectedRevision: opt.Revision, DataDir: data, Status: "selected", Unchanged: true}, nil
	}
	if before.Current.valid() && !versionGreater(m.Version, before.Current.Version) {
		return result, ErrInstallConflict
	}
	lock, e := maintenance.Acquire(data)
	if e != nil {
		return result, e
	}
	defer func() {
		if lock != nil {
			lock.Close()
		}
	}()
	if e = maintenance.UpgradeSource(lock); e != nil {
		return result, e
	}
	var oldGuard *maintenance.UpgradeGuard
	if g, e := maintenance.ReadUpgradeGuard(data); e == nil {
		if g.RootID != s.owner.ID || g.Phase != "active" {
			return result, ErrInstallConflict
		}
		oldGuard = &g
	} else if !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	if before.Current.valid() != (oldGuard != nil) {
		return result, ErrInstallConflict
	}
	if before.Current.valid() {
		if oldGuard == nil || oldGuard.BinarySHA256 != mServerDigest(ctx, s, before.Current) {
			return result, ErrInstallConflict
		}
	}
	if e = s.root.Mkdir("backups", 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return result, e
	}
	info, e := s.root.Lstat("backups")
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return result, ErrInstallConflict
	}
	id, e := stageID()
	if e != nil {
		return result, e
	}
	result = InstallResult{ID: id, RequestID: opt.RequestID, ExpectedRevision: opt.Revision, Revision: before.Revision, DataDir: data, Current: before.Current, Target: Selection{opt.ArchiveSHA256, m.Version, m.Commit}, Status: "preparing", BackupFile: filepath.Join(s.path, "backups", id+".jmsbackup")}
	j := upgradeJournal{Schema: 2, RootID: s.owner.ID, ID: id, Phase: "preparing", Before: before, BeforeGuard: oldGuard, Guard: maintenance.UpgradeGuard{Schema: 1, RootID: s.owner.ID, ID: id, BinarySHA256: m.Files[nativeExecutable(m)].SHA256, Phase: "pending"}, Result: result}
	if e = s.saveUpgrade(j); e != nil {
		return result, e
	}
	if e = maintenance.SetUpgradeGuard(lock, j.Guard); e != nil {
		return result, ErrInstallPending
	}
	backupOpt := maintenance.Options{DataDir: data, File: result.BackupFile, Version: opt.SourceVersion, ExternalVaultKey: opt.ExternalVaultKey, Passphrase: opt.Passphrase, Replace: true}
	if before.Current.valid() {
		backupOpt.Version = before.Current.Version
	}
	j.Result.Backup, e = maintenance.CreateLocked(ctx, backupOpt, lock)
	if e != nil {
		return result, ErrInstallPending
	}
	verified, e := maintenance.Verify(ctx, backupOpt)
	if e != nil || !reflect.DeepEqual(verified, j.Result.Backup) {
		return result, ErrInstallPending
	}
	j.Phase = "checking"
	if e = s.saveUpgrade(j); e != nil {
		return result, e
	}
	if e = lock.Close(); e != nil {
		return result, e
	}
	lock = nil
	directory := filepath.Join(s.path, "releases", opt.ArchiveSHA256)
	checkErr := check(ctx, filepath.Join(directory, nativeExecutable(m)), filepath.Join(directory, "web"), data, id)
	lock, e = maintenance.Acquire(data)
	if e != nil {
		return j.Result, ErrInstallPending
	}
	if guard, e := maintenance.ReadUpgradeGuard(data); e != nil || guard != j.Guard {
		return j.Result, ErrInstallPending
	}
	if checkErr != nil || ctx.Err() != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		return s.rollbackInstall(rollbackCtx, j, lock, opt.Passphrase)
	}
	j.Result.Status = "selected"
	j.Result.Current = j.Result.Target
	j.Result.Revision++
	j.After = receiptState(before, j.Result)
	j.After.Current = j.Result.Target
	j.After.Revision = j.Result.Revision
	j.Phase = "selecting"
	if e = s.saveUpgrade(j); e != nil {
		return j.Result, e
	}
	if e = s.saveInstallation(j.After); e != nil {
		return j.Result, e
	}
	g := j.Guard
	g.Phase = "selected"
	if e = maintenance.SetUpgradeGuard(lock, g); e != nil {
		return j.Result, ErrInstallPending
	}
	j.Phase = "awaiting_start"
	if e = s.saveUpgrade(j); e != nil {
		return j.Result, e
	}
	return j.Result, nil
}
func mServerDigest(ctx context.Context, s *stagingRoot, selected Selection) string {
	m, e := s.inspect(ctx, "releases/"+selected.ArchiveSHA256, selected.ArchiveSHA256)
	if e != nil || selected != (Selection{selected.ArchiveSHA256, m.Version, m.Commit}) {
		return ""
	}
	return m.Files[nativeExecutable(m)].SHA256
}
func (s *stagingRoot) finishInstallJournal() error {
	if e := s.root.Remove(upgradeJournalFile); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return syncStageDirectory(s.path)
}
func (s *stagingRoot) commitInstall(j upgradeJournal, lock *maintenance.Lock) (InstallResult, error) {
	g := j.Guard
	g.Phase = "active"
	if current, e := maintenance.ReadUpgradeGuard(lock.DataDir); e != nil || current != j.Guard && current != g {
		return j.Result, ErrInstallPending
	}
	if e := maintenance.SetUpgradeGuard(lock, g); e != nil {
		return j.Result, ErrInstallPending
	}
	if e := s.finishInstallJournal(); e != nil {
		return j.Result, e
	}
	return j.Result, nil
}
func (s *stagingRoot) rollbackInstall(ctx context.Context, j upgradeJournal, lock *maintenance.Lock, password []byte) (InstallResult, error) {
	r := j.Result
	current, e := s.installation()
	if e != nil {
		return r, e
	}
	selected := j.Schema == 2 && j.After.Schema != 0 && reflect.DeepEqual(current, j.After)
	if selected && r.FailureCode == "" {
		r.FailureCode = "activation_failed"
		j.Result = r
	}
	guard, guardErr := maintenance.ReadUpgradeGuard(lock.DataDir)
	if guardErr != nil {
		return r, guardErr
	}
	if guard.Phase == "active" && guard.ID == j.ID {
		return r, ErrInstallConflict
	}
	if j.Phase != "preparing" {
		j.Phase = "rolling_back"
		if e := s.saveUpgrade(j); e != nil {
			return r, e
		}
		opt := maintenance.Options{DataDir: lock.DataDir, File: r.BackupFile, Passphrase: password, Replace: true}
		verified, e := maintenance.Verify(ctx, opt)
		if e != nil || !reflect.DeepEqual(verified, r.Backup) {
			return r, maintenance.ErrIntegrity
		}
		restored, e := maintenance.RestoreUpgradeCheckpoint(ctx, opt, lock, s.owner.ID, j.ID)
		if e != nil {
			return r, e
		}
		r.PreviousDataDir = restored.PreviousDataDir
		r.Status = "rolled_back"
	} else {
		if _, e := os.Lstat(r.BackupFile); e == nil {
			verified, e := maintenance.Verify(ctx, maintenance.Options{File: r.BackupFile, Passphrase: password})
			if e != nil {
				return r, maintenance.ErrIntegrity
			}
			r.Backup = verified
		} else if !errors.Is(e, os.ErrNotExist) {
			return r, e
		}
		r.Status = "aborted"
	}
	r.Current = j.Before.Current
	r.Revision = j.Before.Revision
	if selected {
		r.Revision = j.After.Revision + 1
	}
	if e := s.saveInstallation(rollbackState(j.Before, r)); e != nil {
		return r, e
	}
	if e := maintenance.RestoreUpgradeGuard(lock, s.owner.ID, j.ID, j.BeforeGuard); e != nil {
		return r, e
	}
	if e := s.finishInstallJournal(); e != nil {
		return r, e
	}
	return r, resultError(r)
}
func rollbackState(before Installation, r InstallResult) Installation {
	v := receiptState(before, r)
	v.Revision = r.Revision
	v.Current = r.Current
	return v
}

func (s *stagingRoot) readUpgrade() (upgradeJournal, error) {
	var j upgradeJournal
	if e := readStageJSON(s.root, upgradeJournalFile, &j); e != nil {
		return j, e
	}
	validPhase := j.Phase == "preparing" || j.Phase == "checking" || j.Phase == "rolling_back" || j.Schema == 1 && j.Phase == "committing" || j.Schema == 2 && (j.Phase == "selecting" || j.Phase == "awaiting_start" || j.Phase == "starting" || j.Phase == "activating")
	if j.Schema != 1 && j.Schema != 2 || !validPhase || j.RootID != s.owner.ID || !validID(j.ID) || j.Result.ID != j.ID || !s.validInstallation(j.Before) || !j.Result.Target.valid() || !installRequestID.MatchString(j.Result.RequestID) || j.Result.ExpectedRevision != j.Before.Revision || j.Guard.ID != j.ID || j.Guard.RootID != s.owner.ID || j.Guard.Phase != "pending" || j.Guard.Attempt != "" || !digest.MatchString(j.Guard.BinarySHA256) || j.Result.BackupFile != filepath.Join(s.path, "backups", j.ID+".jmsbackup") {
		return j, ErrInstallConflict
	}
	data, e := canonicalData(s, j.Result.DataDir)
	if e != nil || data != j.Result.DataDir || j.Before.DataDir != "" && data != j.Before.DataDir {
		return j, ErrInstallConflict
	}
	requiresAfter := j.Phase == "committing" || j.Phase == "selecting" || j.Phase == "awaiting_start" || j.Phase == "starting" || j.Phase == "activating" || j.After.Schema != 0
	if requiresAfter && (!s.validInstallation(j.After) || j.After.Current != j.Result.Target || j.After.Revision != j.Before.Revision+1) {
		return j, ErrInstallConflict
	}
	if j.Attempt != "" && !validID(j.Attempt) || (j.Phase == "starting" || j.Phase == "activating") && !validID(j.Attempt) {
		return j, ErrInstallConflict
	}
	if j.BeforeGuard != nil && (j.BeforeGuard.Schema != 1 || j.BeforeGuard.RootID != s.owner.ID || j.BeforeGuard.Phase != "active" || !validID(j.BeforeGuard.ID) || !digest.MatchString(j.BeforeGuard.BinarySHA256)) {
		return j, ErrInstallConflict
	}
	return j, nil
}

// RecoverInstallation rolls back an uncommitted transaction, or completes an
// already durable selection. It never rolls back a committed version to an old
// checkpoint that might predate new production writes.
func RecoverInstallation(ctx context.Context, path string, password []byte) (InstallResult, error) {
	var result InstallResult
	if len(password) < 12 || len(password) > 1024 {
		return result, ErrInvalid
	}
	s, e := openStagingRoot(path, runtime.GOOS, runtime.GOARCH, false)
	if e != nil {
		return result, e
	}
	defer s.close()
	j, e := s.readUpgrade()
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return InstallResult{Status: "no_pending_upgrade", Unchanged: true}, nil
		}
		return result, e
	}
	lock, e := maintenance.Acquire(j.Result.DataDir)
	if e != nil {
		return result, e
	}
	defer lock.Close()
	current, e := s.installation()
	if e != nil {
		return result, e
	}
	if j.Phase == "committing" && reflect.DeepEqual(current, j.After) {
		return s.commitInstall(j, lock)
	}
	if j.Schema == 2 && j.After.Schema != 0 && reflect.DeepEqual(current, j.After) {
		g, e := maintenance.ReadUpgradeGuard(lock.DataDir)
		if e == nil && activationGuardMatches(g, j) && g.Phase == "active" {
			if e = s.finishInstallJournal(); e != nil {
				return j.Result, e
			}
			return j.Result, nil
		}
	}
	for _, r := range current.Receipts {
		if r.ID == j.ID && (r.Status == "rolled_back" || r.Status == "aborted") {
			if r.RequestID != j.Result.RequestID || r.Target != j.Result.Target || !reflect.DeepEqual(current, rollbackState(j.Before, r)) {
				return r, ErrInstallConflict
			}
			if g, e := maintenance.ReadUpgradeGuard(lock.DataDir); e == nil && g.ID == j.ID && (g == j.Guard || j.Schema == 2 && activationGuardMatches(g, j) && g.Phase != "active") {
				if e = maintenance.RestoreUpgradeGuard(lock, s.owner.ID, j.ID, j.BeforeGuard); e != nil {
					return r, e
				}
			} else if e == nil {
				if j.BeforeGuard == nil || g != *j.BeforeGuard {
					return r, ErrInstallConflict
				}
			} else if e != nil && !errors.Is(e, os.ErrNotExist) {
				return r, e
			} else if j.BeforeGuard != nil {
				return r, ErrInstallConflict
			}
			if e = s.finishInstallJournal(); e != nil {
				return r, e
			}
			r.Unchanged = true
			return r, nil
		}
	}
	if !reflect.DeepEqual(current, j.Before) && !(j.Schema == 2 && reflect.DeepEqual(current, j.After)) {
		return result, ErrInstallConflict
	}
	guard, guardErr := maintenance.ReadUpgradeGuard(lock.DataDir)
	if j.Phase != "preparing" && (guardErr != nil || guard != j.Guard && !(j.Schema == 2 && activationGuardMatches(guard, j) && guard.Phase != "active")) {
		return result, ErrInstallConflict
	}
	if j.Phase == "preparing" && guardErr != nil && (!errors.Is(guardErr, os.ErrNotExist) || j.BeforeGuard != nil) {
		return result, ErrInstallConflict
	}
	if guardErr != nil || guard.Phase == "active" {
		if e = maintenance.SetUpgradeGuard(lock, j.Guard); e != nil {
			return result, e
		}
	}
	r, rollbackErr := s.rollbackInstall(ctx, j, lock, password)
	if errors.Is(rollbackErr, ErrPreflightRolledBack) || errors.Is(rollbackErr, ErrUpgradeAborted) || errors.Is(rollbackErr, ErrActivationRolledBack) {
		return r, nil
	}
	return r, rollbackErr
}
func InstallationStatus(ctx context.Context, path string) (Installation, error) {
	s, e := openScheduleRoot(ctx, path)
	if e != nil {
		return Installation{}, e
	}
	defer s.close()
	if e = ctx.Err(); e != nil {
		return Installation{}, e
	}
	v, e := s.installation()
	if e != nil {
		return v, e
	}
	if j, e := s.readUpgrade(); e == nil {
		v.PendingUpgrade = j.Phase
	} else if !errors.Is(e, os.ErrNotExist) {
		return v, e
	}
	if v.DataDir != "" {
		if g, e := maintenance.ReadUpgradeGuard(v.DataDir); e == nil {
			if g.RootID != s.owner.ID {
				return v, ErrInstallConflict
			}
			v.ActivationState = g.Phase
		} else if !errors.Is(e, os.ErrNotExist) || v.Current.valid() {
			return v, ErrInstallConflict
		}
	}
	return v, nil
}

// RunInstalled launches the selected verified tree with its bound data/web
// paths. The persistent data guard prevents a racing old binary from opening
// data migrated by another version after this metadata lock is released.
func RunInstalled(ctx context.Context, path string, stdout, stderr io.Writer) error {
	return RunInstalledWithPassphrase(ctx, path, nil, stdout, stderr)
}
