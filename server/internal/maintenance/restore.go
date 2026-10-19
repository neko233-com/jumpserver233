package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

type receipt struct {
	BackupID    string    `json:"backup_id"`
	ManifestSHA string    `json:"manifest_sha256"`
	AppliedAt   time.Time `json:"applied_at"`
}
type stagedState struct {
	Manifest    manifest `json:"manifest"`
	ManifestSHA string   `json:"manifest_sha256"`
}
type restoreJournal struct {
	Format      int      `json:"format"`
	Phase       string   `json:"phase"`
	Stage       string   `json:"stage"`
	Previous    string   `json:"previous"`
	Old         []string `json:"old"`
	New         []string `json:"new"`
	StageSHA    string   `json:"stage_sha256"`
	ManifestSHA string   `json:"manifest_sha256"`
	Result      Result   `json:"backup"`
}

func controlDir(dataDir string) string  { return filepath.Join(dataDir, controlName) }
func journalPath(dataDir string) string { return filepath.Join(controlDir(dataDir), "restore.json") }
func receiptAt(dataDir string) (receipt, error) {
	var r receipt
	b, e := readPrivateJSON(filepath.Join(dataDir, receiptName), 4096)
	if e != nil {
		return r, e
	}
	if json.Unmarshal(b, &r) != nil || len(r.BackupID) != 32 || len(r.ManifestSHA) != 64 || r.AppliedAt.IsZero() {
		return r, ErrIntegrity
	}
	return r, nil
}
func matchesReceipt(dataDir string, j restoreJournal) bool {
	r, e := receiptAt(dataDir)
	return e == nil && r.BackupID == j.Result.BackupID && r.ManifestSHA == j.ManifestSHA
}
func ownedControl(name, kind string) bool {
	prefix := kind + "-"
	if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+32 || filepath.Base(name) != name {
		return false
	}
	_, e := hex.DecodeString(strings.TrimPrefix(name, prefix))
	return e == nil
}
func regularDirectory(name string) bool {
	info, e := os.Lstat(name)
	return e == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}
func topEntries(dir string) ([]string, error) {
	rows, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, row := range rows {
		if strings.EqualFold(row.Name(), controlName) {
			if !actualControl(dir, row.Name()) {
				return nil, ErrInvalid
			}
			continue
		}
		if !safeName(row.Name()) || strings.Contains(row.Name(), "/") || len(out) >= maxEntries {
			return nil, ErrInvalid
		}
		out = append(out, row.Name())
	}
	sort.Strings(out)
	return out, nil
}
func writeJournal(dataDir string, j restoreJournal) error {
	body, e := json.Marshal(j)
	if e != nil {
		return e
	}
	if int64(len(body)) > maxManifestBytes {
		return ErrInvalid
	}
	return atomicPrivate(journalPath(dataDir), body)
}

// Restore authenticates into a private stage, then journals every top-level
// rename. The persistent root and lock never move, including Docker mounts.
// Existing data is retained in PreviousDataDir; no documents or IDs are merged.
func Restore(ctx context.Context, opt Options) (Result, error) {
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	lock, e := Acquire(opt.DataDir)
	if e != nil {
		return Result{}, e
	}
	defer lock.Close()
	if _, _, e = recoverJournal(ctx, lock.DataDir); e != nil {
		return Result{}, e
	}
	if e = standaloneMode(lock.DataDir, false); e != nil {
		return Result{}, e
	}
	id, e := randomID()
	if e != nil {
		return Result{}, e
	}
	name := "stage-" + id
	stage := filepath.Join(controlDir(lock.DataDir), name)
	data := filepath.Join(stage, "data")
	if e = os.MkdirAll(data, 0700); e != nil {
		return Result{}, e
	}
	defer func() {
		if !exists(journalPath(lock.DataDir)) && ownedControl(name, "stage") {
			_ = os.RemoveAll(stage)
		}
	}()
	root, e := os.OpenRoot(data)
	if e != nil {
		return Result{}, e
	}
	m, hash, e := readArchive(ctx, opt, root)
	ce := root.Close()
	if e != nil {
		return Result{}, e
	}
	if ce != nil {
		return Result{}, ce
	}
	if e = standaloneMode(data, true); e != nil {
		return Result{}, e
	}
	if r, re := receiptAt(lock.DataDir); re == nil && r.BackupID == m.Result.BackupID {
		if r.ManifestSHA != hash {
			return Result{}, ErrConflict
		}
		m.Result.Unchanged = true
		return m.Result, nil
	}
	old, e := topEntries(lock.DataDir)
	if e != nil {
		return Result{}, e
	}
	if len(old) > 0 && !opt.Replace {
		return Result{}, ErrConflict
	}
	previous := "previous-" + id
	previousPath := filepath.Join(controlDir(lock.DataDir), previous)
	if exists(previousPath) {
		return Result{}, ErrConflict
	}
	body, e := json.Marshal(stagedState{Manifest: m, ManifestSHA: hash})
	if e != nil || int64(len(body)) > maxManifestBytes {
		return Result{}, ErrInvalid
	}
	if e = atomicPrivate(filepath.Join(stage, "manifest.json"), body); e != nil {
		return Result{}, e
	}
	raw, _ := json.Marshal(receipt{BackupID: m.Result.BackupID, ManifestSHA: hash, AppliedAt: time.Now().UTC()})
	if e = atomicPrivate(filepath.Join(data, receiptName), raw); e != nil {
		return Result{}, e
	}
	if e = syncTreeDirectories(stage); e != nil {
		return Result{}, e
	}
	next, e := topEntries(data)
	if e != nil {
		return Result{}, e
	}
	sum := sha256.Sum256(body)
	j := restoreJournal{Format: 1, Phase: "saving-old", Stage: name, Previous: previous, Old: old, New: next, StageSHA: hex.EncodeToString(sum[:]), ManifestSHA: hash, Result: m.Result}
	if len(old) > 0 {
		j.Result.PreviousDataDir = previousPath
	}
	if e = writeJournal(lock.DataDir, j); e != nil {
		return Result{}, e
	}
	result, applied, e := recoverJournal(ctx, lock.DataDir)
	if e != nil {
		return Result{}, e
	}
	if !applied {
		return Result{}, ErrIntegrity
	}
	return result, nil
}
func syncTreeDirectories(root string) error {
	var dirs []string
	e := filepath.WalkDir(root, func(name string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			dirs = append(dirs, name)
		}
		return nil
	})
	if e != nil {
		return e
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if e = syncDirectory(dirs[i]); e != nil {
			return e
		}
	}
	return nil
}
func validTopList(names []string) bool {
	seen := map[string]bool{}
	if len(names) > maxEntries {
		return false
	}
	for _, n := range names {
		if !safeName(n) || strings.Contains(n, "/") || strings.EqualFold(n, controlName) || seen[strings.ToLower(n)] {
			return false
		}
		seen[strings.ToLower(n)] = true
	}
	return true
}
func readJournal(dataDir string) (restoreJournal, error) {
	var j restoreJournal
	body, e := readPrivateJSON(journalPath(dataDir), maxManifestBytes)
	if e != nil {
		return j, e
	}
	d := json.NewDecoder(strings.NewReader(string(body)))
	d.DisallowUnknownFields()
	if d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || j.Format != 1 || (j.Phase != "saving-old" && j.Phase != "installing-new" && j.Phase != "rollback-new" && j.Phase != "rollback-old") || !ownedControl(j.Stage, "stage") || !ownedControl(j.Previous, "previous") || len(j.StageSHA) != 64 || len(j.ManifestSHA) != 64 || len(j.Result.BackupID) != 32 || !validTopList(j.Old) || !validTopList(j.New) {
		return j, ErrIntegrity
	}
	previous := filepath.Join(controlDir(dataDir), j.Previous)
	if j.Result.PreviousDataDir != "" && j.Result.PreviousDataDir != previous {
		return j, ErrIntegrity
	}
	return j, nil
}

// Recover is called under Acquire before any standalone store opens. Journal
// validation fails closed, so startup never initializes over a partial restore.
func Recover(ctx context.Context, dataDir string) error {
	_, _, e := recoverJournal(ctx, dataDir)
	return e
}
func recoverJournal(ctx context.Context, dataDir string) (Result, bool, error) {
	j, e := readJournal(dataDir)
	if errors.Is(e, os.ErrNotExist) {
		return Result{}, false, nil
	}
	if e != nil {
		return Result{}, false, e
	}
	if strings.HasPrefix(j.Phase, "rollback-") {
		return Result{}, false, rollbackJournal(ctx, dataDir, j)
	}
	stage := filepath.Join(controlDir(dataDir), j.Stage)
	data := filepath.Join(stage, "data")
	previous := filepath.Join(controlDir(dataDir), j.Previous)
	if !regularDirectory(stage) {
		if j.Phase == "saving-old" {
			if e = rollbackJournal(ctx, dataDir, j); e != nil {
				return Result{}, false, e
			}
			return Result{}, false, nil
		}
		return Result{}, false, ErrIntegrity
	}
	if e = validateStage(ctx, dataDir, j); e != nil {
		return Result{}, false, e
	}
	if j.Phase == "saving-old" {
		if !exists(previous) {
			if e = os.Mkdir(previous, 0700); e != nil {
				return Result{}, false, e
			}
		} else if !regularDirectory(previous) {
			return Result{}, false, ErrConflict
		}
		for _, name := range j.Old {
			if e = ctx.Err(); e != nil {
				return Result{}, false, e
			}
			from, to := filepath.Join(dataDir, name), filepath.Join(previous, name)
			a, b := exists(from), exists(to)
			if a == b {
				return Result{}, false, ErrConflict
			}
			if a {
				if e = os.Rename(from, to); e != nil {
					return Result{}, false, e
				}
			}
		}
		if e = syncDirectory(dataDir); e != nil {
			return Result{}, false, e
		}
		if e = syncDirectory(previous); e != nil {
			return Result{}, false, e
		}
		j.Phase = "installing-new"
		if e = writeJournal(dataDir, j); e != nil {
			return Result{}, false, e
		}
	}
	for _, name := range j.New {
		if e = ctx.Err(); e != nil {
			return Result{}, false, e
		}
		from, to := filepath.Join(data, name), filepath.Join(dataDir, name)
		a, b := exists(from), exists(to)
		if a == b {
			return Result{}, false, ErrConflict
		}
		if a {
			if e = os.Rename(from, to); e != nil {
				return Result{}, false, e
			}
		}
	}
	if !matchesReceipt(dataDir, j) {
		return Result{}, false, ErrIntegrity
	}
	if e = syncDirectory(dataDir); e != nil {
		return Result{}, false, e
	}
	if e = os.Remove(journalPath(dataDir)); e != nil {
		return Result{}, false, e
	}
	if e = syncDirectory(controlDir(dataDir)); e != nil {
		return Result{}, false, e
	}
	_ = os.RemoveAll(stage)
	if len(j.Old) == 0 {
		_ = os.Remove(previous)
	}
	return j.Result, true, nil
}

// Rollback preserves partly installed new entries under the private stage and
// restores all old entries. It requires an explicit local CLI action.
func Rollback(ctx context.Context, dataDir string) error {
	j, e := readJournal(dataDir)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	return rollbackJournal(ctx, dataDir, j)
}
func rollbackJournal(ctx context.Context, dataDir string, j restoreJournal) error {
	previous := filepath.Join(controlDir(dataDir), j.Previous)
	if j.Phase == "saving-old" {
		j.Phase = "rollback-old"
		if e := writeJournal(dataDir, j); e != nil {
			return e
		}
	}
	if j.Phase == "installing-new" {
		j.Phase = "rollback-new"
		if e := writeJournal(dataDir, j); e != nil {
			return e
		}
	}
	if j.Phase == "rollback-new" {
		quarantine := filepath.Join(controlDir(dataDir), j.Stage, "failed-data")
		if e := os.MkdirAll(quarantine, 0700); e != nil {
			return e
		}
		for _, name := range j.New {
			if e := ctx.Err(); e != nil {
				return e
			}
			from, to := filepath.Join(dataDir, name), filepath.Join(quarantine, name)
			if exists(from) {
				if exists(to) {
					return ErrConflict
				}
				if e := os.Rename(from, to); e != nil {
					return e
				}
			}
		}
		if e := syncDirectory(quarantine); e != nil {
			return e
		}
		if e := syncDirectory(dataDir); e != nil {
			return e
		}
		j.Phase = "rollback-old"
		if e := writeJournal(dataDir, j); e != nil {
			return e
		}
	}
	for _, name := range j.Old {
		if e := ctx.Err(); e != nil {
			return e
		}
		from, to := filepath.Join(previous, name), filepath.Join(dataDir, name)
		a, b := exists(from), exists(to)
		if a == b {
			return ErrConflict
		}
		if a {
			if e := os.Rename(from, to); e != nil {
				return e
			}
		}
	}
	if e := syncDirectory(dataDir); e != nil {
		return e
	}
	if e := os.Remove(journalPath(dataDir)); e != nil {
		return e
	}
	return syncDirectory(controlDir(dataDir))
}
func validateStage(ctx context.Context, dataDir string, j restoreJournal) error {
	stage := filepath.Join(controlDir(dataDir), j.Stage)
	data := filepath.Join(stage, "data")
	body, e := readPrivateJSON(filepath.Join(stage, "manifest.json"), maxManifestBytes)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != j.StageSHA {
		return ErrIntegrity
	}
	var state stagedState
	if json.Unmarshal(body, &state) != nil || state.ManifestSHA != j.ManifestSHA || state.Manifest.Result.BackupID != j.Result.BackupID || state.Manifest.Format != 1 || len(state.Manifest.Entries) > maxEntries {
		return ErrIntegrity
	}
	expected := map[string]entry{}
	tops := map[string]bool{receiptName: true}
	for _, item := range state.Manifest.Entries {
		if !safeName(item.Name) || reserved(item.Name) {
			return ErrIntegrity
		}
		expected[item.Name] = item
		tops[strings.SplitN(item.Name, "/", 2)[0]] = true
	}
	names := []string{}
	for name := range tops {
		names = append(names, name)
	}
	sort.Strings(names)
	if !slices.Equal(names, j.New) {
		return ErrIntegrity
	}
	actual, e := topEntries(data)
	if e != nil {
		return e
	}
	for _, name := range actual {
		if !tops[name] {
			return ErrIntegrity
		}
	}
	current, e := topEntries(dataDir)
	if e != nil {
		return e
	}
	allowed := tops
	if j.Phase == "saving-old" {
		allowed = map[string]bool{}
		for _, name := range j.Old {
			allowed[name] = true
		}
	}
	for _, name := range current {
		if !allowed[name] {
			return ErrConflict
		}
	}
	seen := 0
	receiptFound := false
	for _, top := range j.New {
		base := data
		if !exists(filepath.Join(base, top)) {
			if j.Phase != "installing-new" {
				return ErrIntegrity
			}
			base = dataDir
		} else if j.Phase == "installing-new" && exists(filepath.Join(dataDir, top)) {
			return ErrConflict
		}
		if !regularDirectory(base) {
			return ErrIntegrity
		}
		root, e := os.OpenRoot(base)
		if e != nil {
			return e
		}
		e = fs.WalkDir(root.FS(), top, func(name string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if e = ctx.Err(); e != nil {
				return e
			}
			if name == receiptName {
				if !matchesReceipt(base, j) {
					return ErrIntegrity
				}
				receiptFound = true
				return nil
			}
			item, ok := expected[name]
			if !ok {
				return ErrIntegrity
			}
			seen++
			info, e := root.Lstat(name)
			if e != nil {
				return e
			}
			if info.IsDir() != item.Directory || !info.IsDir() && !info.Mode().IsRegular() || info.Size() != item.Size && !item.Directory {
				return ErrIntegrity
			}
			if item.Directory {
				return nil
			}
			f, e := root.Open(name)
			if e != nil {
				return e
			}
			hash := sha256.New()
			_, e = io.Copy(hash, contextReader(ctx, f))
			ce := f.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
			if hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
				return ErrIntegrity
			}
			return nil
		})
		root.Close()
		if e != nil {
			return e
		}
	}
	if seen != len(expected) || !receiptFound {
		return ErrIntegrity
	}
	return nil
}
