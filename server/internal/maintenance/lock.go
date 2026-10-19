// Package maintenance implements offline standalone backup and recovery.
package maintenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	ErrBusy      = errors.New("data directory is in use; stop the service before maintenance")
	ErrInvalid   = errors.New("invalid backup or maintenance input")
	ErrIntegrity = errors.New("backup authentication or integrity check failed")
	ErrConflict  = errors.New("restore conflicts with existing data; use an explicit replacement")
	ErrCluster   = errors.New("offline standalone backup cannot capture PostgreSQL cluster state")
)

const modeFile = ".jms233-storage.json"
const controlName = ".jms233-maintenance"

type modeRecord struct {
	Version         int    `json:"version"`
	Mode            string `json:"mode"`
	VaultKeySHA256  string `json:"vault_key_sha256,omitempty"`
	UpgradeProtocol int    `json:"upgrade_protocol,omitempty"`
}

// The control directory stays in place during restore, including Docker mounts.
// Locks are released by the OS after process termination.
type Lock struct {
	DataDir string
	file    *os.File
}

func Acquire(dataDir string) (*Lock, error) {
	if dataDir == "" {
		return nil, ErrInvalid
	}
	abs, e := filepath.Abs(dataDir)
	if e != nil || filepath.Dir(abs) == abs {
		return nil, ErrInvalid
	}
	if e = os.MkdirAll(abs, 0700); e != nil {
		return nil, e
	}
	abs, e = filepath.EvalSymlinks(abs)
	if e != nil {
		return nil, e
	}
	control := filepath.Join(abs, controlName)
	if info, err := os.Lstat(control); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return nil, ErrBusy
	}
	if e = os.MkdirAll(control, 0700); e != nil {
		return nil, e
	}
	if e = os.Chmod(control, 0700); e != nil {
		return nil, e
	}
	path := filepath.Join(control, "lock")
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, ErrBusy
	}
	f, e := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if e != nil {
		return nil, fmt.Errorf("open maintenance lock: %w", e)
	}
	info, e := f.Stat()
	named, ne := os.Lstat(path)
	if e != nil || ne != nil || !info.Mode().IsRegular() || !named.Mode().IsRegular() || !os.SameFile(info, named) {
		f.Close()
		return nil, ErrBusy
	}
	if e = lockFile(f); e != nil {
		f.Close()
		return nil, ErrBusy
	}
	return &Lock{DataDir: abs, file: f}, nil
}
func (l *Lock) Close() error {
	if l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	unlockFile(f)
	return f.Close()
}

// RecordMode marks the authoritative store. Switching from PostgreSQL back to
// stale local import files is rejected instead of silently losing shared state.
func RecordMode(dataDir string, cluster bool) error {
	if exists(journalPath(dataDir)) {
		return ErrConflict
	}
	if !cluster {
		if e := standaloneMode(dataDir, false); e != nil {
			return e
		}
	}
	if e := os.MkdirAll(dataDir, 0700); e != nil {
		return e
	}
	mode := "standalone"
	if cluster {
		mode = "postgres"
	}
	body, _ := json.Marshal(modeRecord{Version: 1, Mode: mode, UpgradeProtocol: 1})
	return atomicPrivate(filepath.Join(dataDir, modeFile), body)
}

// RecordVaultKey is called only after every runtime store accepted the key.
// Backups can then reject a stale or mistyped external key without mutating data.
func RecordVaultKey(dataDir string, key []byte) error {
	if len(key) != 32 {
		return ErrInvalid
	}
	body, e := readPrivateJSON(filepath.Join(dataDir, modeFile), 1024)
	if e != nil {
		return e
	}
	var mode modeRecord
	if json.Unmarshal(body, &mode) != nil || mode.Version != 1 || (mode.Mode != "standalone" && mode.Mode != "postgres") {
		return ErrInvalid
	}
	sum := sha256.Sum256(key)
	mode.VaultKeySHA256 = hex.EncodeToString(sum[:])
	body, _ = json.Marshal(mode)
	return atomicPrivate(filepath.Join(dataDir, modeFile), body)
}
func standaloneMode(dataDir string, required bool) error {
	body, e := readPrivateJSON(filepath.Join(dataDir, modeFile), 1024)
	if errors.Is(e, os.ErrNotExist) && !required {
		return nil
	}
	if e != nil {
		return fmt.Errorf("read storage mode (start this version once before backup): %w", e)
	}
	return standaloneModeData(body)
}
func standaloneModeData(body []byte) error {
	var mode modeRecord
	if json.Unmarshal(body, &mode) != nil || mode.Version != 1 {
		return ErrInvalid
	}
	if mode.Mode == "postgres" {
		return ErrCluster
	}
	if mode.Mode != "standalone" {
		return ErrInvalid
	}
	return nil
}

func readPrivateJSON(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	named, ne := os.Lstat(path)
	if e != nil || ne != nil || !info.Mode().IsRegular() || !named.Mode().IsRegular() || !os.SameFile(info, named) || info.Size() > limit {
		return nil, ErrInvalid
	}
	return readBounded(f, limit)
}
func atomicPrivate(path string, body []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".jms233-write-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(body)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(path))
}
