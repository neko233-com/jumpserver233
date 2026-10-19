package maintenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var ErrUpgradePending = errors.New("offline upgrade pending; recover it before starting the service")
var upgradeID = regexp.MustCompile(`^[a-f0-9]{32}$`)
var upgradeDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type UpgradeGuard struct {
	Schema       int    `json:"schema"`
	RootID       string `json:"root_id"`
	ID           string `json:"transaction_id"`
	BinarySHA256 string `json:"binary_sha256"`
	Phase        string `json:"phase"`
	Attempt      string `json:"activation_attempt,omitempty"`
}

func upgradeGuardPath(data string) string { return filepath.Join(controlDir(data), "upgrade.json") }
func (g UpgradeGuard) valid() bool {
	return g.Schema == 1 && upgradeID.MatchString(g.RootID) && upgradeID.MatchString(g.ID) && upgradeDigest.MatchString(g.BinarySHA256) && (g.Phase == "pending" || g.Phase == "selected" || g.Phase == "trial" || g.Phase == "active") && (g.Attempt == "" || upgradeID.MatchString(g.Attempt)) && (g.Phase != "trial" || g.Attempt != "") && (g.Phase != "pending" && g.Phase != "selected" || g.Attempt == "")
}
func ReadUpgradeGuard(data string) (UpgradeGuard, error) {
	var g UpgradeGuard
	body, e := readPrivateJSON(upgradeGuardPath(data), 4096)
	if e != nil {
		return g, e
	}
	if json.Unmarshal(body, &g) != nil || !g.valid() {
		return g, ErrIntegrity
	}
	return g, nil
}

// CheckUpgradeGuard is called before recovery or opening any business store.
// The transaction ID is an identifier, not a credential; local OS ownership is
// the trust boundary. The target executable must also match the pinned digest.
func CheckUpgradeGuard(data, id, binarySHA string) error {
	g, e := ReadUpgradeGuard(data)
	if errors.Is(e, os.ErrNotExist) {
		if id != "" {
			return ErrUpgradePending
		}
		return nil
	}
	if e != nil {
		return e
	}
	if g.BinarySHA256 != binarySHA || g.Phase != "pending" && g.Phase != "active" || g.Phase == "pending" && (id == "" || g.ID != id) || g.Phase == "active" && id != "" {
		return ErrUpgradePending
	}
	return nil
}
func CheckNoUpgradePending(data string) error {
	g, e := ReadUpgradeGuard(data)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if g.Phase != "active" {
		return ErrUpgradePending
	}
	return nil
}
func SetUpgradeGuard(lock *Lock, g UpgradeGuard) error {
	if lock == nil || lock.file == nil {
		return ErrBusy
	}
	if !g.valid() {
		return ErrInvalid
	}
	if old, e := ReadUpgradeGuard(lock.DataDir); e == nil {
		if old == g {
			return nil
		}
		if old.RootID != g.RootID || old.Phase != "active" && old.ID != g.ID {
			return ErrConflict
		}
		if old.ID == g.ID && (old.BinarySHA256 != g.BinarySHA256 || old.Phase == "active" || old.Phase == "trial" && g.Phase == "active" && old.Attempt != g.Attempt) {
			return ErrConflict
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	body, _ := json.Marshal(g)
	return atomicPrivate(upgradeGuardPath(lock.DataDir), body)
}

// RestoreUpgradeGuard restores the previously selected binary only after a
// checkpoint rollback. It never authorizes a different installation root.
func RestoreUpgradeGuard(lock *Lock, rootID, id string, old *UpgradeGuard) error {
	if lock == nil || lock.file == nil {
		return ErrBusy
	}
	g, e := ReadUpgradeGuard(lock.DataDir)
	if e != nil {
		return e
	}
	if g.RootID != rootID || g.ID != id {
		return ErrConflict
	}
	if old == nil {
		return ClearUpgradeGuard(lock, rootID, id)
	}
	if !old.valid() || old.Phase != "active" || old.RootID != rootID {
		return ErrInvalid
	}
	body, _ := json.Marshal(old)
	return atomicPrivate(upgradeGuardPath(lock.DataDir), body)
}
func ClearUpgradeGuard(lock *Lock, rootID, id string) error {
	if lock == nil || lock.file == nil {
		return ErrBusy
	}
	g, e := ReadUpgradeGuard(lock.DataDir)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if g.RootID != rootID || g.ID != id {
		return ErrConflict
	}
	if e = os.Remove(upgradeGuardPath(lock.DataDir)); e != nil {
		return e
	}
	return syncDirectory(controlDir(lock.DataDir))
}

// UpgradeSource rejects PostgreSQL and pre-guard baselines. A guarded baseline
// must have successfully opened every store and recorded the validated key.
func UpgradeSource(lock *Lock) error {
	if lock == nil || lock.file == nil {
		return ErrBusy
	}
	if e := standaloneMode(lock.DataDir, true); e != nil {
		return e
	}
	if exists(journalPath(lock.DataDir)) {
		return ErrConflict
	}
	body, e := readPrivateJSON(filepath.Join(lock.DataDir, modeFile), 4096)
	if e != nil {
		return e
	}
	var m modeRecord
	if json.Unmarshal(body, &m) != nil || m.UpgradeProtocol != 1 || !upgradeDigest.MatchString(m.VaultKeySHA256) {
		return ErrInvalid
	}
	return nil
}
func ExecutableSHA256() (string, error) {
	path, e := os.Executable()
	if e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
