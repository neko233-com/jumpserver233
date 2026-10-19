package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type ActivationRecord struct {
	Schema       int    `json:"schema"`
	RootID       string `json:"root_id"`
	ID           string `json:"transaction_id"`
	Attempt      string `json:"activation_attempt"`
	PID          int    `json:"pid"`
	Address      string `json:"address"`
	Version      string `json:"version"`
	BinarySHA256 string `json:"binary_sha256"`
	Phase        string `json:"phase"`
}
type activationRelease struct {
	Schema       int    `json:"schema"`
	RootID       string `json:"root_id"`
	ID           string `json:"transaction_id"`
	Attempt      string `json:"activation_attempt"`
	PID          int    `json:"pid"`
	BinarySHA256 string `json:"binary_sha256"`
}

func activationPath(data, kind string) string {
	return filepath.Join(controlDir(data), "activation-"+kind+".json")
}
func (r ActivationRecord) valid() bool {
	host, port, e := net.SplitHostPort(r.Address)
	n, ne := strconv.Atoi(port)
	return r.Schema == 1 && upgradeID.MatchString(r.RootID) && upgradeID.MatchString(r.ID) && upgradeID.MatchString(r.Attempt) && r.PID > 0 && upgradeDigest.MatchString(r.BinarySHA256) && len(r.Version) > 0 && len(r.Version) <= 128 && (r.Phase == "trial" || r.Phase == "active") && e == nil && ne == nil && n > 0 && n < 65536 && net.ParseIP(host) != nil
}
func ReadActivation(data string) (ActivationRecord, error) {
	var r ActivationRecord
	body, e := readPrivateJSON(activationPath(data, "ready"), 4096)
	if e != nil {
		return r, e
	}
	if json.Unmarshal(body, &r) != nil || !r.valid() {
		return r, ErrIntegrity
	}
	return r, nil
}
func CheckActivationGuard(data, id, attempt, binarySHA string) (UpgradeGuard, error) {
	g, e := ReadUpgradeGuard(data)
	if e != nil {
		return g, e
	}
	if g.Phase != "trial" || id != g.ID || attempt != g.Attempt || binarySHA != g.BinarySHA256 {
		return g, ErrUpgradePending
	}
	return g, nil
}
func PublishActivation(lock *Lock, g UpgradeGuard, address, version, phase string) (ActivationRecord, error) {
	var r ActivationRecord
	if lock == nil || lock.file == nil {
		return r, ErrBusy
	}
	current, e := ReadUpgradeGuard(lock.DataDir)
	if e != nil || current != g {
		return r, ErrConflict
	}
	r = ActivationRecord{Schema: 1, RootID: g.RootID, ID: g.ID, Attempt: g.Attempt, PID: os.Getpid(), Address: address, Version: version, BinarySHA256: g.BinarySHA256, Phase: phase}
	if !r.valid() || phase != g.Phase {
		return r, ErrInvalid
	}
	if old, e := ReadActivation(lock.DataDir); e == nil {
		if old.RootID != g.RootID {
			return r, ErrConflict
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return r, e
	}
	body, _ := json.Marshal(r)
	return r, atomicPrivate(activationPath(lock.DataDir, "ready"), body)
}
func releaseOf(r ActivationRecord) activationRelease {
	return activationRelease{Schema: 1, RootID: r.RootID, ID: r.ID, Attempt: r.Attempt, PID: r.PID, BinarySHA256: r.BinarySHA256}
}
func readActivationRelease(data string) (activationRelease, error) {
	var r activationRelease
	body, e := readPrivateJSON(activationPath(data, "release"), 4096)
	if e != nil {
		return r, e
	}
	if json.Unmarshal(body, &r) != nil || r.Schema != 1 || !upgradeID.MatchString(r.RootID) || !upgradeID.MatchString(r.ID) || !upgradeID.MatchString(r.Attempt) || !upgradeDigest.MatchString(r.BinarySHA256) || r.PID <= 0 {
		return r, ErrIntegrity
	}
	return r, nil
}

// ReleaseActivation is a local file handshake. No HTTP endpoint can enable
// business traffic. The IDs are lifecycle identifiers, never login credentials.
func ReleaseActivation(data string, r ActivationRecord) error {
	if !r.valid() || r.Phase != "trial" {
		return ErrInvalid
	}
	g, e := ReadUpgradeGuard(data)
	if e != nil || g.Phase != "trial" || g.RootID != r.RootID || g.ID != r.ID || g.Attempt != r.Attempt || g.BinarySHA256 != r.BinarySHA256 {
		return ErrConflict
	}
	current, e := ReadActivation(data)
	if e != nil || current != r {
		return ErrConflict
	}
	if old, e := readActivationRelease(data); e == nil {
		if old.RootID != r.RootID {
			return ErrConflict
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	body, _ := json.Marshal(releaseOf(r))
	return atomicPrivate(activationPath(data, "release"), body)
}

// AwaitActivation commits the active guard before the caller starts any remote
// work. A launcher crash never leaves a trial listener waiting indefinitely.
func AwaitActivation(ctx context.Context, lock *Lock, g UpgradeGuard, r ActivationRecord) (UpgradeGuard, error) {
	if lock == nil || lock.file == nil || !r.valid() || r.Phase != "trial" || releaseOf(r) != (activationRelease{1, g.RootID, g.ID, g.Attempt, os.Getpid(), g.BinarySHA256}) {
		return g, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		command, e := readActivationRelease(lock.DataDir)
		if e == nil && command == releaseOf(r) {
			current, e := ReadUpgradeGuard(lock.DataDir)
			if e != nil || current != g {
				return g, ErrConflict
			}
			g.Phase = "active"
			return g, SetUpgradeGuard(lock, g)
		}
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return g, e
		}
		select {
		case <-ctx.Done():
			return g, ctx.Err()
		case <-ticker.C:
		}
	}
}

func ClearActivation(lock *Lock, g UpgradeGuard) error {
	if lock == nil || lock.file == nil {
		return ErrBusy
	}
	if r, e := ReadActivation(lock.DataDir); e == nil {
		if r.RootID == g.RootID && r.ID == g.ID && r.Attempt == g.Attempt && r.PID == os.Getpid() {
			if e = os.Remove(activationPath(lock.DataDir, "ready")); e != nil {
				return e
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if r, e := readActivationRelease(lock.DataDir); e == nil {
		if r.RootID == g.RootID && r.ID == g.ID && r.Attempt == g.Attempt && r.PID == os.Getpid() {
			if e = os.Remove(activationPath(lock.DataDir, "release")); e != nil {
				return e
			}
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return syncDirectory(controlDir(lock.DataDir))
}
