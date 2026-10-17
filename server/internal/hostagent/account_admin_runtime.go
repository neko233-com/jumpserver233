package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const AccountAdminDirectory = "/var/lib/jumpserver233/account-admin"
const AccountAdminBinaryDirectory = "/usr/local/libexec/jumpserver233"

type accountAdminIdentity struct {
	Account
	Marker string
	Expiry string // Only the expiration field; no password hash is retained.
}
type accountAdminSystem interface {
	lookup(context.Context, string) (accountAdminIdentity, bool, error)
	create(context.Context, AccountAdminTask) (accountAdminIdentity, error)
	provision(context.Context, AccountAdminTask, accountAdminIdentity) error
	modify(context.Context, accountAdminIdentity, string, string) error
	prepareRemove(context.Context, accountAdminIdentity) (accountHomeProof, error)
	remove(context.Context, accountAdminIdentity, accountHomeProof) error
}
type accountHomeProof struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Absent bool   `json:"absent,omitempty"`
}
type accountAdminReceipt struct {
	Task      AccountAdminTask   `json:"task"`
	Result    AccountAdminResult `json:"result"`
	HomeProof *accountHomeProof  `json:"home_proof,omitempty"`
}
type accountDisabledState struct {
	Username string `json:"username"`
	UID      uint32 `json:"uid"`
	Shell    string `json:"shell"`
	Expiry   string `json:"expiry"`
	Disabled bool   `json:"disabled"`
	TaskID   string `json:"task_id"`
}

func adminRead(dir, name string, out any) error {
	f, e := openSnapshot(filepath.Join(dir, name))
	if e != nil {
		return e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || !owned(s) || s.Mode().Perm() != 0600 || s.Size() > MaxAccountAdminBytes {
		return ErrAccountAdmin
	}
	raw, e := io.ReadAll(io.LimitReader(f, MaxAccountAdminBytes+1))
	if e != nil || len(raw) > MaxAccountAdminBytes || validateJSON(raw) != nil {
		return ErrAccountAdmin
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrAccountAdmin
	}
	return nil
}
func adminWrite(dir, name string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > MaxAccountAdminBytes {
		return ErrAccountAdmin
	}
	f, e := os.CreateTemp(dir, ".account-admin-*")
	if e != nil {
		return ErrAccountAdmin
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrAccountAdmin
	}
	if e = os.Rename(f.Name(), filepath.Join(dir, name)); e != nil {
		return ErrAccountAdmin
	}
	return syncDirectory(dir)
}

func runAccountAdmin(ctx context.Context, req AccountAdminRequest, dir string, system accountAdminSystem) (AccountAdminResult, error) {
	t := req.Task
	r := AccountAdminResult{Format: AccountAdminFormat, ID: t.ID, Digest: t.Digest(), Action: t.Action, Username: t.Username, State: "absent"}
	if req.Validate() != nil {
		return r, ErrAccountAdmin
	}
	unlock, e := stateLock(filepath.Join(dir, "account-admin.lock"))
	if e != nil {
		r.ErrorCode = "busy"
		return r, e
	}
	defer unlock()
	receipt := accountAdminReceipt{Task: t, Result: r}
	name := t.ID + ".json"
	var stored accountAdminReceipt
	e = adminRead(dir, name, &stored)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		r.ErrorCode = "unsafe_state"
		return r, ErrAccountAdmin
	}
	if e == nil {
		receipt = stored
		encoded, marshalError := json.Marshal(receipt.Result)
		_, decodeError := DecodeAccountAdminResult(encoded, t)
		if marshalError != nil || decodeError != nil {
			r.ErrorCode = "unsafe_state"
			return r, ErrAccountAdmin
		}
	}
	if e == nil && (receipt.Task != t || receipt.Result.ID != t.ID || receipt.Result.Digest != t.Digest()) {
		r.State = "conflict"
		r.ErrorCode = "request_conflict"
		return r, ErrAccountAdmin
	}
	if req.Mode == "inspect" {
		if errors.Is(e, os.ErrNotExist) {
			return r, nil
		}
		if receipt.Result.State == "applied" {
			identity, exists, e := system.lookup(ctx, t.Username)
			valid := e == nil && (t.Action == "delete" && !exists || exists && identity.UID == receipt.Result.UID && identity.GID == receipt.Result.GID && identity.GID != 0 && (t.Action == "create" && identity.Marker == "jumpserver233/"+t.ID && identity.Home == receipt.Result.Home && identity.Shell == t.Shell || t.Action == "disable" && identity.Expiry == "1" && identity.Shell == "/usr/sbin/nologin" || t.Action == "enable" && identity.Shell == receipt.Result.Shell))
			if !valid {
				r = receipt.Result
				r.State = "conflict"
				r.ErrorCode = "identity_conflict"
				return r, errAdminIdentity
			}
		}
		return receipt.Result, nil
	}
	if req.Mode == "cancel" {
		identity, exists, lookupError := system.lookup(ctx, t.Username)
		if lookupError != nil {
			r.ErrorCode = "identity_conflict"
			return r, lookupError
		}
		if t.Action != "create" && receipt.Result.State != "absent" && receipt.Result.State != "cancelled" && receipt.Result.Stage != "prepared" || t.Action == "create" && exists && (identity.Marker == "jumpserver233/"+t.ID || receipt.Result.UID != 0 && identity.UID == receipt.Result.UID) {
			r = receipt.Result
			r.State = "incomplete"
			r.UID = identity.UID
			r.GID = identity.GID
			r.Home = identity.Home
			r.Shell = identity.Shell
			r.ErrorCode = "identity_conflict"
			return r, errAdminIdentity
		}
		if t.Action == "disable" || t.Action == "enable" {
			var snapshot accountDisabledState
			snapshotName := "disabled-" + t.Username + ".json"
			if e := adminRead(dir, snapshotName, &snapshot); e == nil && snapshot.TaskID == t.ID {
				if t.Action == "disable" {
					if !exists || identity.UID != snapshot.UID || identity.Expiry != snapshot.Expiry || identity.Shell != snapshot.Shell {
						return r, errAdminIdentity
					}
					snapshot.Disabled = false
				}
				snapshot.TaskID = ""
				if adminWrite(dir, snapshotName, snapshot) != nil {
					return r, errAdminState
				}
			}
		}
		r.State = "cancelled"
		r.Stage = "cancelled"
		r.ErrorCode = ""
		receipt = accountAdminReceipt{Task: t, Result: r}
		if adminWrite(dir, name, receipt) != nil {
			return r, errAdminState
		}
		return r, nil
	}
	if receipt.Result.State == "cancelled" {
		return receipt.Result, errAdminIdentity
	}
	if errors.Is(e, os.ErrNotExist) {
		receipt.Result.State = "prepared"
		receipt.Result.Stage = "prepared"
		if adminWrite(dir, name, receipt) != nil {
			r.ErrorCode = "state_unavailable"
			return r, ErrAccountAdmin
		}
	}
	r = receipt.Result
	finish := func(stage string, cause error) (AccountAdminResult, error) {
		r.Stage = stage
		r.ErrorCode = ""
		r.State = "incomplete"
		if cause == nil {
			r.State = "applied"
		} else {
			r.ErrorCode = adminFailureCode(cause)
		}
		receipt.Result = r
		if adminWrite(dir, name, receipt) != nil {
			r.State = "incomplete"
			r.ErrorCode = "state_unavailable"
			return r, ErrAccountAdmin
		}
		return r, cause
	}
	if ctx.Err() != nil {
		return finish(r.Stage, ctx.Err())
	}
	identity, exists, e := system.lookup(ctx, t.Username)
	if e != nil {
		return finish(r.Stage, e)
	}
	if r.State == "applied" {
		if t.Action == "delete" && !exists {
			return r, nil
		}
		if exists && identity.UID == r.UID && identity.GID == r.GID && identity.GID != 0 && (t.Action == "create" && identity.Marker == "jumpserver233/"+t.ID && identity.Home == r.Home && identity.Shell == t.Shell || t.Action == "disable" && identity.Expiry == "1" && identity.Shell == "/usr/sbin/nologin" || t.Action == "enable" && identity.Shell == r.Shell) {
			return r, nil
		}
		return finish(r.Stage, errAdminIdentity)
	}
	if t.Action == "create" {
		if exists && (identity.Marker != "jumpserver233/"+t.ID || identity.UID < 1000 || identity.UID > 60000) {
			return finish(r.Stage, errAdminIdentity)
		}
		if !exists {
			identity, e = system.create(ctx, t)
			if e != nil {
				return finish(r.Stage, e)
			}
		}
		r.UID, r.GID, r.Home, r.Shell = identity.UID, identity.GID, identity.Home, t.Shell
		r.Stage = "account_created"
		receipt.Result = r
		if adminWrite(dir, name, receipt) != nil {
			return r, ErrAccountAdmin
		}
		if e = system.provision(ctx, t, identity); e != nil {
			return finish(r.Stage, e)
		}
		return finish("ready", nil)
	}
	if !exists {
		if t.Action == "delete" && r.Stage == "delete_started" {
			r.UID = t.UID
			return finish("deleted", nil)
		}
		return finish(r.Stage, errAdminIdentity)
	}
	if identity.UID != t.UID || identity.UID < 1000 || identity.UID > 60000 || identity.GID == 0 {
		return finish(r.Stage, errAdminIdentity)
	}
	r.UID, r.GID, r.Home, r.Shell = identity.UID, identity.GID, identity.Home, identity.Shell
	snapshotName := "disabled-" + t.Username + ".json"
	snapshot := accountDisabledState{}
	if t.Action == "disable" {
		e = adminRead(dir, snapshotName, &snapshot)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return finish(r.Stage, errAdminState)
		}
		if e == nil && snapshot.Disabled {
			if snapshot.UID != identity.UID || snapshot.Username != t.Username {
				return finish(r.Stage, errAdminIdentity)
			}
			if identity.Expiry == "1" && identity.Shell == "/usr/sbin/nologin" {
				r.Shell = "/usr/sbin/nologin"
				return finish("disabled", nil)
			}
			if snapshot.TaskID != t.ID || identity.Expiry != snapshot.Expiry || identity.Shell != snapshot.Shell {
				return finish(r.Stage, errAdminIdentity)
			}
		} else {
			snapshot = accountDisabledState{Username: t.Username, UID: t.UID, Shell: identity.Shell, Expiry: identity.Expiry, Disabled: true, TaskID: t.ID}
			if adminWrite(dir, snapshotName, snapshot) != nil {
				return finish(r.Stage, errAdminState)
			}
		}
		r.Stage = "disable_started"
		receipt.Result = r
		if adminWrite(dir, name, receipt) != nil {
			return r, ErrAccountAdmin
		}
		if e = system.modify(ctx, identity, "1", "/usr/sbin/nologin"); e != nil {
			return finish(r.Stage, e)
		}
		r.Shell = "/usr/sbin/nologin"
		return finish("disabled", nil)
	}
	if t.Action == "enable" {
		if adminRead(dir, snapshotName, &snapshot) != nil || snapshot.UID != t.UID || snapshot.Username != t.Username {
			return finish(r.Stage, errAdminIdentity)
		}
		alreadyApplied := r.Stage == "enable_started" && snapshot.TaskID == t.ID && identity.Expiry == snapshot.Expiry && identity.Shell == snapshot.Shell
		if !alreadyApplied {
			if !snapshot.Disabled || identity.Expiry != "1" || identity.Shell != "/usr/sbin/nologin" {
				return finish(r.Stage, errAdminIdentity)
			}
			snapshot.TaskID = t.ID
			if adminWrite(dir, snapshotName, snapshot) != nil {
				return finish(r.Stage, errAdminState)
			}
			r.Stage = "enable_started"
			receipt.Result = r
			if adminWrite(dir, name, receipt) != nil {
				return r, ErrAccountAdmin
			}
			if e = system.modify(ctx, identity, snapshot.Expiry, snapshot.Shell); e != nil {
				return finish(r.Stage, e)
			}
		}
		r.Shell = snapshot.Shell
		snapshot.Disabled = false
		if adminWrite(dir, snapshotName, snapshot) != nil {
			return finish("enable_started", errAdminState)
		}
		return finish("enabled", nil)
	}
	if receipt.HomeProof == nil {
		proof, e := system.prepareRemove(ctx, identity)
		if e != nil {
			return finish(r.Stage, e)
		}
		receipt.HomeProof = &proof
	} else if receipt.Result.Home != "" && receipt.Result.Home != identity.Home {
		return finish(r.Stage, errAdminIdentity)
	}
	r.Stage = "delete_started"
	receipt.Result = r
	if adminWrite(dir, name, receipt) != nil {
		return r, ErrAccountAdmin
	}
	if e = system.remove(ctx, identity, *receipt.HomeProof); e != nil {
		return finish(r.Stage, e)
	}
	return finish("deleted", nil)
}

var errAdminIdentity = errors.New("identity_conflict")
var errAdminState = errors.New("state_unavailable")
var errAdminHome = errors.New("home_conflict")
var errAdminCommand = errors.New("system_command_failed")

func adminFailureCode(e error) string {
	switch {
	case errors.Is(e, errAdminIdentity):
		return "identity_conflict"
	case errors.Is(e, errAdminHome):
		return "home_conflict"
	case errors.Is(e, errAdminState):
		return "state_unavailable"
	case errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded):
		return "interrupted"
	default:
		return "system_command_failed"
	}
}
