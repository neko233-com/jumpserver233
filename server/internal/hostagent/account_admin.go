package hostagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

const AccountAdminFormat = "jms233/linux-account-admin/v1"
const MaxAccountAdminBytes = 16 << 10

var ErrAccountAdmin = errors.New("remote_account_unavailable")
var accountAdminName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{1,31}$`)
var accountAdminID = regexp.MustCompile(`^ra-[a-f0-9]{32}$`)

// AccountAdminTask contains a public SSH key and explicit identity preconditions.
// Passwords and private keys are never accepted by the privileged native helper.
type AccountAdminTask struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	Username  string `json:"username"`
	UID       uint32 `json:"uid"`
	Shell     string `json:"shell,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

func (t AccountAdminTask) Validate() error {
	if !accountAdminID.MatchString(t.ID) || !accountAdminName.MatchString(t.Username) || t.Username == "root" || t.Username == "nobody" {
		return ErrAccountAdmin
	}
	if t.Action == "create" {
		if t.UID != 0 || t.Shell != "/bin/bash" && t.Shell != "/bin/sh" || AccountAdminKeyFingerprint(t.PublicKey) == "" {
			return ErrAccountAdmin
		}
		return nil
	}
	if t.Action != "disable" && t.Action != "enable" && t.Action != "delete" || t.UID < 1000 || t.UID > 60000 || t.Shell != "" || t.PublicKey != "" {
		return ErrAccountAdmin
	}
	return nil
}

func AccountAdminKeyFingerprint(key string) string {
	parts := strings.Split(key, " ")
	if len(parts) != 2 || parts[0] != "ssh-ed25519" {
		return ""
	}
	raw, e := base64.StdEncoding.DecodeString(parts[1])
	if e != nil || len(raw) != 51 || binary.BigEndian.Uint32(raw[:4]) != 11 || string(raw[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(raw[15:19]) != 32 || base64.StdEncoding.EncodeToString(raw) != parts[1] {
		return ""
	}
	h := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}
func (t AccountAdminTask) Digest() string {
	raw, _ := json.Marshal(t)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

type AccountAdminRequest struct {
	Task AccountAdminTask `json:"task"`
	Mode string           `json:"mode"` // apply is explicit; inspect only reads a durable receipt.
}

func (r AccountAdminRequest) Validate() error {
	if r.Mode != "apply" && r.Mode != "inspect" && r.Mode != "cancel" {
		return ErrAccountAdmin
	}
	return r.Task.Validate()
}
func DecodeAccountAdminRequest(raw []byte) (AccountAdminRequest, error) {
	var r AccountAdminRequest
	if len(raw) == 0 || len(raw) > MaxAccountAdminBytes || validateJSON(raw) != nil {
		return r, ErrAccountAdmin
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Validate() != nil {
		return AccountAdminRequest{}, ErrAccountAdmin
	}
	return r, nil
}

// AccountAdminResult contains safe metadata only, including incomplete effects.
type AccountAdminResult struct {
	Format    string `json:"format"`
	ID        string `json:"id"`
	Digest    string `json:"digest"`
	Action    string `json:"action"`
	Username  string `json:"username"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Home      string `json:"home,omitempty"`
	Shell     string `json:"shell,omitempty"`
	State     string `json:"state"`
	Stage     string `json:"stage,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

func DecodeAccountAdminResult(raw []byte, task AccountAdminTask) (AccountAdminResult, error) {
	var r AccountAdminResult
	if len(raw) == 0 || len(raw) > MaxAccountAdminBytes || validateJSON(raw) != nil || task.Validate() != nil {
		return r, ErrAccountAdmin
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || r.Format != AccountAdminFormat || r.ID != task.ID || r.Digest != task.Digest() || r.Action != task.Action || r.Username != task.Username || r.UID != 0 && (r.UID < 1000 || r.UID > 60000) || !validAccountText(r.Home, 512) || !validAccountText(r.Shell, 512) {
		return AccountAdminResult{}, ErrAccountAdmin
	}
	switch r.State {
	case "absent", "prepared", "incomplete", "applied", "conflict", "cancelled":
	default:
		return AccountAdminResult{}, ErrAccountAdmin
	}
	switch r.Stage {
	case "", "prepared", "account_created", "ready", "disable_started", "disabled", "enable_started", "enabled", "delete_started", "deleted", "cancelled":
	default:
		return AccountAdminResult{}, ErrAccountAdmin
	}
	switch r.ErrorCode {
	case "", "busy", "unsafe_state", "request_conflict", "state_unavailable", "identity_conflict", "home_conflict", "interrupted", "system_command_failed":
	default:
		return AccountAdminResult{}, ErrAccountAdmin
	}
	if r.State == "applied" && (r.UID == 0 || task.UID != 0 && r.UID != task.UID || r.ErrorCode != "") {
		return AccountAdminResult{}, ErrAccountAdmin
	}
	return r, nil
}

// AccountOperation is stamped by the platform; public job JSON cannot supply it.
// Every retry has a separate attempt and approval scope, while the native task
// ID remains stable for explicit reconciliation after an uncertain effect.
type AccountOperation struct {
	CollectorAccount string           `json:"collector_account"`
	Task             AccountAdminTask `json:"task"`
	Mode             string           `json:"mode"`
	Attempt          uint64           `json:"attempt"`
	Binding          string           `json:"binding"`
	Target           string           `json:"target"`
	ParentAssetID    string           `json:"parent_asset_id"`
	AccountID        string           `json:"account_id"`
}

func (o AccountOperation) Validate() error {
	if o.CollectorAccount == "" || !validAccountText(o.CollectorAccount, 128) {
		return ErrAccountAdmin
	}
	if (AccountAdminRequest{Task: o.Task, Mode: o.Mode}).Validate() != nil || o.Attempt == 0 || o.Attempt > 1<<53-1 || !validHex(o.Binding, 32) || !validHex(o.Target, 32) || !validAccountText(o.ParentAssetID, 128) || !validAccountText(o.AccountID, 200) || o.ParentAssetID == "" || o.AccountID == "" {
		return ErrAccountAdmin
	}
	return nil
}
func (o AccountOperation) Command() string {
	return "account-admin " + o.Task.Action + " username=" + o.Task.Username + " mode=" + o.Mode + " task=" + o.Task.ID + " digest=" + o.Task.Digest() + " binding=" + o.Binding
}
func (o AccountOperation) Clone() AccountOperation { return o }
