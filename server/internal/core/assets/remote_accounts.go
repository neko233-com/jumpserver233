package assets

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	xssh "golang.org/x/crypto/ssh"
)

var ErrRemoteAccountPending = errors.New("remote account operation requires reconciliation")
var ErrRemoteAccountShared = errors.New("remote account has other managed references")
var ErrRemoteAccountConflict = errors.New("remote account operation changed")

const maxRemoteAccountTasks = 2000

type RemoteAccountState struct {
	OperationID string `json:"operation_id"`
	State       string `json:"state"`
	UID         uint32 `json:"uid,omitempty"`
	ProvisionID string `json:"provision_id,omitempty"`
}
type RemoteAccountTask struct {
	RetiredReviewID    string                        `json:"retired_review_id,omitempty"`
	RetiredReviewOwner string                        `json:"retired_review_owner,omitempty"`
	PreviousActive     bool                          `json:"previous_active"`
	PreviousRemote     *RemoteAccountState           `json:"previous_remote,omitempty"`
	Creator            AccountActor                  `json:"creator"`
	Operation          hostagent.AccountOperation    `json:"operation"`
	CollectorID        string                        `json:"collector_id"`
	OwnerID            string                        `json:"owner_id"`
	Owner              string                        `json:"owner"`
	RequestID          string                        `json:"request_id"`
	Revision           int                           `json:"revision"`
	State              string                        `json:"state"`
	JobID              string                        `json:"job_id,omitempty"`
	ReviewID           string                        `json:"review_id,omitempty"`
	ErrorCode          string                        `json:"error_code,omitempty"`
	Origin             accesspolicies.Origin         `json:"access_origin"`
	CreatedAt          time.Time                     `json:"created_at"`
	UpdatedAt          time.Time                     `json:"updated_at"`
	Result             *hostagent.AccountAdminResult `json:"result,omitempty"`
}
type RemoteAccountInput struct {
	Action    string `json:"action"`
	Username  string `json:"username"`
	Shell     string `json:"shell,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	UID       uint32 `json:"uid,omitempty"`
	Version   string `json:"version"`
	RequestID string `json:"request_id"`
}

func cloneRemoteAccountState(v *RemoteAccountState) *RemoteAccountState {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}
func remoteAccountPending(a Asset) bool {
	return a.RemoteAccount != nil && a.RemoteAccount.State == "pending"
}
func remoteTaskCopy(v RemoteAccountTask) RemoteAccountTask {
	v.PreviousRemote = cloneRemoteAccountState(v.PreviousRemote)
	if v.Result != nil {
		r := *v.Result
		v.Result = &r
	}
	return v
}
func remoteTaskTerminal(v RemoteAccountTask) bool {
	return v.State == "succeeded" || v.State == "cancelled"
}

// A versioned outer document makes older binaries refuse lifecycle metadata.
// Existing inventories without remote operations keep their original array format.
func decodeRemoteAssetRecords(raw []byte, out *[]storedAsset, imports ...*[]accountImportRecord) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var box struct {
			Format  int                   `json:"format"`
			Records []storedAsset         `json:"records"`
			Imports []accountImportRecord `json:"account_imports,omitempty"`
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&box) != nil || d.Decode(new(any)) != io.EOF || box.Format != 2 && box.Format != 3 && box.Format != 4 && box.Format != 5 || box.Records == nil || box.Format == 2 && len(box.Imports) > 0 || box.Format == 3 && (len(imports) != 1 || len(box.Imports) == 0) || len(box.Imports) > 0 && len(imports) != 1 || validateImportRecords(box.Imports) != nil {
			return ErrInvalidInput
		}
		*out = box.Records
		if box.Format < 4 {
			for _, record := range box.Records {
				if hasPlannedRotationMetadata(record) {
					return ErrInvalidInput
				}
			}
		}
		if box.Format < 5 {
			for _, record := range box.Records {
				if hasPAMAssetMetadata(record) || record.ParentAssetID == "" && !IsSSH(record.Asset) && record.PendingRotation != nil {
					return ErrInvalidInput
				}
			}
		}
		if len(imports) == 1 {
			*imports[0] = box.Imports
		}
		return nil
	}
	if e := json.Unmarshal(raw, out); e != nil {
		return e
	}
	for _, v := range *out {
		if v.PAM != nil || v.RemoteAccount != nil || len(v.RemoteOperations) > 0 || hasPlannedRotationMetadata(v) {
			return ErrInvalidInput
		}
	}
	return nil
}
func encodeRemoteAssetRecords(records []storedAsset, indent bool, receipts ...[]accountImportRecord) ([]byte, error) {
	var value any = records
	for _, v := range records {
		if v.RemoteAccount != nil || len(v.RemoteOperations) > 0 {
			value = struct {
				Format  int           `json:"format"`
				Records []storedAsset `json:"records"`
			}{2, records}
			break
		}
	}
	if len(receipts) == 1 && len(receipts[0]) > 0 {
		value = struct {
			Format  int                   `json:"format"`
			Records []storedAsset         `json:"records"`
			Imports []accountImportRecord `json:"account_imports"`
		}{3, records, receipts[0]}
	}
	for _, v := range records {
		if hasPlannedRotationMetadata(v) {
			var imports []accountImportRecord
			if len(receipts) == 1 {
				imports = receipts[0]
			}
			value = struct {
				Format  int                   `json:"format"`
				Records []storedAsset         `json:"records"`
				Imports []accountImportRecord `json:"account_imports,omitempty"`
			}{4, records, imports}
			break
		}
	}
	if indent {
		return encodePAMAssetRecords(records, receipts, value, true)
	}
	return encodePAMAssetRecords(records, receipts, value, false)
}

func encodePAMAssetRecords(records []storedAsset, receipts [][]accountImportRecord, original any, indent bool) ([]byte, error) {
	value := original
	for _, r := range records {
		if hasPAMAssetMetadata(r) || !IsSSH(r.Asset) && r.PendingRotation != nil {
			var imports []accountImportRecord
			if len(receipts) == 1 {
				imports = receipts[0]
			}
			value = struct {
				Format  int                   `json:"format"`
				Records []storedAsset         `json:"records"`
				Imports []accountImportRecord `json:"account_imports,omitempty"`
			}{5, records, imports}
			break
		}
	}
	if indent {
		return json.MarshalIndent(value, "", "  ")
	}
	return json.Marshal(value)
}
func hasPAMAssetMetadata(r storedAsset) bool {
	if r.PAM != nil {
		return true
	}
	if r.PlannedPasswordReceipt != nil && (r.PlannedPasswordReceipt.PAMBinding != "" || r.PlannedPasswordReceipt.PAMCollector != "") {
		return true
	}
	return r.PendingRotation != nil && r.PendingRotation.Planned != nil && (r.PendingRotation.Planned.PAMBinding != "" || r.PendingRotation.Planned.PAMCollector != "")
}
func validateRemoteAssetRecord(v storedAsset) error {
	if len(v.RemoteOperations) > maxRemoteAccountTasks || v.ParentAssetID != "" && len(v.RemoteOperations) > 0 {
		return ErrInvalidInput
	}
	if r := v.RemoteAccount; r != nil {
		if v.ParentAssetID == "" || !validRemoteTaskID(r.OperationID) || r.ProvisionID != "" && !validRemoteTaskID(r.ProvisionID) || r.State != "pending" && r.State != "ready" && r.State != "disabled" || r.UID != 0 && (r.UID < 1000 || r.UID > 60000) || r.State != "ready" && !v.AccountDisabled {
			return ErrInvalidInput
		}
	}
	seen := map[string]bool{}
	for _, r := range v.RemoteOperations {
		if r.Operation.Validate() != nil || r.Operation.ParentAssetID != v.ID || r.Revision < 1 || r.Revision > 1<<53-1 || !validAccountActor(r.Creator) || !validAccountActor(AccountActor{ID: r.OwnerID, Name: r.Owner}) || r.CollectorID == "" || !keyRequestPattern.MatchString(r.RequestID) || (r.RetiredReviewID == "") != (r.RetiredReviewOwner == "") || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || seen[r.Operation.Task.ID] {
			return ErrInvalidInput
		}
		seen[r.Operation.Task.ID] = true
		switch r.State {
		case "prepared", "executing", "needs_reconcile", "succeeded", "cancelled":
		default:
			return ErrInvalidInput
		}
		if r.Result != nil {
			raw, _ := json.Marshal(r.Result)
			if _, e := hostagent.DecodeAccountAdminResult(raw, r.Operation.Task); e != nil {
				return ErrInvalidInput
			}
		}
	}
	return nil
}

func validRemoteTaskID(v string) bool {
	return len(v) == 35 && strings.HasPrefix(v, "ra-") && keyRequestPattern.MatchString(v[3:]) && strings.Trim(v[3:], "0123456789abcdef") == ""
}
func (s *Store) remoteAccountCopyAllowedLocked(a Asset) error {
	for _, other := range s.assets {
		if other.ID != a.ID && remoteAccountPending(other.Asset) && other.HostKeyFingerprint == a.HostKeyFingerprint && other.Username == a.Username {
			return ErrRemoteAccountPending
		}
	}
	return nil
}

func (s *Service) RemoteAccountTasks(parentID string) ([]RemoteAccountTask, error) {
	s.store.mu.RLock()
	defer s.store.mu.RUnlock()
	r, ok := s.store.assets[parentID]
	if !ok || r.ParentAssetID != "" || !IsSSH(r.Asset) {
		return nil, ErrNotFound
	}
	out := make([]RemoteAccountTask, 0, len(r.RemoteOperations))
	for _, v := range r.RemoteOperations {
		out = append(out, remoteTaskCopy(v))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (s *Service) RemoteAccountTask(parentID, id string) (RemoteAccountTask, error) {
	all, e := s.RemoteAccountTasks(parentID)
	if e != nil {
		return RemoteAccountTask{}, e
	}
	for _, v := range all {
		if v.Operation.Task.ID == id {
			return v, nil
		}
	}
	return RemoteAccountTask{}, ErrNotFound
}

// remoteAccountUnique is called while the shared inventory mutation lock is held.
func (s *Service) remoteAccountUnique(a Asset, except string) error {
	stores := map[string]*Store{s.passwordScope: s.store}
	if s.passwordCoordinator != nil {
		stores = s.passwordCoordinator.stores
	}
	for _, store := range stores {
		for _, other := range store.List() {
			if IsSSH(other) && a.HostKeyFingerprint == other.HostKeyFingerprint && a.Username == other.Username && !(store == s.store && other.ID == except) {
				return ErrRemoteAccountShared
			}
		}
	}
	return nil
}

// PrepareRemoteAccount atomically reserves a disabled credential endpoint and
// the public task before any SSH effect. The generated private key stays in Vault.
func (s *Service) PrepareRemoteAccount(collectorID string, in RemoteAccountInput, binding, target string, actor AccountActor, origin accesspolicies.Origin) (RemoteAccountTask, error) {
	if !validAccountActor(actor) || !keyRequestPattern.MatchString(in.RequestID) || in.Version == "" {
		return RemoteAccountTask{}, ErrInvalidInput
	}
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.refreshSharedLocked()
	}
	collector, e := s.Get(collectorID)
	if e != nil || !IsSSH(collector) || collector.AccountDisabled {
		return RemoteAccountTask{}, ErrInvalidInput
	}
	parentID := ResourceID(collector)
	existing, e := s.RemoteAccountTasks(parentID)
	if e != nil {
		return RemoteAccountTask{}, e
	}
	for _, v := range existing {
		if v.OwnerID == actor.ID && v.RequestID == in.RequestID {
			t := v.Operation.Task
			if t.Action != in.Action || t.Username != in.Username || t.Shell != in.Shell || v.CollectorID != collectorID || in.AccountID != "" && v.Operation.AccountID != in.AccountID || in.UID != 0 && t.UID != in.UID {
				return RemoteAccountTask{}, ErrRemoteAccountConflict
			}
			return v, nil
		}
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return RemoteAccountTask{}, e
	}
	id := "ra-" + hex.EncodeToString(nonce[:])
	task := hostagent.AccountAdminTask{ID: id, Action: in.Action, Username: in.Username, UID: in.UID, Shell: in.Shell}
	var a Asset
	var credentials sshclient.Credentials
	if in.Action == "create" {
		if in.AccountID != "" || in.UID != 0 {
			return RemoteAccountTask{}, ErrInvalidInput
		}
		credentials, _, e = generateSSHKey()
		if e != nil {
			return RemoteAccountTask{}, e
		}
		signer, e := xssh.ParsePrivateKey(credentials.PrivateKey)
		if e != nil {
			return RemoteAccountTask{}, e
		}
		task.PublicKey = strings.TrimSpace(string(xssh.MarshalAuthorizedKey(signer.PublicKey())))
		parent, parentOK := s.find(parentID)
		if !parentOK || accountVersion(parent) != in.Version {
			return RemoteAccountTask{}, ErrCredentialChanged
		}
		a = inheritAccount(parent, Asset{ID: "account-" + parentID + "-" + hex.EncodeToString(nonce[:]), ParentAssetID: parentID, Username: in.Username, AccountName: in.Username, AccountDisabled: true, PasswordRotationDisabled: true, CredentialType: CredentialSSHKey, KeyFingerprint: xssh.FingerprintSHA256(signer.PublicKey()), KeyRotationEnabled: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), CredentialRevision: 1})
	} else {
		a, e = s.AccountAsset(parentID, in.AccountID)
		if e != nil || a.ParentAssetID == "" || a.Username != in.Username || a.Username == collector.Username {
			return RemoteAccountTask{}, ErrInvalidInput
		}
		if accountVersion(a) != in.Version {
			return RemoteAccountTask{}, ErrCredentialChanged
		}
		if remoteAccountPending(a) {
			return RemoteAccountTask{}, ErrRemoteAccountPending
		}
		if a.RemoteAccount != nil && a.RemoteAccount.UID != 0 && a.RemoteAccount.UID != in.UID {
			return RemoteAccountTask{}, ErrRemoteAccountConflict
		}
		if in.Action == "enable" && (a.RemoteAccount == nil || a.RemoteAccount.State != "disabled") {
			return RemoteAccountTask{}, ErrInvalidInput
		}
	}
	if task.Validate() != nil {
		return RemoteAccountTask{}, ErrInvalidInput
	}
	if e = s.remoteAccountUnique(a, a.ID); e != nil {
		return RemoteAccountTask{}, e
	}
	operation := hostagent.AccountOperation{Task: task, Mode: "apply", Attempt: 1, Binding: binding, Target: target, ParentAssetID: parentID, AccountID: a.ID}
	operation.CollectorAccount = collector.Username
	if operation.Validate() != nil {
		return RemoteAccountTask{}, ErrInvalidInput
	}
	now := time.Now().UTC()
	result := RemoteAccountTask{PreviousActive: !a.AccountDisabled, PreviousRemote: cloneRemoteAccountState(a.RemoteAccount), Creator: actor, Operation: operation, CollectorID: collectorID, OwnerID: actor.ID, Owner: actor.Name, RequestID: in.RequestID, Revision: 1, State: "prepared", Origin: origin, CreatedAt: now, UpdatedAt: now}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	parent, ok := s.store.assets[parentID]
	if !ok || parent.ParentAssetID != "" || len(parent.RemoteOperations) >= maxRemoteAccountTasks {
		return RemoteAccountTask{}, ErrAccountCapacity
	}
	for _, v := range parent.RemoteOperations {
		if !remoteTaskTerminal(v) && v.Operation.AccountID == a.ID {
			return RemoteAccountTask{}, ErrRemoteAccountPending
		}
	}
	previous, exists := s.store.assets[a.ID]
	if in.Action == "create" {
		if exists || accountVersion(parent.Asset) != in.Version {
			return RemoteAccountTask{}, ErrCredentialChanged
		}
		for _, v := range s.store.assets {
			if ResourceID(v.Asset) == parentID && v.Username == a.Username {
				return RemoteAccountTask{}, ErrAccountDuplicate
			}
		}
	} else {
		if !exists || accountVersion(previous.Asset) != in.Version || previous.PendingRotation != nil || previous.PendingKeyChange != nil || s.rotationRunning[a.ID] {
			return RemoteAccountTask{}, ErrCredentialChanged
		}
	}
	if in.Action == "delete" {
		for _, v := range s.store.assets {
			if v.GatewayID == a.ID {
				return RemoteAccountTask{}, ErrGatewayInUse
			}
		}
	}
	if len(previous.AccountAudit) >= maxAccountAudit {
		return RemoteAccountTask{}, ErrAccountCapacity
	}
	r := previous
	if in.Action == "create" {
		r = storedAsset{Asset: a, PasswordRotatedAt: now}
		a.PasswordRotatedAt = now
		r.Credential, e = s.store.sealCredentials(&a, credentials)
		if e != nil {
			return RemoteAccountTask{}, e
		}
		a.KeyRotatedAt = now
	}
	state := cloneRemoteAccountState(a.RemoteAccount)
	if state == nil {
		state = &RemoteAccountState{}
	}
	state.OperationID = id
	state.State = "pending"
	if in.Action == "create" {
		state.ProvisionID = id
	}
	if in.UID != 0 {
		state.UID = in.UID
	}
	a.RemoteAccount = state
	a.AccountDisabled = true
	a.UpdatedAt = now
	r.Asset = a
	r.AccountAudit = append(append([]AccountAudit(nil), r.AccountAudit...), newAccountAudit("remote_"+in.Action+"_requested", actor, a, in.Version, accountVersion(a)))
	updatedParent := parent
	updatedParent.RemoteOperations = append(append([]RemoteAccountTask(nil), parent.RemoteOperations...), result)
	s.store.assets[a.ID] = r
	s.store.assets[parentID] = updatedParent
	if e = s.store.persistLocked(); e != nil {
		if exists {
			s.store.assets[a.ID] = previous
		} else {
			delete(s.store.assets, a.ID)
		}
		s.store.assets[parentID] = parent
		return RemoteAccountTask{}, e
	}
	return remoteTaskCopy(result), nil
}

func (s *Service) RemoteAccountOperationAllowed(owner, collector string, op *hostagent.AccountOperation) bool {
	if op == nil || op.Validate() != nil {
		return false
	}
	task, e := s.RemoteAccountTask(op.ParentAssetID, op.Task.ID)
	return e == nil && task.OwnerID == owner && task.CollectorID == collector && reflect.DeepEqual(task.Operation, *op)
}

type RemoteAccountExecutor func(context.Context, string, string, string, hostagent.AccountOperation, func() error) (hostagent.AccountAdminResult, error)

func (s *Service) mutateRemoteAccountTask(parentID, id string, fn func(*storedAsset, *RemoteAccountTask) error) (RemoteAccountTask, error) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	previous, ok := s.store.assets[parentID]
	if !ok {
		return RemoteAccountTask{}, ErrNotFound
	}
	parent := previous
	parent.RemoteOperations = append([]RemoteAccountTask(nil), previous.RemoteOperations...)
	for i, v := range parent.RemoteOperations {
		if v.Operation.Task.ID != id {
			continue
		}
		next := remoteTaskCopy(v)
		if next.Revision >= 1<<53-1 {
			return RemoteAccountTask{}, ErrRemoteAccountConflict
		}
		if e := fn(&parent, &next); e != nil {
			return RemoteAccountTask{}, e
		}
		next.Revision++
		next.UpdatedAt = time.Now().UTC()
		parent.RemoteOperations[i] = next
		s.store.assets[parentID] = parent
		if e := s.store.persistLocked(); e != nil {
			s.store.assets[parentID] = previous
			return RemoteAccountTask{}, e
		}
		return remoteTaskCopy(next), nil
	}
	return RemoteAccountTask{}, ErrNotFound
}

func (s *Service) BindRemoteAccountSubmission(op hostagent.AccountOperation, jobID, reviewID string) (RemoteAccountTask, error) {
	return s.mutateRemoteAccountTask(op.ParentAssetID, op.Task.ID, func(_ *storedAsset, v *RemoteAccountTask) error {
		if !reflect.DeepEqual(v.Operation, op) {
			return ErrRemoteAccountConflict
		}
		if remoteTaskTerminal(*v) {
			if jobID != "" && v.JobID == jobID {
				return nil
			}
			return ErrRemoteAccountConflict
		}
		if jobID != "" {
			if v.JobID != "" && v.JobID != jobID {
				return ErrRemoteAccountConflict
			}
			v.JobID = jobID
		}
		if reviewID != "" {
			v.ReviewID = reviewID
		}
		return nil
	})
}

// ResumeRemoteAccount never runs SSH. The caller must first ensure that the
// previous job is terminal and reauthorize the complete pinned route.
func (s *Service) ResumeRemoteAccount(parentID, id string, revision int, mode, binding string, actor AccountActor, origin accesspolicies.Origin) (RemoteAccountTask, error) {
	if !validAccountActor(actor) {
		return RemoteAccountTask{}, ErrInvalidInput
	}
	return s.mutateRemoteAccountTask(parentID, id, func(_ *storedAsset, v *RemoteAccountTask) error {
		if v.Revision != revision || remoteTaskTerminal(*v) || v.Operation.Attempt >= 1<<53-1 {
			return ErrRemoteAccountConflict
		}
		if v.RetiredReviewID != "" {
			return ErrRemoteAccountPending
		}
		if (hostagent.AccountAdminRequest{Task: v.Operation.Task, Mode: mode}).Validate() != nil {
			return ErrInvalidInput
		}
		op := v.Operation
		op.Mode = mode
		op.Binding = binding
		op.Attempt++
		if op.Validate() != nil {
			return ErrInvalidInput
		}
		v.RetiredReviewID = v.ReviewID
		v.RetiredReviewOwner = ""
		if v.ReviewID != "" {
			v.RetiredReviewOwner = v.OwnerID
		}
		v.Operation = op
		v.OwnerID = actor.ID
		v.Owner = actor.Name
		v.Origin = origin
		v.State = "prepared"
		v.ErrorCode = ""
		v.JobID = ""
		v.ReviewID = ""
		return nil
	})
}

func (s *Service) AcknowledgeRemoteAccountReview(parent, id, review string) (RemoteAccountTask, error) {
	return s.mutateRemoteAccountTask(parent, id, func(_ *storedAsset, t *RemoteAccountTask) error {
		if t.RetiredReviewID != review {
			return ErrRemoteAccountConflict
		}
		t.RetiredReviewID = ""
		t.RetiredReviewOwner = ""
		return nil
	})
}

// ExecuteRemoteAccount first records a durable attempt, then stores observations
// as needs_reconcile. Promoting a credential is a separate, authorized commit.
func (s *Service) ExecuteRemoteAccount(ctx context.Context, op hostagent.AccountOperation, jobID string, execute RemoteAccountExecutor, guard func() error) (hostagent.AccountAdminResult, error) {
	if execute == nil || guard == nil || op.Validate() != nil {
		return hostagent.AccountAdminResult{}, ErrInvalidInput
	}
	if e := guard(); e != nil {
		return hostagent.AccountAdminResult{}, e
	}
	task, e := s.mutateRemoteAccountTask(op.ParentAssetID, op.Task.ID, func(_ *storedAsset, v *RemoteAccountTask) error {
		if remoteTaskTerminal(*v) || !reflect.DeepEqual(v.Operation, op) {
			return ErrRemoteAccountConflict
		}
		if v.JobID != "" && v.JobID != jobID {
			return ErrRemoteAccountConflict
		}
		v.JobID = jobID
		v.State = "executing"
		return nil
	})
	if e != nil {
		return hostagent.AccountAdminResult{}, e
	}
	result, execError := execute(ctx, task.CollectorID, jobID, op.ParentAssetID, op, guard)
	_, saveError := s.mutateRemoteAccountTask(op.ParentAssetID, op.Task.ID, func(_ *storedAsset, v *RemoteAccountTask) error {
		if !reflect.DeepEqual(v.Operation, op) || remoteTaskTerminal(*v) {
			return ErrRemoteAccountConflict
		}
		v.State = "needs_reconcile"
		v.ErrorCode = "remote_unavailable"
		if result.Format != "" {
			raw, _ := json.Marshal(result)
			if _, e := hostagent.DecodeAccountAdminResult(raw, op.Task); e != nil {
				return ErrInvalidInput
			}
			v.Result = &result
			v.ErrorCode = result.ErrorCode
		}
		return nil
	})
	if saveError != nil {
		return result, saveError
	}
	if execError != nil {
		return result, execError
	}
	if result.State != "applied" && result.State != "cancelled" {
		return result, ErrRemoteAccountPending
	}
	if e = guard(); e != nil {
		return result, e
	}
	if result.State == "applied" && op.Task.Action == "create" {
		_, route, _, e := s.store.connection(task.CollectorID)
		if e != nil {
			return result, e
		}
		s.store.mu.RLock()
		record, ok := s.store.assets[op.AccountID]
		if !ok || !remoteAccountPending(record.Asset) || record.RemoteAccount.OperationID != op.Task.ID {
			s.store.mu.RUnlock()
			return result, ErrRemoteAccountConflict
		}
		a := record.Asset
		plain, e := s.store.aead.Open(nil, record.Credential.Nonce, record.Credential.Ciphertext, credentialAAD(record.ID, record.CredentialType, ""))
		s.store.mu.RUnlock()
		if e != nil {
			return result, e
		}
		target := sshTarget(a)
		target.Admission = s.store.admissionGate()
		target.Gateways = route.Gateways
		credentials := decodeCredentials(a.CredentialType, plain)
		if e = s.verifyPassword(ctx, target, credentials, 8*time.Second); e != nil {
			_, _ = s.mutateRemoteAccountTask(op.ParentAssetID, op.Task.ID, func(_ *storedAsset, v *RemoteAccountTask) error {
				if !reflect.DeepEqual(v.Operation, op) || remoteTaskTerminal(*v) {
					return ErrRemoteAccountConflict
				}
				v.ErrorCode = "credential_verification_failed"
				return nil
			})
			return result, ErrRemoteAccountPending
		}
	}
	return result, nil
}

// CommitRemoteAccount must run after the API's current authorization guard,
// under its publication read lock. It atomically promotes or removes the Vault
// endpoint together with its run receipt and account activity.
func (s *Service) CommitRemoteAccount(op hostagent.AccountOperation, result hostagent.AccountAdminResult) (RemoteAccountTask, error) {
	if result.ID != op.Task.ID || result.Digest != op.Task.Digest() || result.State != "applied" && result.State != "cancelled" {
		return RemoteAccountTask{}, ErrInvalidInput
	}
	if c := s.passwordCoordinator; c != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		defer c.refreshSharedLocked()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	previousParent, ok := s.store.assets[op.ParentAssetID]
	if !ok {
		return RemoteAccountTask{}, ErrNotFound
	}
	parent := previousParent
	parent.RemoteOperations = append([]RemoteAccountTask(nil), parent.RemoteOperations...)
	index := -1
	var task RemoteAccountTask
	for i, v := range parent.RemoteOperations {
		if v.Operation.Task.ID == op.Task.ID {
			index = i
			task = remoteTaskCopy(v)
			break
		}
	}
	if index < 0 || !reflect.DeepEqual(task.Operation, op) || remoteTaskTerminal(task) || task.Result == nil || !reflect.DeepEqual(*task.Result, result) || task.Revision >= 1<<53-1 {
		return RemoteAccountTask{}, ErrRemoteAccountConflict
	}
	previous, ok := s.store.assets[op.AccountID]
	if !ok || !remoteAccountPending(previous.Asset) || previous.RemoteAccount.OperationID != op.Task.ID {
		return RemoteAccountTask{}, ErrRemoteAccountConflict
	}
	if len(previous.AccountAudit) >= maxAccountAudit {
		return RemoteAccountTask{}, ErrAccountCapacity
	}
	r := previous
	a := cloneAsset(r.Asset)
	before := accountVersion(a)
	a.UpdatedAt = time.Now().UTC()
	state := cloneRemoteAccountState(a.RemoteAccount)
	remove := result.State == "cancelled" && op.Task.Action == "create" || result.State == "applied" && op.Task.Action == "delete"
	if result.State == "cancelled" && op.Mode != "cancel" {
		return RemoteAccountTask{}, ErrInvalidInput
	}
	actor := AccountActor{ID: task.OwnerID, Name: task.Owner}
	audit := newAccountAudit("remote_"+op.Task.Action+"_"+result.State, actor, a, before, "")
	if !remove {
		state.UID = result.UID
		state.State = "ready"
		a.AccountDisabled = false
		if op.Task.Action == "disable" {
			state.State = "disabled"
			a.AccountDisabled = true
		}
		a.RemoteAccount = state
		if result.State == "cancelled" {
			a.RemoteAccount = cloneRemoteAccountState(task.PreviousRemote)
			a.AccountDisabled = !task.PreviousActive
		}
		r.Asset = a
		audit.After = accountVersion(a)
		r.AccountAudit = append(append([]AccountAudit(nil), r.AccountAudit...), audit)
		s.store.assets[a.ID] = r
	} else {
		if len(parent.AccountAudit)+len(r.AccountAudit)+1 > maxAccountAudit {
			return RemoteAccountTask{}, ErrAccountCapacity
		}
		parent.AccountAudit = append(append([]AccountAudit(nil), parent.AccountAudit...), r.AccountAudit...)
		parent.AccountAudit = append(parent.AccountAudit, audit)
		delete(s.store.assets, a.ID)
	}
	task.State = "succeeded"
	if result.State == "cancelled" {
		task.State = "cancelled"
	}
	task.ErrorCode = ""
	task.Revision++
	task.UpdatedAt = time.Now().UTC()
	task.Result = &result
	parent.RemoteOperations[index] = task
	s.store.assets[op.ParentAssetID] = parent
	if e := s.store.persistLocked(); e != nil {
		s.store.assets[op.ParentAssetID] = previousParent
		s.store.assets[op.AccountID] = previous
		return RemoteAccountTask{}, e
	}
	delete(s.status, a.ID)
	delete(s.last, a.ID)
	delete(s.rotationStatus, a.ID)
	return remoteTaskCopy(task), nil
}
