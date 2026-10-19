package jobs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/core/accessreviews"
	"github.com/neko233-com/jumpserver233/server/internal/core/accountdiscovery"
	"github.com/neko233-com/jumpserver233/server/internal/core/hostplugins"
	"github.com/neko233-com/jumpserver233/server/internal/core/playbooks"
	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid      = errors.New("invalid job input")
	ErrNotFound     = errors.New("job not found")
	ErrConflict     = errors.New("job state or request ID conflicts")
	ErrBusy         = errors.New("job capacity reached")
	ErrAccessDenied = errors.New("job execution access policy denied")
)

type Input struct {
	ConnectionScope string                      `json:"-"`
	PlaybookStep    *playbooks.Execution        `json:"-"`
	RemoteAccount   *hostagent.AccountOperation `json:"-"`
	Discovery       *accountdiscovery.Operation `json:"-"`
	Plugin          *hostplugins.Operation      `json:"-"`
	Origin          accesspolicies.Origin       `json:"-"`
	AssetID         string                      `json:"asset_id"`
	Command         string                      `json:"command"`
	TimeoutSeconds  int                         `json:"timeout_seconds"`
	RequestID       string                      `json:"request_id"`
}
type Job struct {
	ConnectionScope string                      `json:"connection_scope,omitempty"`
	PlaybookStep    *playbooks.Execution        `json:"playbook_step,omitempty"`
	RemoteAccount   *hostagent.AccountOperation `json:"remote_account,omitempty"`
	Discovery       *accountdiscovery.Operation `json:"account_discovery,omitempty"`
	Plugin          *hostplugins.Operation      `json:"plugin,omitempty"`
	AccessOrigin    accesspolicies.Origin       `json:"access_origin,omitempty"`
	ID              string                      `json:"id"`
	AssetID         string                      `json:"asset_id"`
	AssetName       string                      `json:"asset_name"`
	Account         string                      `json:"account"`
	OperatorID      string                      `json:"operator_id"`
	Operator        string                      `json:"operator"`
	Command         string                      `json:"command"`
	TimeoutSeconds  int                         `json:"timeout_seconds"`
	RequestID       string                      `json:"request_id,omitempty"`
	State           string                      `json:"state"`
	RuleName        string                      `json:"rule_name,omitempty"`
	ReviewedBy      string                      `json:"reviewed_by,omitempty"`
	CreatedAt       time.Time                   `json:"created_at"`
	StartedAt       time.Time                   `json:"started_at,omitzero"`
	FinishedAt      time.Time                   `json:"finished_at,omitzero"`
	sshclient.ExecResult
	ErrorCode string `json:"error_code,omitempty"`
}
type Executor func(context.Context, string, string) (sshclient.ExecResult, error)
type Service struct {
	mu                sync.Mutex
	path              string
	documents         *storage.Documents
	aead              cipher.AEAD
	jobs              map[string]Job
	running           map[string]context.CancelFunc
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	exec              Executor
	contextBinder     func(context.Context, Job) (context.Context, error)
	pluginExec        func(context.Context, Job) (sshclient.ExecResult, error)
	discoveryExec     func(context.Context, Job) (sshclient.ExecResult, error)
	remoteAccountExec func(context.Context, Job) (sshclient.ExecResult, error)
	executionGuard    func(Job) error
	abandoned         bool
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func Open(path string, key []byte, documents *storage.Documents, exec Executor) (*Service, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if exec == nil {
		return nil, fmt.Errorf("job executor is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{path: path, documents: documents, aead: aead, jobs: map[string]Job{}, running: map[string]context.CancelFunc{}, ctx: ctx, cancel: cancel, exec: exec}
	var data []byte
	if documents != nil {
		data, err = documents.LoadOrImport("ssh-jobs", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		cancel()
		return nil, err
	}
	if len(data) > 0 {
		var e envelope
		if json.Unmarshal(data, &e) != nil || e.Version < 1 || e.Version > 5 || len(e.Nonce) != aead.NonceSize() {
			cancel()
			return nil, fmt.Errorf("invalid encrypted job store")
		}
		plain, err := aead.Open(nil, e.Nonce, e.Ciphertext, []byte(fmt.Sprintf("jms233/ssh-jobs/v%d", e.Version)))
		if err != nil {
			cancel()
			return nil, fmt.Errorf("decrypt job store: %w", err)
		}
		var records []Job
		if json.Unmarshal(plain, &records) != nil || len(records) > 1000 {
			cancel()
			return nil, fmt.Errorf("invalid job records")
		}
		for _, j := range records {
			if j.PlaybookStep != nil && (e.Version < 4 || j.PlaybookStep.Validate() != nil || j.RemoteAccount != nil || j.Discovery != nil || j.Plugin != nil) {
				cancel()
				return nil, ErrInvalid
			}
			if j.ConnectionScope != "" {
				if _, err := accessreviews.ParseConnectionScope(j.ConnectionScope); err != nil || e.Version < 5 || j.RemoteAccount != nil || j.Discovery != nil || j.Plugin != nil {
					cancel()
					return nil, ErrInvalid
				}
			}
			if j.RemoteAccount != nil && (e.Version < 3 || j.RemoteAccount.Validate() != nil || j.Command != j.RemoteAccount.Command() || j.Discovery != nil || j.Plugin != nil) {
				cancel()
				return nil, ErrInvalid
			}
			if j.Discovery != nil && (j.Discovery.Validate() != nil || j.Discovery.PlanID != "" && (e.Version < 2 || j.Discovery.Sequence == 0)) {
				cancel()
				return nil, ErrInvalid
			}
			if j.ID == "" || j.OperatorID == "" || j.AssetID == "" || !validState(j.State) {
				cancel()
				return nil, fmt.Errorf("invalid job record")
			}
			if _, ok := s.jobs[j.ID]; ok {
				cancel()
				return nil, fmt.Errorf("duplicate job ID")
			}
			s.jobs[j.ID] = j
		}
	}
	changed := false
	for id, j := range s.jobs {
		if j.State == "running" {
			j.State = "interrupted"
			j.ErrorCode = "node_restarted"
			j.FinishedAt = time.Now().UTC()
			s.jobs[id] = j
			changed = true
		}
	}
	if changed {
		if err := s.persistLocked(); err != nil {
			cancel()
			return nil, err
		}
	}
	return s, nil
}
func validState(v string) bool {
	switch v {
	case "pending_review", "running", "succeeded", "failed", "denied", "cancelled", "timed_out", "interrupted":
		return true
	}
	return false
}
func Validate(in Input) (Input, error) {
	if in.ConnectionScope != "" {
		if _, err := accessreviews.ParseConnectionScope(in.ConnectionScope); err != nil || in.RemoteAccount != nil || in.Discovery != nil || in.Plugin != nil {
			return in, ErrInvalid
		}
	}
	if in.PlaybookStep != nil {
		if in.PlaybookStep.Validate() != nil || in.RemoteAccount != nil || in.Discovery != nil || in.Plugin != nil {
			return in, ErrInvalid
		}
		copy := *in.PlaybookStep
		in.PlaybookStep = &copy
	}
	if in.RemoteAccount != nil {
		if in.Discovery != nil || in.Plugin != nil || in.RemoteAccount.Validate() != nil || in.Command != in.RemoteAccount.Command() {
			return in, ErrInvalid
		}
		o := in.RemoteAccount.Clone()
		in.RemoteAccount = &o
	}
	if in.Discovery != nil {
		if in.Plugin != nil || in.Discovery.Validate() != nil || in.Discovery.PlanID != "" && in.Discovery.Sequence == 0 || in.Command != in.Discovery.Command() {
			return in, ErrInvalid
		}
		o := in.Discovery.Clone()
		in.Discovery = &o
	}
	if in.Plugin != nil {
		if in.Plugin.Validate() != nil || in.Command != in.Plugin.Command() {
			return in, ErrInvalid
		}
		op := in.Plugin.Clone()
		in.Plugin = &op
	}
	in.Command = strings.TrimSpace(in.Command)
	in.AssetID = strings.TrimSpace(in.AssetID)
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = 60
	}
	if in.AssetID == "" || len(in.AssetID) > 128 || in.Command == "" || len(in.Command) > 8192 || in.TimeoutSeconds < 1 || in.TimeoutSeconds > 300 || len(in.RequestID) > 128 {
		return in, ErrInvalid
	}
	if strings.IndexFunc(in.RequestID, unicode.IsControl) >= 0 || strings.IndexFunc(in.Command, func(c rune) bool { return unicode.IsControl(c) && (in.PlaybookStep == nil || c != '\n' && c != '\t') }) >= 0 {
		return in, ErrInvalid
	}
	return in, nil
}
func (s *Service) Submit(in Input, actorID, actor, assetName, account, decision, rule string) (Job, error) {
	return s.SubmitWithGate(in, actorID, actor, assetName, account, decision, rule, nil)
}

// The gate runs after deduplication and capacity checks, before persistence and
// SSH execution. It can consume a one-use login permit without losing it to a
// busy executor; gate failures never execute the command.
func (s *Service) SubmitWithGate(in Input, actorID, actor, assetName, account, decision, rule string, gate func() error) (Job, error) {
	in, err := Validate(in)
	if err != nil {
		return Job{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.expireLocked(); err != nil {
		return Job{}, err
	}
	if s.ctx.Err() != nil {
		return Job{}, ErrBusy
	}
	for _, j := range s.jobs {
		if in.RequestID != "" && j.OperatorID == actorID && j.RequestID == in.RequestID {
			if j.AssetID != in.AssetID || j.Command != in.Command || j.TimeoutSeconds != in.TimeoutSeconds || (!samePlugin(j.Plugin, in.Plugin) || !sameDiscovery(j.Discovery, in.Discovery) || !sameRemoteAccount(j.RemoteAccount, in.RemoteAccount) || !samePlaybookStep(j.PlaybookStep, in.PlaybookStep)) {
				return Job{}, ErrConflict
			}
			return cloneJob(j), nil
		}
	}
	if len(s.jobs) >= 1000 {
		return Job{}, ErrBusy
	}
	var raw [16]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return Job{}, err
	}
	j := Job{ConnectionScope: in.ConnectionScope, PlaybookStep: in.PlaybookStep, RemoteAccount: in.RemoteAccount, Discovery: in.Discovery, Plugin: in.Plugin, AccessOrigin: in.Origin, ID: "job-" + hex.EncodeToString(raw[:]), AssetID: in.AssetID, AssetName: assetName, Account: account, OperatorID: actorID, Operator: actor, Command: in.Command, TimeoutSeconds: in.TimeoutSeconds, RequestID: in.RequestID, RuleName: rule, CreatedAt: time.Now().UTC(), ExecResult: sshclient.ExecResult{ExitCode: -1}}
	switch decision {
	case "deny":
		j.State = "denied"
		j.ErrorCode = "command_denied"
		j.FinishedAt = j.CreatedAt
	case "review":
		j.State = "pending_review"
	default:
		j.State = "running"
		j.StartedAt = j.CreatedAt
	}
	pending := 0
	for _, old := range s.jobs {
		if old.OperatorID == actorID && old.State == "pending_review" {
			pending++
		}
	}
	if pending >= 20 || (j.State == "running" && !s.capacityLocked(actorID)) {
		return Job{}, ErrBusy
	}
	if gate != nil {
		if err := gate(); err != nil {
			return Job{}, err
		}
	}
	s.jobs[j.ID] = j
	if err = s.persistLocked(); err != nil {
		delete(s.jobs, j.ID)
		return Job{}, err
	}
	if j.State == "running" {
		s.launchLocked(j)
	}
	return cloneJob(j), nil
}
func (s *Service) capacityLocked(owner string) bool {
	n := 0
	for id := range s.running {
		if s.jobs[id].OperatorID == owner {
			n++
		}
	}
	return len(s.running) < 8 && n < 2
}
func (s *Service) Review(id, reviewer string, approve bool) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.expireLocked(); err != nil {
		return Job{}, err
	}
	j, ok := s.jobs[id]
	if !ok {
		return Job{}, ErrNotFound
	}
	if j.State != "pending_review" {
		return Job{}, ErrConflict
	}
	if approve && (s.ctx.Err() != nil || !s.capacityLocked(j.OperatorID)) {
		return Job{}, ErrBusy
	}
	previous := j
	j.ReviewedBy = reviewer
	if approve {
		j.State = "running"
		j.StartedAt = time.Now().UTC()
	} else {
		j.State = "denied"
		j.ErrorCode = "review_denied"
		j.FinishedAt = time.Now().UTC()
	}
	s.jobs[id] = j
	if err := s.persistLocked(); err != nil {
		s.jobs[id] = previous
		return Job{}, err
	}
	if approve {
		s.launchLocked(j)
	}
	return cloneJob(j), nil
}
func samePlugin(a, b *hostplugins.Operation) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Command() == b.Command()
}

func sameDiscovery(a, b *accountdiscovery.Operation) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Command() == b.Command()
}

func cloneJob(j Job) Job {
	if j.PlaybookStep != nil {
		copy := *j.PlaybookStep
		j.PlaybookStep = &copy
	}
	if j.RemoteAccount != nil {
		o := j.RemoteAccount.Clone()
		j.RemoteAccount = &o
	}
	if j.Discovery != nil {
		o := j.Discovery.Clone()
		j.Discovery = &o
	}
	if j.Plugin != nil {
		o := j.Plugin.Clone()
		j.Plugin = &o
	}
	return j
}
func (s *Service) SetPluginExecutor(exec func(context.Context, Job) (sshclient.ExecResult, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pluginExec = exec
}

// A persisted ordinary command proof requires the authenticated server binder.
// It must never fall back to the unbound executor after restart or takeover.
func (s *Service) SetConnectionContext(binder func(context.Context, Job) (context.Context, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contextBinder = binder
}
func (s *Service) SetDiscoveryExecutor(exec func(context.Context, Job) (sshclient.ExecResult, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discoveryExec = exec
}

func (s *Service) SetRemoteAccountExecutor(exec func(context.Context, Job) (sshclient.ExecResult, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remoteAccountExec = exec
}
func sameRemoteAccount(a, b *hostagent.AccountOperation) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func samePlaybookStep(a, b *playbooks.Execution) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
func (s *Service) SetExecutionGuard(guard func(Job) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executionGuard = guard
}
func (s *Service) launchLocked(j Job) {
	j = cloneJob(j)
	guard := s.executionGuard
	pluginExec := s.pluginExec
	binder := s.contextBinder
	if j.Discovery != nil {
		pluginExec = s.discoveryExec
	}
	if j.RemoteAccount != nil {
		pluginExec = s.remoteAccountExec
	}
	timeoutCtx, timeoutCancel := context.WithTimeout(s.ctx, time.Duration(j.TimeoutSeconds)*time.Second)
	ctx, causeCancel := context.WithCancelCause(timeoutCtx)
	cancel := func() { causeCancel(context.Canceled); timeoutCancel() }
	s.running[j.ID] = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		var result sshclient.ExecResult
		var err error
		if j.PlaybookStep != nil && guard == nil {
			err = ErrAccessDenied
		}
		if guard != nil {
			err = guard(j)
		}
		if err == nil {
			if j.Plugin != nil || j.Discovery != nil || j.RemoteAccount != nil {
				if pluginExec == nil || guard == nil {
					err = ErrAccessDenied
				} else {
					watchDone := make(chan struct{})
					watchExit := make(chan struct{})
					go func() {
						defer close(watchExit)
						ticker := time.NewTicker(500 * time.Millisecond)
						defer ticker.Stop()
						for {
							select {
							case <-watchDone:
								return
							case <-ctx.Done():
								return
							case <-ticker.C:
								if e := guard(j); e != nil {
									causeCancel(ErrAccessDenied)
									return
								}
							}
						}
					}()
					result, err = pluginExec(ctx, j)
					close(watchDone)
					<-watchExit
					if errors.Is(context.Cause(ctx), ErrAccessDenied) {
						err = ErrAccessDenied
					}
				}
			} else {
				if j.ConnectionScope != "" {
					if binder == nil || guard == nil {
						err = ErrAccessDenied
					} else {
						bound, bindErr := binder(ctx, j)
						if bindErr != nil || bound == nil {
							err = ErrAccessDenied
						} else {
							ctx = bound
						}
					}
				}
				if err == nil {
					result, err = s.exec(ctx, j.AssetID, j.Command)
				}
			}
		}
		if len(result.Stdout) > sshclient.MaxExecOutput {
			result.Stdout = result.Stdout[:sshclient.MaxExecOutput]
			result.Truncated = true
		}
		remaining := sshclient.MaxExecOutput - len(result.Stdout)
		if len(result.Stderr) > remaining {
			result.Stderr = result.Stderr[:remaining]
			result.Truncated = true
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		current := s.jobs[j.ID]
		delete(s.running, j.ID)
		current.ExecResult = result
		current.FinishedAt = time.Now().UTC()
		switch {
		case errors.Is(context.Cause(ctx), ErrAccessDenied):
			current.State = "failed"
			current.ErrorCode = "access_policy_denied"
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			current.State = "timed_out"
			current.ErrorCode = "timeout"
		case ctx.Err() != nil:
			current.State = "cancelled"
			current.ErrorCode = "cancelled"
		case errors.Is(err, ErrAccessDenied):
			current.State = "failed"
			current.ErrorCode = "access_policy_denied"
		case err != nil:
			current.State = "failed"
			current.ErrorCode = "ssh_failed"
		case result.ExitCode != 0:
			current.State = "failed"
			current.ErrorCode = "remote_exit"
		default:
			current.State = "succeeded"
		}
		s.jobs[j.ID] = current
		if !s.abandoned {
			if err := s.persistLocked(); err != nil {
				current.State = "interrupted"
				current.ErrorCode = "audit_unavailable"
				s.jobs[j.ID] = current
			}
		}
	}()
}
func (s *Service) Get(id string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.expireLocked(); err != nil {
		return Job{}, err
	}
	j, ok := s.jobs[id]
	if !ok {
		return Job{}, ErrNotFound
	}
	return cloneJob(j), nil
}
func (s *Service) FindRequest(owner string, in Input) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, j := range s.jobs {
		if in.RequestID != "" && j.OperatorID == owner && j.RequestID == in.RequestID {
			if j.AssetID != in.AssetID || j.Command != in.Command || j.TimeoutSeconds != in.TimeoutSeconds || (!samePlugin(j.Plugin, in.Plugin) || !sameDiscovery(j.Discovery, in.Discovery) || !sameRemoteAccount(j.RemoteAccount, in.RemoteAccount) || !samePlaybookStep(j.PlaybookStep, in.PlaybookStep)) {
				return Job{}, false, ErrConflict
			}
			return cloneJob(j), true, nil
		}
	}
	return Job{}, false, nil
}
func (s *Service) List(owner string, offset, limit int) ([]Job, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.expireLocked(); err != nil {
		return nil, 0, err
	}
	all := []Job{}
	for _, j := range s.jobs {
		if owner == "" || j.OperatorID == owner {
			j.Stdout = ""
			j.Stderr = ""
			all = append(all, cloneJob(j))
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].ID > all[j].ID
		}
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})
	total := len(all)
	offset = min(max(offset, 0), total)
	return all[offset:min(total, offset+limit)], total, nil
}
func (s *Service) expireLocked() error {
	old := make(map[string]Job, len(s.jobs))
	changed := false
	now := time.Now().UTC()
	for id, j := range s.jobs {
		old[id] = j
		if j.State == "pending_review" && now.Sub(j.CreatedAt) >= 5*time.Minute {
			j.State = "timed_out"
			j.ErrorCode = "review_expired"
			j.FinishedAt = now
			s.jobs[id] = j
			changed = true
		}
	}
	if changed {
		if err := s.persistLocked(); err != nil {
			s.jobs = old
			return err
		}
	}
	return nil
}
func (s *Service) Cancel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if cancel, ok := s.running[id]; ok {
		cancel()
		return nil
	}
	if j.State != "pending_review" {
		return ErrConflict
	}
	old := j
	j.State = "cancelled"
	j.ErrorCode = "cancelled"
	j.FinishedAt = time.Now().UTC()
	s.jobs[id] = j
	if err := s.persistLocked(); err != nil {
		s.jobs[id] = old
		return err
	}
	return nil
}
func (s *Service) Close() { s.mu.Lock(); s.cancel(); s.mu.Unlock(); s.wg.Wait() }

// Abandon prevents a node that lost leadership from overwriting shared state.
// The next leader marks persisted running jobs interrupted without replay.
func (s *Service) Abandon() { s.mu.Lock(); s.abandoned = true; s.cancel(); s.mu.Unlock(); s.wg.Wait() }
func (s *Service) persistLocked() error {
	if s.abandoned {
		return fmt.Errorf("job store leadership was lost")
	}
	records := make([]Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		records = append(records, j)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	plain, err := json.Marshal(records)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	version := 1
	for _, j := range records {
		if j.ConnectionScope != "" {
			version = 5
			break
		}
	}
	for _, j := range records {
		if j.PlaybookStep != nil {
			version = max(version, 4)
			break
		}
		if j.RemoteAccount != nil {
			version = max(version, 3)
		}
		if j.Discovery != nil && j.Discovery.PlanID != "" {
			version = max(version, 2)
		}
	}
	data, err := json.Marshal(envelope{Version: version, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte(fmt.Sprintf("jms233/ssh-jobs/v%d", version)))})
	if err != nil {
		return err
	}
	if s.documents != nil {
		return s.documents.Save("ssh-jobs", data)
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), ".ssh-jobs-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), s.path)
}

// Only the internal scheduled reader can leave hot history after its full
// receipt was durably archived. General jobs keep their existing retention.
func (s *Service) PruneCollector(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.abandoned {
		return ErrBusy
	}
	j, ok := s.jobs[id]
	if !ok {
		return nil
	}
	collector := j.Plugin != nil && j.Plugin.Plugin == "banhack233" && j.Plugin.Action == "events_collect" || j.Discovery != nil && j.Discovery.PlanID != "" && j.Discovery.Sequence > 0
	if !collector || !strings.HasPrefix(j.RequestID, "operation-") || j.State == "running" || j.State == "pending_review" {
		return ErrConflict
	}
	if _, active := s.running[id]; active {
		return ErrBusy
	}
	delete(s.jobs, id)
	if e := s.persistLocked(); e != nil {
		s.jobs[id] = j
		return e
	}
	return nil
}
