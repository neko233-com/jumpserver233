package databasequery

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/core/accesspolicies"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid  = errors.New("invalid database query")
	ErrNotFound = errors.New("database query not found")
	ErrDenied   = errors.New("database query access denied")
	ErrConflict = errors.New("database query request conflicts")
	ErrBusy     = errors.New("database query capacity reached")
)

type Session struct {
	Protocol  string    `json:"protocol,omitempty"`
	ID        string    `json:"-"`
	UserID    string    `json:"-"`
	Operator  string    `json:"-"`
	AssetID   string    `json:"asset_id"`
	AssetName string    `json:"asset_name"`
	Account   string    `json:"account"`
	Database  string    `json:"database"`
	ReadOnly  bool      `json:"read_only"`
	Binding   string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
}
type SessionResponse struct {
	Session
	Token string `json:"session_token"`
}
type Input struct {
	sqlclient.Input
	RequestID string `json:"request_id"`
}
type Job struct {
	Protocol        string                `json:"protocol,omitempty"`
	ExecutionSQL    string                `json:"-"`
	ID              string                `json:"id"`
	AssetID         string                `json:"asset_id"`
	AssetName       string                `json:"asset_name"`
	Account         string                `json:"account"`
	Database        string                `json:"database"`
	OperatorID      string                `json:"operator_id"`
	Operator        string                `json:"operator"`
	SQL             string                `json:"sql"`
	ParameterCount  int                   `json:"parameter_count"`
	RequestID       string                `json:"request_id"`
	Fingerprint     string                `json:"fingerprint"`
	State           string                `json:"state"`
	ReadOnly        bool                  `json:"read_only"`
	RuleName        string                `json:"rule_name,omitempty"`
	ReviewedBy      string                `json:"reviewed_by,omitempty"`
	CreatedAt       time.Time             `json:"created_at"`
	StartedAt       *time.Time            `json:"started_at,omitempty"`
	FinishedAt      *time.Time            `json:"finished_at,omitempty"`
	ReviewExpiresAt *time.Time            `json:"review_expires_at,omitempty"`
	Origin          accesspolicies.Origin `json:"origin"`
	Binding         string                `json:"-"`
	SessionHash     string                `json:"-"`
	ResultAvailable bool                  `json:"result_available"`
	Summary         sqlclient.Result      `json:"summary"`
}
type storedJob struct {
	Job
	BindingValue string `json:"binding"`
	SessionValue string `json:"session_hash"`
	Payload      *Input `json:"payload,omitempty"`
}
type Response struct {
	Job
	Result *sqlclient.Result `json:"result,omitempty"`
}
type Executor func(context.Context, string, sqlclient.Input, func() error) (sqlclient.Result, error)
type Guard func(Job) error
type Service struct {
	mu           sync.Mutex
	path         string
	documents    *storage.Documents
	aead         cipher.AEAD
	hashKey      []byte
	jobs         map[string]storedJob
	results      map[string]sqlclient.Result
	sessions     map[string]Session
	running      map[string]context.CancelFunc
	reviewTimers map[string]*time.Timer
	sem          chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	exec         Executor
	guard        Guard
	closed       bool
	abandoned    bool
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func Open(path string, key []byte, documents *storage.Documents, execute Executor) (*Service, error) {
	if len(key) != 32 || execute == nil {
		return nil, ErrInvalid
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{path: path, documents: documents, aead: aead, hashKey: append([]byte(nil), key...), jobs: map[string]storedJob{}, results: map[string]sqlclient.Result{}, sessions: map[string]Session{}, running: map[string]context.CancelFunc{}, reviewTimers: map[string]*time.Timer{}, sem: make(chan struct{}, 4), ctx: ctx, cancel: cancel, exec: execute}
	var raw []byte
	if documents != nil {
		raw, e = documents.LoadOrImport("database-queries", path)
	} else {
		raw, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		cancel()
		return nil, e
	}
	changed := false
	if len(raw) > 0 {
		var enc envelope
		if json.Unmarshal(raw, &enc) != nil || enc.Version != 1 || len(enc.Nonce) != aead.NonceSize() {
			cancel()
			return nil, ErrInvalid
		}
		plain, e := aead.Open(nil, enc.Nonce, enc.Ciphertext, []byte("jms233/database-queries/v1"))
		if e != nil {
			cancel()
			return nil, ErrInvalid
		}
		var records []storedJob
		if json.Unmarshal(plain, &records) != nil || len(records) > 1000 {
			cancel()
			return nil, ErrInvalid
		}
		for _, r := range records {
			if r.ID == "" || r.AssetID == "" || r.OperatorID == "" || r.RequestID == "" || r.Fingerprint == "" || r.CreatedAt.IsZero() {
				cancel()
				return nil, ErrInvalid
			}
			if _, ok := s.jobs[r.ID]; ok {
				cancel()
				return nil, ErrInvalid
			}
			r.Binding = r.BindingValue
			r.SessionHash = r.SessionValue
			r.ResultAvailable = false
			if len(r.Summary.MissingCells) > 0 || len(r.Summary.Columns) > 0 || len(r.Summary.Rows) > 0 || len(r.Summary.ResultSets) > 0 {
				changed = true
			}
			r.Summary.MissingCells = nil
			r.Summary.Columns = nil
			r.Summary.Rows = nil
			r.Summary.ResultSets = nil
			if !terminal(r.State) {
				now := time.Now().UTC()
				r.State = "interrupted"
				r.FinishedAt = &now
				r.Summary.ErrorCode = "interrupted"
				r.Summary.Transaction = "unknown"
				r.Payload = nil
				changed = true
			}
			s.jobs[r.ID] = r
		}
	}
	if changed {
		if e = s.persistLocked(); e != nil {
			cancel()
			return nil, e
		}
	}
	return s, nil
}
func (s *Service) BindOwner(ctx context.Context) { context.AfterFunc(ctx, s.cancel) }
func (s *Service) SetGuard(g Guard)              { s.mu.Lock(); defer s.mu.Unlock(); s.guard = g }
func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (s *Service) CreateSession(session Session) (SessionResponse, error) {
	if session.UserID == "" || session.Operator == "" || session.AssetID == "" || session.Account == "" || session.Binding == "" {
		return SessionResponse{}, ErrInvalid
	}
	var raw [32]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return SessionResponse{}, e
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	session.ID = digest(token)
	session.ExpiresAt = time.Now().UTC().Add(30 * time.Minute)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return SessionResponse{}, ErrBusy
	}
	count := 0
	for id, old := range s.sessions {
		if !time.Now().Before(old.ExpiresAt) {
			delete(s.sessions, id)
		} else if old.UserID == session.UserID {
			count++
		}
	}
	if count >= 32 || len(s.sessions) >= 5000 {
		return SessionResponse{}, ErrBusy
	}
	s.sessions[session.ID] = session
	return SessionResponse{Session: session, Token: token}, nil
}
func (s *Service) Session(token, userID, assetID string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return Session{}, ErrNotFound
	}
	session, ok := s.sessions[digest(token)]
	if !ok || session.UserID != userID || session.AssetID != assetID || !time.Now().Before(session.ExpiresAt) {
		return Session{}, ErrNotFound
	}
	return session, nil
}
func (s *Service) DeleteSession(token, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrBusy
	}
	id := digest(token)
	session, ok := s.sessions[id]
	if !ok || session.UserID != user {
		return ErrNotFound
	}
	delete(s.sessions, id)
	changed := false
	for jobID, r := range s.jobs {
		if r.SessionHash != id || terminal(r.State) {
			continue
		}
		if cancel := s.running[jobID]; cancel != nil {
			cancel()
			continue
		}
		now := time.Now().UTC()
		r.State = "cancelled"
		r.FinishedAt = &now
		r.Payload = nil
		s.jobs[jobID] = r
		if timer := s.reviewTimers[jobID]; timer != nil {
			timer.Stop()
			delete(s.reviewTimers, jobID)
		}
		changed = true
	}
	if changed {
		return s.persistLocked()
	}
	return nil
}
func validRequestID(id string) bool {
	if len(id) < 8 || len(id) > 80 {
		return false
	}
	for _, r := range id {
		if r != '-' && r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}
func terminal(state string) bool {
	switch state {
	case "completed", "failed", "denied", "cancelled", "expired", "interrupted":
		return true
	}
	return false
}
func (s *Service) hash(user, asset string, in Input) string {
	raw, _ := json.Marshal(in)
	mac := hmac.New(sha256.New, s.hashKey)
	mac.Write([]byte("jms233/database-query/v1\x00" + user + "\x00" + asset + "\x00"))
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}
func (s *Service) Submit(session Session, in Input, origin accesspolicies.Origin, review bool, rule string) (Job, error) {
	in.Dialect = session.Protocol
	if !validRequestID(in.RequestID) || sqlclient.ValidateInput(in.Input) != nil {
		return Job{}, ErrInvalid
	}
	redacted, e := sqlclient.AuditSQL(in.SQL, in.Dialect)
	if e != nil {
		return Job{}, ErrInvalid
	}
	in.ReadOnly = in.ReadOnly || session.ReadOnly
	fingerprint := s.hash(session.UserID, session.AssetID, in)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return Job{}, ErrBusy
	}
	live, ok := s.sessions[session.ID]
	if !ok || live != session || !time.Now().Before(live.ExpiresAt) {
		return Job{}, ErrDenied
	}
	for _, record := range s.jobs {
		if record.OperatorID == session.UserID && record.RequestID == in.RequestID {
			if record.AssetID != session.AssetID || record.Fingerprint != fingerprint {
				return Job{}, ErrConflict
			}
			return cloneJob(record.Job), nil
		}
	}
	active := 0
	for _, r := range s.jobs {
		if !terminal(r.State) {
			active++
		}
	}
	if active >= 20 {
		return Job{}, ErrBusy
	}
	if len(s.jobs) >= 1000 {
		oldest := ""
		for id, r := range s.jobs {
			if terminal(r.State) && (oldest == "" || r.CreatedAt.Before(s.jobs[oldest].CreatedAt)) {
				oldest = id
			}
		}
		if oldest == "" {
			return Job{}, ErrBusy
		}
		delete(s.jobs, oldest)
		delete(s.results, oldest)
	}
	var token [16]byte
	if _, e = rand.Read(token[:]); e != nil {
		return Job{}, e
	}
	now := time.Now().UTC()
	j := Job{Protocol: session.Protocol, ID: "dbq-" + hex.EncodeToString(token[:]), AssetID: session.AssetID, AssetName: session.AssetName, Account: session.Account, Database: session.Database, OperatorID: session.UserID, Operator: session.Operator, SQL: redacted, ParameterCount: len(in.Parameters), RequestID: in.RequestID, Fingerprint: fingerprint, ReadOnly: in.ReadOnly, State: "queued", RuleName: rule, CreatedAt: now, Origin: origin, Binding: session.Binding, SessionHash: session.ID, Summary: sqlclient.Result{Columns: []sqlclient.Column{}, Rows: nil, Transaction: "not_started", ReadOnly: in.ReadOnly}}
	if review {
		j.State = "awaiting_review"
		expires := now.Add(5 * time.Minute)
		j.ReviewExpiresAt = &expires
	}
	copyInput := in
	copyInput.Parameters = append([]json.RawMessage(nil), in.Parameters...)
	for i, p := range in.Parameters {
		copyInput.Parameters[i] = append(json.RawMessage(nil), p...)
	}
	s.jobs[j.ID] = storedJob{Job: j, BindingValue: j.Binding, SessionValue: j.SessionHash, Payload: &copyInput}
	if e = s.persistLocked(); e != nil {
		delete(s.jobs, j.ID)
		return Job{}, e
	}
	if review {
		s.reviewTimers[j.ID] = time.AfterFunc(5*time.Minute, func() { s.expire(j.ID) })
	} else {
		s.launchLocked(j.ID)
	}
	return cloneJob(j), nil
}
func (s *Service) check(j Job) error {
	s.mu.Lock()
	session, ok := s.sessions[j.SessionHash]
	guard := s.guard
	closed := s.closed || s.ctx.Err() != nil
	s.mu.Unlock()
	if closed || !ok || session.UserID != j.OperatorID || session.AssetID != j.AssetID || session.Binding != j.Binding || !time.Now().Before(session.ExpiresAt) {
		return ErrDenied
	}
	if guard != nil {
		return guard(j)
	}
	return nil
}
func (s *Service) launchLocked(id string) {
	ctx, cancel := context.WithCancel(s.ctx)
	s.running[id] = cancel
	s.wg.Add(1)
	go s.run(ctx, id)
}
func (s *Service) run(ctx context.Context, id string) {
	defer s.wg.Done()
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		s.complete(id, sqlclient.Result{ErrorCode: "cancelled", Transaction: "not_started"}, ctx.Err())
		return
	}
	s.mu.Lock()
	r, ok := s.jobs[id]
	if s.closed || s.ctx.Err() != nil || !ok || r.Payload == nil || r.State != "queued" {
		delete(s.running, id)
		s.mu.Unlock()
		return
	}
	now := time.Now().UTC()
	r.State = "running"
	r.StartedAt = &now
	s.jobs[id] = r
	e := s.persistLocked()
	if e != nil {
		s.mu.Unlock()
		s.complete(id, sqlclient.Result{ErrorCode: "audit_unavailable", Transaction: "not_started"}, e)
		return
	}
	j, in := r.Job, *r.Payload
	s.mu.Unlock()
	j.ExecutionSQL = in.SQL
	if e = s.check(j); e != nil {
		s.complete(id, sqlclient.Result{ErrorCode: "access_revoked", Transaction: "not_started"}, e)
		return
	}
	work, stop := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-work.Done():
				return
			case <-ticker.C:
				if s.check(j) != nil {
					stop()
					return
				}
			}
		}
	}()
	result, e := s.exec(work, j.AssetID, in.Input, func() error { return s.check(j) })
	stop()
	<-watchDone
	s.complete(id, result, e)
}
func (s *Service) complete(id string, result sqlclient.Result, cause error) {
	result = sqlclient.CloneResult(result)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.jobs[id]
	if !ok {
		return
	}
	if cancel := s.running[id]; cancel != nil {
		cancel()
		delete(s.running, id)
	}
	if s.abandoned || (!s.closed && s.ctx.Err() != nil) {
		return
	}
	now := time.Now().UTC()
	r.FinishedAt = &now
	r.Payload = nil
	r.State = "completed"
	if cause != nil {
		r.State = "failed"
		if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
			r.State = "cancelled"
		}
		if result.ErrorCode == "" {
			result.ErrorCode = "query_failed"
		}
	}
	r.Summary = result
	r.Summary.MissingCells = nil
	r.Summary.Columns = nil
	r.Summary.Rows = nil
	r.Summary.ResultSets = nil
	r.ResultAvailable = true
	s.jobs[id] = r
	s.results[id] = result
	s.pruneResultsLocked()
	if e := s.persistLocked(); e != nil {
		r.State = "interrupted"
		r.Summary.Transaction = "unknown"
		r.Summary.ErrorCode = "audit_unavailable"
		r.ResultAvailable = false
		s.jobs[id] = r
		delete(s.results, id)
	}
}
func (s *Service) Resolve(id, reviewer string, approve bool) error {
	if !ValidReviewActor(reviewer) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrBusy
	}
	r, ok := s.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if r.State != "awaiting_review" || r.ReviewExpiresAt == nil || !time.Now().Before(*r.ReviewExpiresAt) {
		return ErrConflict
	}
	old := r
	r.ReviewedBy = reviewer
	r.State = "queued"
	if !approve {
		now := time.Now().UTC()
		r.State = "denied"
		r.FinishedAt = &now
		r.Payload = nil
	}
	s.jobs[id] = r
	if e := s.persistLocked(); e != nil {
		s.jobs[id] = old
		return e
	}
	if timer := s.reviewTimers[id]; timer != nil {
		timer.Stop()
		delete(s.reviewTimers, id)
	}
	if approve {
		s.launchLocked(id)
	}
	return nil
}
func (s *Service) expire(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return
	}
	r, ok := s.jobs[id]
	if !ok || r.State != "awaiting_review" {
		return
	}
	old := r
	now := time.Now().UTC()
	r.State = "expired"
	r.FinishedAt = &now
	r.Payload = nil
	s.jobs[id] = r
	if s.persistLocked() != nil {
		s.jobs[id] = old
		s.reviewTimers[id] = time.AfterFunc(time.Second, func() { s.expire(id) })
		return
	}
	delete(s.reviewTimers, id)
}
func (s *Service) Cancel(id, user string, all bool) error {
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrBusy
	}
	r, ok := s.jobs[id]
	if !ok || (!all && r.OperatorID != user) {
		s.mu.Unlock()
		return ErrNotFound
	}
	if terminal(r.State) {
		s.mu.Unlock()
		return ErrConflict
	}
	if cancel := s.running[id]; cancel != nil {
		cancel()
		s.mu.Unlock()
		return nil
	}
	old := r
	now := time.Now().UTC()
	r.State = "cancelled"
	r.FinishedAt = &now
	r.Payload = nil
	s.jobs[id] = r
	e := s.persistLocked()
	if e != nil {
		s.jobs[id] = old
		s.mu.Unlock()
		return e
	}
	if timer := s.reviewTimers[id]; timer != nil {
		timer.Stop()
		delete(s.reviewTimers, id)
	}
	s.mu.Unlock()
	return e
}
func cloneJob(j Job) Job {
	j.ExecutionSQL = ""
	j.Summary = sqlclient.CloneResult(j.Summary)
	j.Summary.MissingCells = nil
	j.Summary.Columns = nil
	j.Summary.Rows = nil
	j.Summary.ResultSets = nil
	return j
}
func (s *Service) List(user, asset string, all bool) []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneResultsLocked()
	out := []Job{}
	for _, r := range s.jobs {
		if (all || r.OperatorID == user) && (asset == "" || r.AssetID == asset) {
			j := cloneJob(r.Job)
			j.ResultAvailable = j.OperatorID == user && j.ResultAvailable
			out = append(out, j)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func (s *Service) Get(id, user string, all bool) (Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneResultsLocked()
	r, ok := s.jobs[id]
	if !ok || (!all && r.OperatorID != user) {
		return Response{}, ErrNotFound
	}
	j := cloneJob(r.Job)
	response := Response{Job: j}
	if r.OperatorID == user {
		if result, ok := s.results[id]; ok {
			copy := sqlclient.CloneResult(result)
			response.Result = &copy
		}
	} else {
		response.ResultAvailable = false
	}
	return response, nil
}
func (s *Service) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	for _, t := range s.reviewTimers {
		t.Stop()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, r := range s.jobs {
		if !terminal(r.State) {
			now := time.Now().UTC()
			r.State = "cancelled"
			r.FinishedAt = &now
			r.Payload = nil
			s.jobs[id] = r
		}
	}
	_ = s.persistLocked()
}
func (s *Service) Abandon() {
	s.mu.Lock()
	s.abandoned = true
	s.closed = true
	s.cancel()
	for _, t := range s.reviewTimers {
		t.Stop()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func (s *Service) persistLocked() error {
	records := make([]storedJob, 0, len(s.jobs))
	for _, r := range s.jobs {
		r.ResultAvailable = false
		r.Summary.MissingCells = nil
		r.Summary.Columns = nil
		r.Summary.Rows = nil
		r.Summary.ResultSets = nil
		records = append(records, r)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	plain, e := json.Marshal(records)
	if e != nil {
		return e
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/database-queries/v1"))})
	if e != nil {
		return e
	}
	if s.documents != nil {
		return s.documents.Save("database-queries", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".database-queries-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	e = f.Chmod(0600)
	if e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(f.Name(), s.path)
	}
	return e
}

func Binding(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func ValidReviewActor(actor string) bool {
	return actor != "" && len(actor) <= 128 && !strings.ContainsAny(actor, "\r\n\x00")
}
func (s *Service) pruneResultsLocked() {
	now := time.Now()
	for id := range s.results {
		r := s.jobs[id]
		if r.FinishedAt == nil || now.Sub(*r.FinishedAt) > 15*time.Minute {
			delete(s.results, id)
			r.ResultAvailable = false
			s.jobs[id] = r
		}
	}
	for len(s.results) > 16 {
		oldest := ""
		for id := range s.results {
			if oldest == "" || s.jobs[id].CreatedAt.Before(s.jobs[oldest].CreatedAt) {
				oldest = id
			}
		}
		delete(s.results, oldest)
		r := s.jobs[oldest]
		r.ResultAvailable = false
		s.jobs[oldest] = r
	}
}
