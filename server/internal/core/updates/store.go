package updates

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

type Settings struct {
	Automatic     bool `json:"automatic"`
	IntervalHours int  `json:"interval_hours"`
	Revision      int  `json:"revision"`
}
type Audit struct {
	At      time.Time `json:"at"`
	ActorID string    `json:"actor_id"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Error   string    `json:"error,omitempty"`
	Before  *Settings `json:"before,omitempty"`
	After   *Settings `json:"after,omitempty"`
}
type receipt struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
	Result   Result `json:"result"`
	Error    string `json:"error,omitempty"`
}
type state struct {
	Version      int       `json:"version"`
	Settings     Settings  `json:"settings"`
	LastAttempt  time.Time `json:"last_attempt"`
	LastSuccess  time.Time `json:"last_success"`
	Error        string    `json:"error,omitempty"`
	Result       Result    `json:"result"`
	Platform     string    `json:"platform"`
	Architecture string    `json:"architecture"`
	Audit        []Audit   `json:"audit"`
	Receipts     []receipt `json:"receipts"`
}
type Status struct {
	Settings       Settings  `json:"settings"`
	CurrentVersion string    `json:"current_version"`
	CurrentKnown   bool      `json:"current_known"`
	Platform       string    `json:"platform"`
	Architecture   string    `json:"architecture"`
	Repository     string    `json:"repository"`
	LastAttempt    time.Time `json:"last_attempt"`
	LastSuccess    time.Time `json:"last_success"`
	NextCheck      time.Time `json:"next_check"`
	Error          string    `json:"error,omitempty"`
	Checking       bool      `json:"checking"`
	Result         Result    `json:"result"`
}
type Store struct {
	mu       sync.Mutex
	path     string
	docs     *storage.Documents
	feed     *Feed
	data     state
	checking bool
	saveHook func([]byte) error
}

var requestID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,80}$`)

func validSettings(v Settings) bool {
	return v.Revision > 0 && v.IntervalHours >= 1 && v.IntervalHours <= 168
}

func Open(path string, docs *storage.Documents, feed *Feed) (*Store, error) {
	if feed == nil {
		return nil, ErrInvalid
	}
	s := &Store{path: path, docs: docs, feed: feed, data: state{Version: 1, Settings: Settings{IntervalHours: 24, Revision: 1}, Result: Result{Status: "not_checked"}, Audit: []Audit{}, Receipts: []receipt{}}}
	var data []byte
	var e error
	if docs != nil {
		data, e = docs.LoadOrImport("updates", path)
	} else {
		var file *os.File
		file, e = os.Open(path)
		if e == nil {
			defer file.Close()
			data, e = io.ReadAll(io.LimitReader(file, (2<<20)+1))
		} else if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return nil, e
	}
	if len(data) == 0 {
		return s, nil
	}
	if len(data) > 2<<20 || json.Unmarshal(data, &s.data) != nil || s.data.Version != 1 || !validSettings(s.data.Settings) || len(s.data.Audit) > 200 || len(s.data.Receipts) > 100 {
		return nil, ErrInvalid
	}
	if !validResult(s.data.Result, s.data.Platform, s.data.Architecture) {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for _, r := range s.data.Receipts {
		if !requestID.MatchString(r.ID) || seen[r.ID] || r.Revision < 1 || !validResult(r.Result, s.data.Platform, s.data.Architecture) {
			return nil, ErrInvalid
		}
		seen[r.ID] = true
	}
	return s, nil
}
func validResult(r Result, platform, arch string) bool {
	if r.Status == "not_checked" || r.Status == "no_release" {
		return r.Version == "" && r.Artifact == nil && r.ReleaseURL == ""
	}
	v, ok := Version(r.Version)
	return ok && v == r.Version && (r.Status == "update_available" || r.Status == "up_to_date" || r.Status == "current_unknown") && r.ReleaseURL == "https://github.com/"+Repository+"/releases/tag/"+v && !r.PublishedAt.IsZero() && (r.Artifact == nil || ValidateArtifactURL(*r.Artifact, v, platform, arch))
}
func cloneResult(r Result) Result {
	if r.Artifact != nil {
		a := *r.Artifact
		r.Artifact = &a
	}
	return r
}
func (s *Store) nextCheck() time.Time {
	if !s.data.Settings.Automatic {
		return time.Time{}
	}
	if s.data.LastAttempt.IsZero() {
		return time.Time{}
	}
	return s.data.LastAttempt.Add(time.Duration(s.data.Settings.IntervalHours) * time.Hour)
}
func (s *Store) Snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, known := Version(s.feed.current)
	r := cloneResult(s.data.Result)
	if r.Version != "" {
		r.Status = "current_unknown"
		if v, ok := Version(s.feed.current); ok {
			r.Status = "up_to_date"
			if newer(r.Version, v) {
				r.Status = "update_available"
			}
		}
	}
	if s.data.Platform != s.feed.platform || s.data.Architecture != s.feed.arch {
		r.Artifact = nil
	}
	return Status{Settings: s.data.Settings, CurrentVersion: s.feed.current, CurrentKnown: known, Platform: s.feed.platform, Architecture: s.feed.arch, Repository: Repository, LastAttempt: s.data.LastAttempt, LastSuccess: s.data.LastSuccess, NextCheck: s.nextCheck(), Error: s.data.Error, Checking: s.checking, Result: r}
}
func (s *Store) Audit() []Audit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]Audit{}, s.data.Audit...)
	for i := range out {
		if out[i].Before != nil {
			v := *out[i].Before
			out[i].Before = &v
		}
		if out[i].After != nil {
			v := *out[i].After
			out[i].After = &v
		}
	}
	return out
}
func (s *Store) persist(next state) error {
	data, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if len(data) > 2<<20 {
		return ErrInvalid
	}
	if s.saveHook != nil {
		if e = s.saveHook(data); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("updates", data)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".jms233-write-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), s.path)
}
func withAudit(next *state, a Audit) {
	next.Audit = append(append([]Audit{}, next.Audit...), a)
	if len(next.Audit) > 200 {
		next.Audit = next.Audit[len(next.Audit)-200:]
	}
}
func (s *Store) Save(in Settings, actorID, actor string) (Settings, error) {
	if !validSettings(in) || actorID == "" || len(actorID) > 128 || len(actor) > 128 {
		return Settings{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Revision != s.data.Settings.Revision {
		return Settings{}, ErrConflict
	}
	before := s.data.Settings
	if in == before {
		return before, nil
	}
	in.Revision++
	next := s.data
	next.Settings = in
	withAudit(&next, Audit{At: time.Now().UTC(), ActorID: actorID, Actor: actor, Action: "settings", Before: &before, After: &in})
	if e := s.persist(next); e != nil {
		return Settings{}, e
	}
	s.data = next
	return in, nil
}
func (s *Store) Check(ctx context.Context, revision int, id, actorID, actor string) (Result, error) {
	return s.check(ctx, revision, id, actorID, actor, false)
}
func (s *Store) check(ctx context.Context, revision int, id, actorID, actor string, automatic bool) (Result, error) {
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	if !requestID.MatchString(id) || actorID == "" || len(actorID) > 128 || len(actor) > 128 {
		return Result{}, ErrInvalid
	}
	s.mu.Lock()
	for _, r := range s.data.Receipts {
		if r.ID == id {
			s.mu.Unlock()
			if r.Revision != revision {
				return Result{}, ErrConflict
			}
			if r.Error != "" {
				return cloneResult(r.Result), errorFromCode(r.Error)
			}
			return cloneResult(r.Result), nil
		}
	}
	if revision != s.data.Settings.Revision {
		s.mu.Unlock()
		return Result{}, ErrConflict
	}
	if automatic && (!s.data.Settings.Automatic || !s.nextCheck().IsZero() && time.Now().Before(s.nextCheck())) {
		s.mu.Unlock()
		return Result{}, ErrConflict
	}
	if s.checking {
		s.mu.Unlock()
		return Result{}, ErrBusy
	}
	if !s.data.LastAttempt.IsZero() && time.Since(s.data.LastAttempt) < time.Minute {
		s.mu.Unlock()
		return Result{}, ErrLimited
	}
	s.checking = true
	s.mu.Unlock()
	checkCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	result, checkErr := s.feed.Check(checkCtx, "")
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() { s.checking = false }()
	if e := ctx.Err(); e != nil {
		return Result{}, e
	}
	next := s.data
	next.LastAttempt = time.Now().UTC()
	next.Error = ""
	if checkErr != nil {
		next.Error = ErrorCode(checkErr)
		result = Result{Status: "not_checked"}
	} else {
		next.LastSuccess = next.LastAttempt
		next.Result = result
		next.Platform = s.feed.platform
		next.Architecture = s.feed.arch
	}
	// A platform switch cannot retain receipts with another platform's artifact.
	if next.Platform != s.data.Platform || next.Architecture != s.data.Architecture {
		next.Receipts = nil
	}
	next.Receipts = append(append([]receipt{}, next.Receipts...), receipt{ID: id, Revision: revision, Result: result, Error: next.Error})
	if len(next.Receipts) > 100 {
		next.Receipts = next.Receipts[len(next.Receipts)-100:]
	}
	withAudit(&next, Audit{At: next.LastAttempt, ActorID: actorID, Actor: actor, Action: "check", Error: next.Error})
	if e := s.persist(next); e != nil {
		return Result{}, e
	}
	s.data = next
	return cloneResult(result), checkErr
}
func errorFromCode(code string) error {
	switch code {
	case "rate_limited":
		return ErrLimited
	case "invalid_release":
		return ErrFeed
	case "network":
		return ErrNetwork
	case "integrity":
		return ErrIntegrity
	}
	return ErrNetwork
}

// Run belongs to the active node context; disabling checks prevents new calls.
func (s *Store) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		v := s.Snapshot()
		if v.Settings.Automatic && (v.NextCheck.IsZero() || !time.Now().Before(v.NextCheck)) {
			_, _ = s.check(ctx, v.Settings.Revision, "automatic-"+time.Now().UTC().Format("20060102T150405"), "system", "system", true)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
