package accountdiscovery

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/neko233-com/jumpserver233/server/internal/hostagent"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

const maxRows = 16384
const maxAudit = 2000
const maxStateBytes = 16 << 20

var assetPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,79}$`)

type Source struct {
	AssetID string `json:"asset_id"`
	Binding string `json:"binding"`
	Account string `json:"account"`
}
type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Finding struct {
	ID      string `json:"id"`
	Binding string `json:"binding"`
	hostagent.Account
	Present   bool      `json:"present"`
	Review    string    `json:"review"`
	Note      string    `json:"note"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
type Summary struct {
	Binding  string    `json:"binding"`
	Account  string    `json:"account"`
	JobID    string    `json:"job_id"`
	Revision int       `json:"revision"`
	Observed int       `json:"observed"`
	New      int       `json:"new"`
	Missing  int       `json:"missing"`
	Digest   string    `json:"digest"`
	At       time.Time `json:"at"`
}
type Audit struct {
	At        time.Time `json:"at"`
	Actor     Actor     `json:"actor"`
	Action    string    `json:"action"`
	FindingID string    `json:"finding_id,omitempty"`
	Before    string    `json:"before,omitempty"`
	After     string    `json:"after,omitempty"`
	Note      string    `json:"note,omitempty"`
	Summary   *Summary  `json:"summary,omitempty"`
}
type State struct {
	Version  int       `json:"version"`
	Source   Source    `json:"source"`
	Revision int       `json:"revision"`
	Last     *Summary  `json:"last,omitempty"`
	Findings []Finding `json:"findings"`
	Audit    []Audit   `json:"audit"`
}
type Page struct {
	Source   Source    `json:"source"`
	Revision int       `json:"revision"`
	Last     *Summary  `json:"last,omitempty"`
	Results  []Finding `json:"results"`
	Total    int       `json:"total"`
}
type Store struct {
	mu       sync.Mutex
	dir      string
	docs     *storage.Documents
	aead     cipher.AEAD
	ctx      context.Context
	closed   bool
	saveHook func([]byte) error
}
type envelope struct {
	Version int    `json:"version"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}

func Open(dir string, key []byte, docs *storage.Documents) (*Store, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	return &Store{dir: dir, docs: docs, aead: a, ctx: context.Background()}, nil
}
func (s *Store) BindOwner(ctx context.Context) { s.mu.Lock(); defer s.mu.Unlock(); s.ctx = ctx }
func (s *Store) Close()                        { s.mu.Lock(); s.closed = true; s.mu.Unlock() }
func (s *Store) active() error {
	if s.closed || s.ctx.Err() != nil {
		return ErrClosed
	}
	return nil
}
func validSource(v Source) bool {
	return assetPattern.MatchString(v.AssetID) && (Operation{Binding: v.Binding, Target: v.Binding}).Validate() == nil && validText(v.Account, 128) && v.Account != ""
}
func validText(v string, n int) bool {
	return len(v) <= n && utf8.ValidString(v) && strings.IndexFunc(v, unicode.IsControl) < 0
}
func validActor(v Actor) bool {
	return validText(v.ID, 128) && v.ID != "" && validText(v.Name, 128) && v.Name != ""
}
func findingID(binding string, a hostagent.Account) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s\x00%s\x00%d", binding, a.Username, a.UID))
	return hex.EncodeToString(h[:16])
}
func (s *Store) load(id string) (State, error) {
	if !assetPattern.MatchString(id) {
		return State{}, ErrInvalid
	}
	if e := s.active(); e != nil {
		return State{}, e
	}
	var raw []byte
	var e error
	p := filepath.Join(s.dir, id+".json")
	if s.docs != nil {
		raw, e = s.docs.LoadOrImport("account-discovery-"+id, p)
	} else {
		f, err := os.Open(p)
		e = err
		if e == nil {
			raw, e = io.ReadAll(io.LimitReader(f, maxStateBytes*2+1))
			f.Close()
		}
	}
	if errors.Is(e, os.ErrNotExist) || errors.Is(e, storage.ErrDocumentNotFound) || e == nil && len(raw) == 0 {
		return State{Version: 1, Source: Source{AssetID: id}, Findings: []Finding{}, Audit: []Audit{}}, nil
	}
	if e != nil {
		return State{}, e
	}
	if len(raw) > maxStateBytes*2 {
		return State{}, ErrInvalid
	}
	var box envelope
	if json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != s.aead.NonceSize() {
		return State{}, ErrInvalid
	}
	plain, e := s.aead.Open(nil, box.Nonce, box.Data, []byte("jms233/account-discovery/v1/"+id))
	if e != nil || len(plain) > maxStateBytes {
		return State{}, ErrInvalid
	}
	var v State
	if json.Unmarshal(plain, &v) != nil || v.Version != 1 || v.Source.AssetID != id || !validSource(v.Source) || v.Revision < 1 || len(v.Findings) > maxRows || len(v.Audit) > maxAudit {
		return State{}, ErrInvalid
	}
	seen := map[string]bool{}
	for _, f := range v.Findings {
		if !hostagent.ValidAccount(f.Account) || (Operation{Binding: f.Binding, Target: f.Binding}).Validate() != nil || f.ID != findingID(f.Binding, f.Account) || seen[f.ID] || !slices.Contains([]string{"unreviewed", "acknowledged", "ignored"}, f.Review) || !validText(f.Note, 2048) || f.FirstSeen.IsZero() || f.LastSeen.Before(f.FirstSeen) {
			return State{}, ErrInvalid
		}
		seen[f.ID] = true
	}
	return v, nil
}
func (s *Store) save(v State) error {
	if e := s.active(); e != nil {
		return e
	}
	plain, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(plain) > maxStateBytes {
		return ErrCapacity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/account-discovery/v1/"+v.Source.AssetID))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("account-discovery-"+v.Source.AssetID, raw)
	}
	if e = os.MkdirAll(s.dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(s.dir, ".accounts-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
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
	return os.Rename(f.Name(), filepath.Join(s.dir, v.Source.AssetID+".json"))
}
func (s *Store) Import(src Source, actor Actor, job, digest string, rows []hostagent.Account) (Summary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSource(src) || !validActor(actor) || len(job) != 36 || !strings.HasPrefix(job, "job-") || len(rows) == 0 || len(rows) > hostagent.MaxAccounts || hostagent.AccountDigest(rows) != digest {
		return Summary{}, ErrInvalid
	}
	if _, e := hex.DecodeString(job[4:]); e != nil {
		return Summary{}, ErrInvalid
	}
	for i, a := range rows {
		if !hostagent.ValidAccount(a) || i > 0 && rows[i-1].Username >= a.Username {
			return Summary{}, ErrInvalid
		}
	}
	v, e := s.load(src.AssetID)
	if e != nil {
		return Summary{}, e
	}
	for _, a := range v.Audit {
		if a.Summary != nil && a.Summary.JobID == job {
			if a.Summary.Digest != digest || a.Summary.Binding != src.Binding {
				return Summary{}, ErrConflict
			}
			return *a.Summary, nil
		}
	}
	if len(v.Audit) >= maxAudit {
		return Summary{}, ErrCapacity
	}
	at := time.Now().UTC()
	summary := Summary{Binding: src.Binding, Account: src.Account, JobID: job, Revision: v.Revision + 1, Observed: len(rows), Digest: digest, At: at}
	indices := map[string]int{}
	for i := range v.Findings {
		indices[v.Findings[i].ID] = i
	}
	present := map[string]bool{}
	for _, a := range rows {
		id := findingID(src.Binding, a)
		present[id] = true
		if i, ok := indices[id]; ok {
			v.Findings[i].Account = a
			v.Findings[i].Present = true
			v.Findings[i].LastSeen = at
		} else {
			if len(v.Findings) >= maxRows {
				return Summary{}, ErrCapacity
			}
			v.Findings = append(v.Findings, Finding{ID: id, Binding: src.Binding, Account: a, Present: true, Review: "unreviewed", FirstSeen: at, LastSeen: at})
			summary.New++
		}
	}
	for i := range v.Findings {
		f := &v.Findings[i]
		if !present[f.ID] {
			if f.Present {
				summary.Missing++
			}
			f.Present = false
		}
	}
	v.Source = src
	v.Revision++
	v.Last = &summary
	v.Audit = append(v.Audit, Audit{At: at, Actor: actor, Action: "collected", Summary: &summary})
	if e = s.save(v); e != nil {
		return Summary{}, e
	}
	return summary, nil
}
func (s *Store) Findings(src Source, offset, limit int) (Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSource(src) || offset < 0 || offset > maxRows || limit < 1 || limit > 100 {
		return Page{}, ErrInvalid
	}
	v, e := s.load(src.AssetID)
	if e != nil {
		return Page{}, e
	}
	rows := []Finding{}
	for _, f := range v.Findings {
		if f.Binding == src.Binding {
			rows = append(rows, f)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Present != rows[j].Present {
			return rows[i].Present
		}
		if rows[i].Username != rows[j].Username {
			return rows[i].Username < rows[j].Username
		}
		return rows[i].UID < rows[j].UID
	})
	page := Page{Source: src, Revision: v.Revision, Results: []Finding{}, Total: len(rows)}
	if v.Source.Binding == src.Binding {
		page.Last = v.Last
	}
	if offset < len(rows) {
		page.Results = rows[offset:min(len(rows), offset+limit)]
	}
	return page, nil
}

// Finding resolves only the current physical-target binding, including UID.
func (s *Store) Finding(src Source, id string) (Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSource(src) {
		return Finding{}, ErrInvalid
	}
	v, e := s.load(src.AssetID)
	if e != nil {
		return Finding{}, e
	}
	if v.Source.Binding != src.Binding {
		return Finding{}, ErrConflict
	}
	for _, f := range v.Findings {
		if f.ID == id && f.Binding == src.Binding && f.Present {
			return f, nil
		}
	}
	return Finding{}, ErrInvalid
}
func (s *Store) Review(src Source, actor Actor, id, status, note string, revision int) (Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validSource(src) || !validActor(actor) || !slices.Contains([]string{"unreviewed", "acknowledged", "ignored"}, status) || !validText(note, 2048) {
		return Finding{}, ErrInvalid
	}
	v, e := s.load(src.AssetID)
	if e != nil {
		return Finding{}, e
	}
	if v.Revision != revision || v.Source.Binding != src.Binding {
		return Finding{}, ErrConflict
	}
	if len(v.Audit) >= maxAudit {
		return Finding{}, ErrCapacity
	}
	for i, f := range v.Findings {
		if f.ID == id && f.Binding == src.Binding {
			v.Findings[i].Review = status
			v.Findings[i].Note = note
			v.Revision++
			v.Audit = append(v.Audit, Audit{At: time.Now().UTC(), Actor: actor, Action: "reviewed", FindingID: id, Before: f.Review, After: status, Note: note})
			if e = s.save(v); e != nil {
				return Finding{}, e
			}
			return v.Findings[i], nil
		}
	}
	return Finding{}, ErrInvalid
}
func (s *Store) Audit(id string, offset, limit int) ([]Audit, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if offset < 0 || offset > maxAudit || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	v, e := s.load(id)
	if e != nil {
		return nil, 0, e
	}
	rows := []Audit{}
	for i := len(v.Audit) - 1 - offset; i >= 0 && len(rows) < limit; i-- {
		rows = append(rows, v.Audit[i])
	}
	return rows, len(v.Audit), nil
}
