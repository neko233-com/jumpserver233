package assetdiscovery

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

	"github.com/neko233-com/jumpserver233/server/internal/core/assets"
	"github.com/neko233-com/jumpserver233/server/internal/core/operations"
	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

const MaxSources = 32
const MaxPolicies = 128
const MaxFindings = 16384
const MaxRuns = 200
const MaxImportRows = 500
const maxStateBytes = 32 << 20
const maxEnvelopeBytes = 48 << 20

var idPattern = regexp.MustCompile(`^(source|policy)-[a-f0-9]{32}$`)
var requestPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{7,127}$`)
var findingPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var resourcePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type sourceRecord struct {
	ID             string      `json:"id"`
	Input          SourceInput `json:"input"`
	KeyFingerprint string      `json:"key_fingerprint,omitempty"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	Deleted        bool        `json:"deleted,omitempty"`
}
type runRecord struct {
	Run
	RequestDigest string `json:"request_digest"`
}
type previewRecord struct {
	Actor       Actor        `json:"actor"`
	Input       PreviewInput `json:"input"`
	ExpiresAt   time.Time    `json:"expires_at"`
	RequestHash string       `json:"request_hash,omitempty"`
	Used        bool         `json:"used"`
	Planned     []Finding    `json:"planned"`
}
type receiptRecord struct {
	Actor     Actor         `json:"actor"`
	SourceID  string        `json:"source_id"`
	TokenHash string        `json:"token_hash"`
	Input     PreviewInput  `json:"input"`
	Planned   []Finding     `json:"planned"`
	At        time.Time     `json:"at"`
	Result    *ImportResult `json:"result,omitempty"`
}
type state struct {
	Version  int                      `json:"version"`
	Sources  map[string]sourceRecord  `json:"sources"`
	Policies map[string]Policy        `json:"policies"`
	Findings map[string]Finding       `json:"findings"`
	Runs     map[string]runRecord     `json:"runs"`
	Previews map[string]previewRecord `json:"previews"`
	Receipts map[string]receiptRecord `json:"receipts"`
	Audit    []Audit                  `json:"audit"`
}
type envelope struct {
	Version int    `json:"version"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"`
}
type Store struct {
	mu        sync.Mutex
	path      string
	docs      *storage.Documents
	aead      cipher.AEAD
	macKey    []byte
	data      state
	uncertain bool
	saveHook  func([]byte) error
}

func newState() state {
	return state{Version: 1, Sources: map[string]sourceRecord{}, Policies: map[string]Policy{}, Findings: map[string]Finding{}, Runs: map[string]runRecord{}, Previews: map[string]previewRecord{}, Receipts: map[string]receiptRecord{}, Audit: []Audit{}}
}
func Open(path string, key []byte, docs *storage.Documents) (*Store, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("jumpserver233:asset-discovery:ids:v1"))
	s := &Store{path: path, docs: docs, aead: aead, macKey: mac.Sum(nil), data: newState()}
	if e = s.loadLocked(); e != nil {
		return nil, e
	}
	return s, nil
}
func decodeStrict(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func (s *Store) loadLocked() error {
	var data []byte
	var e error
	if s.docs != nil {
		data, e = s.docs.LoadOrImport("asset-discovery", s.path)
	} else {
		var f *os.File
		f, e = os.Open(s.path)
		if errors.Is(e, os.ErrNotExist) {
			s.data = newState()
			return nil
		}
		if e == nil {
			defer f.Close()
			data, e = io.ReadAll(io.LimitReader(f, maxEnvelopeBytes+1))
		}
	}
	if e != nil {
		return e
	}
	if len(data) == 0 {
		s.data = newState()
		return nil
	}
	if len(data) > maxEnvelopeBytes {
		return ErrCapacity
	}
	var sealed envelope
	if decodeStrict(data, &sealed) != nil || sealed.Version != 1 || len(sealed.Nonce) != s.aead.NonceSize() {
		return ErrInvalid
	}
	plain, e := s.aead.Open(nil, sealed.Nonce, sealed.Data, []byte("jumpserver233:asset-discovery:v1"))
	if e != nil {
		return ErrInvalid
	}
	if len(plain) > maxStateBytes {
		return ErrCapacity
	}
	var next state
	if decodeStrict(plain, &next) != nil || validateState(next) != nil {
		return ErrInvalid
	}
	s.data = next
	s.uncertain = false
	return nil
}
func validateState(v state) error {
	if v.Version != 1 || v.Sources == nil || v.Policies == nil || v.Findings == nil || v.Runs == nil || v.Previews == nil || v.Receipts == nil || len(v.Sources) > 128 || len(v.Policies) > 512 || activeSources(v) > MaxSources || activePolicies(v) > MaxPolicies || len(v.Findings) > MaxFindings || len(v.Runs) > MaxRuns || len(v.Previews) > 128 || len(v.Receipts) > 200 || len(v.Audit) > 1000 {
		return ErrInvalid
	}
	for id, r := range v.Sources {
		if id != r.ID || !validID(id, "source") || r.Input.Revision < 1 || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() {
			return ErrInvalid
		}
		if _, e := Addresses(r.Input.Targets, r.Input.Exclude); e != nil {
			return e
		}
		if _, e := normalizePorts(r.Input.Ports); e != nil {
			return e
		}
		if r.Input.TimeoutMS < 100 || r.Input.TimeoutMS > 5000 || r.Input.Concurrency < 1 || r.Input.Concurrency > 32 {
			return ErrInvalid
		}
		if _, _, e := assets.NormalizeDiscoveryTemplate(r.Input.Template, true); e != nil {
			return e
		}
	}
	for id, p := range v.Policies {
		if p.ID != id || !validID(id, "policy") || !validID(p.SourceID, "source") || p.Revision < 1 || !validActor(p.Owner) {
			return ErrInvalid
		}
	}
	for id, f := range v.Findings {
		if id != f.ID || !findingPattern.MatchString(id) || !validID(f.SourceID, "source") || f.Revision < 1 || f.Port < 1 || f.Port > 65535 {
			return ErrInvalid
		}
	}
	for id, r := range v.Runs {
		if id != r.ID || !strings.HasPrefix(id, "run-") || len(id) != 36 || !validActor(r.Actor) || r.Revision < 1 || r.Total < 0 || r.Total > MaxEndpoints || r.Completed < 0 || r.Completed > r.Total {
			return ErrInvalid
		}
	}
	return nil
}
func validID(id, kind string) bool {
	return strings.HasPrefix(id, kind+"-") && idPattern.MatchString(id)
}
func validText(v string, limit int) bool {
	return utf8.ValidString(v) && len(v) <= limit && strings.TrimSpace(v) == v && strings.IndexFunc(v, func(r rune) bool {
		return unicode.IsControl(r) || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069
	}) < 0
}
func validActor(a Actor) bool {
	return a.ID != "" && a.Name != "" && validText(a.ID, 128) && validText(a.Name, 128)
}
func (s *Store) stableID(kind, actor, request string) string {
	h := hmac.New(sha256.New, s.macKey)
	_, _ = h.Write([]byte(kind + "\x00" + actor + "\x00" + request))
	return kind + "-" + hex.EncodeToString(h.Sum(nil)[:16])
}
func (s *Store) hash(value string) string {
	h := hmac.New(sha256.New, s.macKey)
	_, _ = h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}
func copyJSON[T any](v T) T {
	data, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(data, &out)
	return out
}
func (s *Store) refreshLocked() error {
	if s.uncertain {
		previous := s.data
		e := s.loadLocked()
		if e != nil {
			s.data = previous
			s.uncertain = true
			return e
		}
		if len(previous.Sources) > 0 && len(s.data.Sources) == 0 {
			s.data = previous
			s.uncertain = true
			return ErrConflict
		}
		return nil
	}
	return nil
}
func (s *Store) saveLocked(next state) error {
	if e := boundHistory(&next); e != nil {
		return e
	}
	plain, e := json.Marshal(next)
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
	data, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jumpserver233:asset-discovery:v1"))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e = s.saveHook(data); e != nil {
			s.uncertain = true
			return e
		}
	}
	if s.docs != nil {
		e = s.docs.Save("asset-discovery", data)
	} else {
		e = atomicWrite(s.path, data)
	}
	if e != nil {
		s.uncertain = true
		return e
	}
	s.data = next
	return nil
}
func atomicWrite(path string, data []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".asset-discovery-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeError := f.Close()
	if e != nil {
		return e
	}
	if closeError != nil {
		return closeError
	}
	return os.Rename(f.Name(), path)
}
func audit(next *state, a Audit) {
	next.Audit = append(next.Audit, a)
	if len(next.Audit) > 1000 {
		next.Audit = next.Audit[len(next.Audit)-1000:]
	}
}
func publicSource(r sourceRecord) Source {
	in := r.Input
	raw, _ := json.Marshal(in.Template)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, key := range []string{"password", "private_key", "private_key_passphrase", "name", "host", "port", "group", "node_id", "remark", "gateway_id", "host_key_fingerprint"} {
		delete(fields, key)
	}
	template, _ := json.Marshal(fields)
	addresses, _ := Addresses(in.Targets, in.Exclude)
	return Source{Provider: in.Provider, ID: r.ID, Revision: in.Revision, Name: in.Name, Description: in.Description, Enabled: in.Enabled, Targets: slices.Clone(in.Targets), Exclude: slices.Clone(in.Exclude), Ports: slices.Clone(in.Ports), AddressCount: len(addresses), TimeoutMS: in.TimeoutMS, Concurrency: in.Concurrency, GatewayID: in.GatewayID, Template: template, CredentialConfigured: in.Template.Password != "" || in.Template.PrivateKey != "", KeyFingerprint: r.KeyFingerprint, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
}
func normalizeSource(in SourceInput, old *sourceRecord) (SourceInput, string, error) {
	in.RequestID = ""
	if in.Provider == "" {
		in.Provider = "lan"
	}
	if in.Provider != "lan" {
		return in, "", ErrInvalid
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	if in.Name == "" || !validText(in.Name, 120) || !validText(in.Description, 500) || in.Revision < 0 || in.Revision > 1000000000 {
		return in, "", ErrInvalid
	}
	if in.Template.Password != "" || in.Template.PrivateKey != "" || in.Template.PrivateKeyPassphrase != "" {
		return in, "", ErrInvalid
	}
	if in.TimeoutMS == 0 {
		in.TimeoutMS = 1000
	}
	if in.Concurrency == 0 {
		in.Concurrency = 16
	}
	if in.TimeoutMS < 100 || in.TimeoutMS > 5000 || in.Concurrency < 1 || in.Concurrency > 32 {
		return in, "", ErrInvalid
	}
	if in.GatewayID != "" && !resourcePattern.MatchString(in.GatewayID) {
		return in, "", ErrInvalid
	}
	for _, list := range [][]string{in.Targets, in.Exclude} {
		for i := range list {
			list[i] = strings.TrimSpace(list[i])
		}
		slices.Sort(list)
	}
	if in.Exclude == nil {
		in.Exclude = []string{}
	}
	addresses, e := Addresses(in.Targets, in.Exclude)
	if e != nil {
		return in, "", e
	}
	in.Ports, e = normalizePorts(in.Ports)
	if e != nil {
		return in, "", e
	}
	if len(addresses)*len(in.Ports) > MaxEndpoints {
		return in, "", ErrCapacity
	}
	if in.Credential == nil && old != nil {
		in.Template.Password = old.Input.Template.Password
		in.Template.PrivateKey = old.Input.Template.PrivateKey
		if in.Template.CredentialType == "" {
			in.Template.CredentialType = old.Input.Template.CredentialType
		}
	} else if in.Credential != nil {
		in.Template.Password = in.Credential.Password
		in.Template.PrivateKey = in.Credential.PrivateKey
		in.Template.PrivateKeyPassphrase = in.Credential.PrivateKeyPassphrase
	}
	in.Credential = nil
	template, pin, e := assets.NormalizeDiscoveryTemplate(in.Template, true)
	if e != nil {
		return in, "", ErrInvalid
	}
	in.Template = template
	return in, pin, nil
}
func (s *Store) SaveSource(id string, in SourceInput, actor Actor, now time.Time) (Source, error) {
	now = now.UTC()
	if !validActor(actor) {
		return Source{}, ErrInvalid
	}
	create := id == ""
	if create {
		if !requestPattern.MatchString(in.RequestID) {
			return Source{}, ErrInvalid
		}
		id = s.stableID("source", actor.ID, in.RequestID)
	} else if !validID(id, "source") {
		return Source{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return Source{}, e
	}
	old, exists := s.data.Sources[id]
	if exists && old.Deleted {
		return Source{}, ErrNotFound
	}
	if !create && !exists {
		return Source{}, ErrNotFound
	}
	var previous *sourceRecord
	if exists {
		previous = &old
	}
	normalized, pin, e := normalizeSource(copyJSON(in), previous)
	if e != nil {
		return Source{}, e
	}
	if exists {
		candidate := normalized
		candidate.Revision = old.Input.Revision
		a, _ := json.Marshal(candidate)
		b, _ := json.Marshal(old.Input)
		if in.Revision <= old.Input.Revision && bytes.Equal(a, b) {
			return publicSource(old), nil
		}
		if in.Revision != old.Input.Revision {
			return Source{}, ErrConflict
		}
	} else if in.Revision != 0 {
		return Source{}, ErrConflict
	}
	if !exists && activeSources(s.data) >= MaxSources {
		return Source{}, ErrCapacity
	}
	normalized.Revision = old.Input.Revision + 1
	record := sourceRecord{ID: id, Input: normalized, KeyFingerprint: pin, CreatedAt: now, UpdatedAt: now}
	if exists {
		record.CreatedAt = old.CreatedAt
	}
	next := copyJSON(s.data)
	if !exists && len(next.Sources) >= 128 {
		oldest := ""
		for key, entry := range next.Sources {
			if entry.Deleted && (oldest == "" || entry.UpdatedAt.Before(next.Sources[oldest].UpdatedAt)) {
				oldest = key
			}
		}
		if oldest == "" {
			return Source{}, ErrCapacity
		}
		delete(next.Sources, oldest)
	}
	next.Sources[id] = record
	if exists {
		for key, p := range next.Policies {
			if p.SourceID == id && !p.Deleted {
				p.Enabled = false
				p.NextRunAt = time.Time{}
				p.LastScheduleError = "scan_configuration_changed"
				p.Revision++
				next.Policies[key] = p
				audit(&next, Audit{At: now, Actor: actor, Action: "policy_source_changed", SourceID: id, PolicyID: key, Revision: p.Revision})
			}
		}
	}
	audit(&next, Audit{At: now, Actor: actor, Action: "source_saved", SourceID: id, Revision: normalized.Revision, CredentialChanged: in.Credential != nil, Before: snapshot(publicSource(old), exists), After: snapshot(publicSource(record), true)})
	if e = s.saveLocked(next); e != nil {
		return Source{}, e
	}
	return publicSource(record), nil
}
func (s *Store) Sources() ([]Source, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.refreshLocked(); e != nil {
		return nil, e
	}
	out := []Source{}
	for _, r := range s.data.Sources {
		if !r.Deleted {
			out = append(out, publicSource(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func nextOccurrence(schedule *operations.Schedule, after time.Time) (time.Time, error) {
	if schedule == nil {
		return time.Time{}, nil
	}
	if !slices.Contains([]string{"once", "interval", "cron"}, schedule.Kind) {
		return time.Time{}, ErrInvalid
	}
	p, e := operations.PreviewSchedule(operations.PreviewInput{Schedule: *schedule, After: after, Limit: 1}, after)
	if e != nil {
		return time.Time{}, ErrInvalid
	}
	if len(p.Occurrences) == 0 {
		return time.Time{}, nil
	}
	return p.Occurrences[0].At, nil
}
func activeSources(v state) int {
	n := 0
	for _, source := range v.Sources {
		if !source.Deleted {
			n++
		}
	}
	return n
}
func activePolicies(v state) int {
	n := 0
	for _, policy := range v.Policies {
		if !policy.Deleted {
			n++
		}
	}
	return n
}
