// Package labels owns organization-scoped metadata and revisioned resource bindings.
package labels

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var (
	ErrInvalid  = errors.New("invalid label or binding")
	ErrNotFound = errors.New("label or binding not found")
	ErrConflict = errors.New("label revision, name or request conflicts")
	ErrInUse    = errors.New("label is attached to a live resource")
	ErrCapacity = errors.New("label capacity reached")
	ErrClosed   = errors.New("label store closed")
)

const maxBytes = 32 << 20

var idPattern = regexp.MustCompile(`^label-[a-f0-9]{32}$`)
var resourceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
var requestID = regexp.MustCompile(`^[A-Za-z0-9_-]{8,100}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var colorPattern = regexp.MustCompile(`^#[a-f0-9]{6}$`)

type Input struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Color       string `json:"color"`
	Description string `json:"description"`
	Revision    int    `json:"revision"`
	RequestID   string `json:"request_id,omitempty"`
}
type Label struct {
	Input
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
}
type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}
type Binding struct {
	Resource  Resource  `json:"resource"`
	LabelIDs  []string  `json:"label_ids"`
	Revision  int       `json:"revision"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}
type BindingInput struct {
	LabelIDs  []string `json:"label_ids"`
	Revision  int      `json:"revision"`
	RequestID string   `json:"request_id"`
}
type Choice struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"`
	Color string `json:"color"`
}
type Applied struct {
	Choice
	Inherited bool     `json:"inherited"`
	Source    Resource `json:"source"`
}
type Audit struct {
	At       time.Time `json:"at"`
	ActorID  string    `json:"actor_id"`
	Action   string    `json:"action"`
	LabelID  string    `json:"label_id,omitempty"`
	Resource *Resource `json:"resource,omitempty"`
	Revision int       `json:"revision"`
}
type receipt struct {
	ActorID   string   `json:"actor_id"`
	RequestID string   `json:"request_id"`
	Hash      string   `json:"hash"`
	Label     *Label   `json:"label,omitempty"`
	Binding   *Binding `json:"binding,omitempty"`
}
type state struct {
	Labels   map[string]Label   `json:"labels"`
	Bindings map[string]Binding `json:"bindings"`
	Receipts []receipt          `json:"receipts"`
	Audit    []Audit            `json:"audit"`
}
type envelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type Store struct {
	mu     sync.Mutex
	path   string
	docs   *storage.Documents
	aead   cipher.AEAD
	data   state
	now    func() time.Time
	closed bool
}

func validText(s string, n int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= n && strings.IndexFunc(s, unicode.IsControl) < 0
}
func Prepare(in Input) (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Value = strings.TrimSpace(in.Value)
	in.Description = strings.TrimSpace(in.Description)
	in.Color = strings.ToLower(in.Color)
	if in.Color == "" {
		in.Color = "#58a6ff"
	}
	if in.Name == "" || !validText(in.Name, 64) || !validText(in.Value, 128) || !validText(in.Description, 500) || !colorPattern.MatchString(in.Color) || in.Revision < 0 {
		return in, ErrInvalid
	}
	return in, nil
}
func ValidID(id string) bool { return idPattern.MatchString(id) }
func ValidResource(r Resource) bool {
	return (r.Type == "asset" || r.Type == "node") && resourceID.MatchString(r.ID)
}
func resourceKey(r Resource) string  { return r.Type + ":" + r.ID }
func validActor(s string) bool       { return s != "" && validText(s, 128) }
func nameKey(s string) string        { return strings.ToLower(s) }
func cloneBinding(b Binding) Binding { b.LabelIDs = slices.Clone(b.LabelIDs); return b }
func validIDs(ids []string) bool {
	if len(ids) > 64 {
		return false
	}
	for i, id := range ids {
		if !ValidID(id) || i > 0 && ids[i-1] >= id {
			return false
		}
	}
	return true
}
func validLabel(l Label) bool {
	p, e := Prepare(l.Input)
	return e == nil && p == l.Input && ValidID(l.ID) && l.Revision > 0 && l.RequestID == "" && !l.UpdatedAt.IsZero()
}
func validBinding(b Binding, labels map[string]Label) bool {
	if !ValidResource(b.Resource) || b.Revision < 1 || b.UpdatedAt.IsZero() || !validIDs(b.LabelIDs) {
		return false
	}
	names := map[string]bool{}
	for _, id := range b.LabelIDs {
		l, ok := labels[id]
		if !ok || names[nameKey(l.Name)] {
			return false
		}
		names[nameKey(l.Name)] = true
	}
	return true
}
func validate(st state) error {
	if st.Labels == nil || st.Bindings == nil || len(st.Labels) > 2000 || len(st.Bindings) > 20000 || len(st.Receipts) > 4000 || len(st.Audit) > 1000 {
		return ErrInvalid
	}
	unique := map[string]bool{}
	for id, l := range st.Labels {
		k := nameKey(l.Name) + "\x00" + l.Value
		if id != l.ID || !validLabel(l) || unique[k] {
			return ErrInvalid
		}
		unique[k] = true
	}
	for key, b := range st.Bindings {
		if key != resourceKey(b.Resource) || !validBinding(b, st.Labels) {
			return ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, r := range st.Receipts {
		k := r.ActorID + "\x00" + r.RequestID
		if !validActor(r.ActorID) || !requestID.MatchString(r.RequestID) || !digestPattern.MatchString(r.Hash) || seen[k] || (r.Label == nil) == (r.Binding == nil) {
			return ErrInvalid
		}
		seen[k] = true
		if r.Label != nil && !validLabel(*r.Label) {
			return ErrInvalid
		}
		if r.Binding != nil && (!ValidResource(r.Binding.Resource) || r.Binding.Revision < 1 || r.Binding.UpdatedAt.IsZero() || !validIDs(r.Binding.LabelIDs)) {
			return ErrInvalid
		}
	}
	for _, a := range st.Audit {
		if !validActor(a.ActorID) || a.At.IsZero() || a.Revision < 1 {
			return ErrInvalid
		}
		switch a.Action {
		case "save", "delete":
			if !ValidID(a.LabelID) || a.Resource != nil {
				return ErrInvalid
			}
		case "bind":
			if a.Resource == nil || !ValidResource(*a.Resource) || a.LabelID != "" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	return nil
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
	s := &Store{path: path, docs: docs, aead: aead, now: time.Now, data: state{Labels: map[string]Label{}, Bindings: map[string]Binding{}, Receipts: []receipt{}, Audit: []Audit{}}}
	var raw []byte
	if docs != nil {
		raw, e = docs.LoadOrImport("labels", path)
	} else {
		var f *os.File
		f, e = os.Open(path)
		if e == nil {
			raw, e = io.ReadAll(io.LimitReader(f, 2*maxBytes+1))
			_ = f.Close()
		} else if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return nil, e
	}
	if len(raw) == 0 {
		return s, nil
	}
	if len(raw) > 2*maxBytes {
		return nil, ErrInvalid
	}
	var box envelope
	if json.Unmarshal(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	plain, e := aead.Open(nil, box.Nonce, box.Ciphertext, []byte("jms233/labels/v1"))
	if e != nil || len(plain) > maxBytes {
		return nil, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if dec.Decode(&s.data) != nil || dec.Decode(new(any)) != io.EOF || validate(s.data) != nil {
		return nil, ErrInvalid
	}
	return s, nil
}
func (s *Store) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true }
func clone(st state) state {
	out := state{Labels: map[string]Label{}, Bindings: map[string]Binding{}, Receipts: append([]receipt{}, st.Receipts...), Audit: append([]Audit{}, st.Audit...)}
	for k, v := range st.Labels {
		out.Labels[k] = v
	}
	for k, v := range st.Bindings {
		out.Bindings[k] = cloneBinding(v)
	}
	return out
}
func (s *Store) persist(st state) error {
	if e := validate(st); e != nil {
		return e
	}
	plain, e := json.Marshal(st)
	if e != nil {
		return e
	}
	if len(plain) > maxBytes {
		return ErrCapacity
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{Version: 1, Nonce: nonce, Ciphertext: s.aead.Seal(nil, nonce, plain, []byte("jms233/labels/v1"))})
	if e != nil {
		return e
	}
	if s.docs != nil {
		return s.docs.Save("labels", raw)
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".labels-*")
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
	closeError := f.Close()
	if e != nil {
		return e
	}
	if closeError != nil {
		return closeError
	}
	return os.Rename(f.Name(), s.path)
}
func hash(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func find(st state, actor, request, hash string) (receipt, bool, error) {
	for _, r := range st.Receipts {
		if r.ActorID == actor && r.RequestID == request {
			if r.Hash != hash {
				return receipt{}, true, ErrConflict
			}
			return r, true, nil
		}
	}
	return receipt{}, false, nil
}
func (s *Store) commit(st state, r receipt, a Audit) error {
	if len(st.Receipts) >= 4000 {
		return ErrCapacity
	}
	st.Receipts = append(st.Receipts, r)
	st.Audit = append(st.Audit, a)
	if len(st.Audit) > 1000 {
		st.Audit = st.Audit[len(st.Audit)-1000:]
	}
	if e := s.persist(st); e != nil {
		return e
	}
	s.data = st
	return nil
}

func (s *Store) Save(id, actor string, in Input) (Label, error) {
	in, e := Prepare(in)
	if e != nil || !validActor(actor) || !requestID.MatchString(in.RequestID) || id != "" && !ValidID(id) {
		return Label{}, ErrInvalid
	}
	digest := hash([]any{"save", id, in})
	request := in.RequestID
	in.RequestID = ""
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Label{}, ErrClosed
	}
	if r, found, e := find(s.data, actor, request, digest); found {
		if e != nil {
			return Label{}, e
		}
		if r.Label == nil {
			return Label{}, ErrConflict
		}
		return *r.Label, nil
	}
	st := clone(s.data)
	current, exists := st.Labels[id]
	if id != "" && !exists {
		return Label{}, ErrNotFound
	}
	if exists && current.Revision != in.Revision || !exists && in.Revision != 0 {
		return Label{}, ErrConflict
	}
	for other, l := range st.Labels {
		if other != id && nameKey(l.Name) == nameKey(in.Name) && l.Value == in.Value {
			return Label{}, ErrConflict
		}
	}
	if !exists {
		if len(st.Labels) >= 2000 {
			return Label{}, ErrCapacity
		}
		random := make([]byte, 16)
		if _, e = rand.Read(random); e != nil {
			return Label{}, e
		}
		id = "label-" + hex.EncodeToString(random)
		if _, collision := st.Labels[id]; collision {
			return Label{}, ErrConflict
		}
	}
	in.Revision++
	l := Label{Input: in, ID: id, UpdatedAt: s.now().UTC()}
	st.Labels[id] = l
	for _, b := range st.Bindings {
		if !validBinding(b, st.Labels) {
			return Label{}, ErrConflict
		}
	}
	e = s.commit(st, receipt{ActorID: actor, RequestID: request, Hash: digest, Label: &l}, Audit{At: s.now().UTC(), ActorID: actor, Action: "save", LabelID: id, Revision: l.Revision})
	if e != nil {
		return Label{}, e
	}
	return l, nil
}
func (s *Store) Delete(id, actor string, revision int, request string, exists func(Resource) bool) error {
	if !ValidID(id) || !validActor(actor) || revision < 1 || !requestID.MatchString(request) {
		return ErrInvalid
	}
	digest := hash([]any{"delete", id, revision})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, found, e := find(s.data, actor, request, digest); found {
		return e
	}
	st := clone(s.data)
	l, ok := st.Labels[id]
	if !ok {
		return ErrNotFound
	}
	if l.Revision != revision {
		return ErrConflict
	}
	for key, b := range st.Bindings {
		if slices.Contains(b.LabelIDs, id) {
			if exists == nil || exists(b.Resource) {
				return ErrInUse
			}
			delete(st.Bindings, key)
		}
	}
	delete(st.Labels, id)
	return s.commit(st, receipt{ActorID: actor, RequestID: request, Hash: digest, Label: &l}, Audit{At: s.now().UTC(), ActorID: actor, Action: "delete", LabelID: id, Revision: l.Revision})
}
func (s *Store) Page(search string, offset, limit int) ([]Label, int, error) {
	if !validText(search, 256) || offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, 0, ErrClosed
	}
	search = strings.ToLower(strings.TrimSpace(search))
	rows := []Label{}
	for _, l := range s.data.Labels {
		if search == "" || strings.Contains(strings.ToLower(l.Name+" "+l.Value+" "+l.Description), search) {
			rows = append(rows, l)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := nameKey(rows[i].Name), nameKey(rows[j].Name)
		if a != b {
			return a < b
		}
		if rows[i].Value != rows[j].Value {
			return rows[i].Value < rows[j].Value
		}
		return rows[i].ID < rows[j].ID
	})
	total := len(rows)
	offset = min(offset, total)
	return rows[offset:min(offset+limit, total)], total, nil
}
func (s *Store) Binding(resource Resource) (Binding, error) {
	if !ValidResource(resource) {
		return Binding{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Binding{}, ErrClosed
	}
	b, ok := s.data.Bindings[resourceKey(resource)]
	if !ok {
		return Binding{Resource: resource, LabelIDs: []string{}}, nil
	}
	return cloneBinding(b), nil
}
func (s *Store) Bind(resource Resource, actor string, in BindingInput) (Binding, error) {
	if !ValidResource(resource) || !validActor(actor) || in.Revision < 0 || !requestID.MatchString(in.RequestID) {
		return Binding{}, ErrInvalid
	}
	in.LabelIDs = slices.Clone(in.LabelIDs)
	sort.Strings(in.LabelIDs)
	if !validIDs(in.LabelIDs) {
		return Binding{}, ErrInvalid
	}
	if in.LabelIDs == nil {
		in.LabelIDs = []string{}
	}
	digest := hash([]any{"bind", resource, in})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Binding{}, ErrClosed
	}
	if r, found, e := find(s.data, actor, in.RequestID, digest); found {
		if e != nil {
			return Binding{}, e
		}
		if r.Binding == nil {
			return Binding{}, ErrConflict
		}
		return cloneBinding(*r.Binding), nil
	}
	st := clone(s.data)
	current, exists := st.Bindings[resourceKey(resource)]
	if current.Revision != in.Revision {
		return Binding{}, ErrConflict
	}
	if !exists && len(st.Bindings) >= 20000 {
		return Binding{}, ErrCapacity
	}
	b := Binding{Resource: resource, LabelIDs: in.LabelIDs, Revision: current.Revision + 1, UpdatedAt: s.now().UTC()}
	if !validBinding(b, st.Labels) {
		return Binding{}, ErrInvalid
	}
	st.Bindings[resourceKey(resource)] = b
	e := s.commit(st, receipt{ActorID: actor, RequestID: in.RequestID, Hash: digest, Binding: &b}, Audit{At: s.now().UTC(), ActorID: actor, Action: "bind", Resource: &resource, Revision: b.Revision})
	if e != nil {
		return Binding{}, e
	}
	return cloneBinding(b), nil
}

// Resources are ordered from most specific to least specific. A key is selected
// once, so direct asset labels override the nearest node and then its parents.
func (s *Store) Effective(resources []Resource) ([]Applied, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	return effective(s.data, resources)
}

// View returns the direct revision and its effective values from one snapshot.
func (s *Store) View(resources []Resource) (Binding, []Applied, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Binding{}, nil, ErrClosed
	}
	if len(resources) == 0 {
		return Binding{}, nil, ErrInvalid
	}
	rows, e := effective(s.data, resources)
	if e != nil {
		return Binding{}, nil, e
	}
	b, exists := s.data.Bindings[resourceKey(resources[0])]
	if !exists {
		b = Binding{Resource: resources[0], LabelIDs: []string{}}
	}
	return cloneBinding(b), rows, nil
}

func effective(st state, resources []Resource) ([]Applied, error) {
	rows := []Applied{}
	seen := map[string]bool{}
	for index, r := range resources {
		if !ValidResource(r) {
			return nil, ErrInvalid
		}
		b := st.Bindings[resourceKey(r)]
		for _, id := range b.LabelIDs {
			l := st.Labels[id]
			key := nameKey(l.Name)
			if !seen[key] {
				rows = append(rows, Applied{Choice: Choice{ID: l.ID, Name: l.Name, Value: l.Value, Color: l.Color}, Inherited: index > 0, Source: r})
				seen[key] = true
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool { return nameKey(rows[i].Name) < nameKey(rows[j].Name) })
	return rows, nil
}
func (s *Store) Choices() ([]Choice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	rows := []Choice{}
	for _, l := range s.data.Labels {
		rows = append(rows, Choice{ID: l.ID, Name: l.Name, Value: l.Value, Color: l.Color})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := nameKey(rows[i].Name), nameKey(rows[j].Name)
		if a != b {
			return a < b
		}
		return rows[i].Value < rows[j].Value
	})
	return rows, nil
}
func (s *Store) Audit(offset, limit int) ([]Audit, int, error) {
	if offset < 0 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, 0, ErrClosed
	}
	rows := append([]Audit{}, s.data.Audit...)
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	for i := range rows {
		if rows[i].Resource != nil {
			r := *rows[i].Resource
			rows[i].Resource = &r
		}
	}
	total := len(rows)
	offset = min(offset, total)
	return rows[offset:min(offset+limit, total)], total, nil
}
