package monitorhistory

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
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

type envelope struct {
	Version     int
	Nonce, Data []byte
}
type Store struct {
	mu        sync.Mutex
	dir       string
	docs      *storage.Documents
	aead      cipher.AEAD
	keys      map[string]bool
	cache     map[string]segment
	health    Health
	now       func() time.Time
	lastPrune time.Time
	closed    bool
	saveHook  func(string, []byte) error
}

func assetHash(id string) string { h := sha256.Sum256([]byte(id)); return hex.EncodeToString(h[:12]) }
func segmentKey(id string, at time.Time) string {
	return assetHash(id) + "-" + at.UTC().Format("2006010215")
}

func Open(dir string, key []byte, docs *storage.Documents) (*Store, error) {
	if len(key) != 32 {
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
	s := &Store{dir: dir, docs: docs, aead: aead, keys: map[string]bool{}, cache: map[string]segment{}, now: time.Now}
	var meta struct{ Version int }
	ok, e := s.load("meta", &meta)
	if e != nil {
		return nil, e
	}
	if ok && meta.Version != 1 {
		return nil, ErrCorrupt
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, entry := range entries {
			name := strings.TrimSuffix(entry.Name(), ".json")
			if entry.IsDir() || name == "meta" || name == ".DS_Store" || name == "Thumbs.db" || strings.HasPrefix(name, ".history-") {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 || !strings.HasSuffix(entry.Name(), ".json") || !keyPattern.MatchString(name) {
				return nil, ErrCorrupt
			}
			s.keys[name] = true
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if docs != nil {
		keys, e := docs.Keys("mh:", MaxSegments+1)
		if e != nil {
			return nil, e
		}
		for _, key := range keys {
			name := strings.TrimPrefix(key, "mh:")
			if name == "meta" {
				continue
			}
			if !keyPattern.MatchString(name) {
				return nil, ErrCorrupt
			}
			s.keys[name] = true
		}
	}
	if len(s.keys) > MaxSegments {
		return nil, ErrCapacity
	}
	for name := range s.keys {
		if _, e := time.Parse("2006010215", name[25:]); e != nil {
			return nil, ErrCorrupt
		}
	}
	if !ok {
		if len(s.keys) > 0 {
			return nil, ErrCorrupt
		}
		if e = s.save("meta", struct{ Version int }{1}); e != nil {
			return nil, e
		}
	}
	return s, nil
}
func (s *Store) Close() { s.mu.Lock(); s.closed = true; s.cache = nil; s.mu.Unlock() }
func (s *Store) healthLocked() Health {
	h := s.health
	h.Segments = len(s.keys)
	h.Capacity = MaxSegments
	return h
}
func (s *Store) Health() Health { s.mu.Lock(); defer s.mu.Unlock(); return s.healthLocked() }
func (s *Store) fail(e error) error {
	s.health.ErrorCode = "history_unavailable"
	if errors.Is(e, ErrCapacity) {
		s.health.ErrorCode = "history_capacity"
	}
	s.health.LastFailure = s.now().UTC()
	return e
}

func (s *Store) load(key string, value any) (bool, error) {
	var raw []byte
	var e error
	path := filepath.Join(s.dir, key+".json")
	if s.docs != nil {
		raw, e = s.docs.LoadOrImport("mh:"+key, path)
	} else {
		raw, e = os.ReadFile(path)
		if errors.Is(e, os.ErrNotExist) {
			e = nil
		}
	}
	if e != nil {
		return false, e
	}
	if len(raw) == 0 {
		return false, nil
	}
	if len(raw) > 1<<20 {
		return false, ErrCorrupt
	}
	var box envelope
	if strictDecode(raw, &box) != nil || box.Version != 1 || len(box.Nonce) != s.aead.NonceSize() {
		return false, ErrCorrupt
	}
	plain, e := s.aead.Open(nil, box.Nonce, box.Data, []byte("jms233/monitor-history/v1/"+key))
	if e != nil || strictDecode(plain, value) != nil {
		return false, ErrCorrupt
	}
	return true, nil
}
func strictDecode(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(value); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrCorrupt
	}
	return nil
}
func (s *Store) save(key string, value any) error {
	plain, e := json.Marshal(value)
	if e != nil || len(plain) > 512<<10 {
		return ErrCorrupt
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	raw, e := json.Marshal(envelope{1, nonce, s.aead.Seal(nil, nonce, plain, []byte("jms233/monitor-history/v1/"+key))})
	if e != nil {
		return e
	}
	if s.saveHook != nil {
		if e := s.saveHook(key, raw); e != nil {
			return e
		}
	}
	if s.docs != nil {
		return s.docs.Save("mh:"+key, raw)
	}
	if e := os.MkdirAll(s.dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(s.dir, ".history-*")
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
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), filepath.Join(s.dir, key+".json"))
}
func (s *Store) readSegment(key, asset string, hour time.Time) (segment, error) {
	if v, ok := s.cache[key]; ok {
		if v.AssetID != asset {
			return segment{}, ErrCorrupt
		}
		return v, nil
	}
	v := segment{Version: 1, AssetID: asset, Hour: hour.UTC(), Samples: []Sample{}}
	ok, e := s.load(key, &v)
	if e != nil {
		return v, e
	}
	if !ok {
		if s.keys[key] {
			return v, ErrCorrupt
		}
		return v, nil
	}
	if v.Version != 1 || v.AssetID != asset || !v.Hour.Equal(hour) || len(v.Samples) > 60 {
		return v, ErrCorrupt
	}
	var previous time.Time
	for _, p := range v.Samples {
		if !validSample(p) || !p.At.Truncate(time.Hour).Equal(hour) || !previous.IsZero() && !p.At.Truncate(time.Minute).After(previous) {
			return v, ErrCorrupt
		}
		previous = p.At.Truncate(time.Minute)
	}
	return v, nil
}
func (s *Store) cacheSegment(key string, v segment) {
	if len(s.cache) >= cacheSize {
		for k := range s.cache {
			delete(s.cache, k)
			break
		}
	}
	s.cache[key] = v
}

// Record retains the last observed sample in each UTC minute. Equal samples are
// idempotent; conflicting payloads at an identical timestamp are rejected.
func (s *Store) Record(asset string, p Sample) (bool, error) {
	if !idPattern.MatchString(asset) || !validSample(p) {
		return false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	now := s.now().UTC()
	if p.At.After(now.Add(time.Minute)) {
		return false, ErrInvalid
	}
	if p.At.Before(now.Add(-Retention)) {
		return false, nil
	}
	p.At = p.At.UTC()
	p.Values = copyValues(p.Values)
	hour := p.At.Truncate(time.Hour)
	key := segmentKey(asset, hour)
	if !s.keys[key] && len(s.keys) >= MaxSegments {
		return false, s.fail(ErrCapacity)
	}
	v, e := s.readSegment(key, asset, hour)
	if e != nil {
		return false, s.fail(e)
	}
	index := sort.Search(len(v.Samples), func(i int) bool { return !v.Samples[i].At.Truncate(time.Minute).Before(p.At.Truncate(time.Minute)) })
	v.Samples = append([]Sample{}, v.Samples...)
	if index < len(v.Samples) && v.Samples[index].At.Truncate(time.Minute).Equal(p.At.Truncate(time.Minute)) {
		old := v.Samples[index]
		if p.At.Before(old.At) {
			return false, nil
		}
		if p.At.Equal(old.At) {
			if reflect.DeepEqual(old, p) {
				return false, nil
			}
			return false, ErrConflict
		}
		v.Samples[index] = p
	} else {
		v.Samples = append(v.Samples, Sample{})
		copy(v.Samples[index+1:], v.Samples[index:])
		v.Samples[index] = p
	}
	if e := s.save(key, v); e != nil {
		return false, s.fail(e)
	}
	s.keys[key] = true
	s.cacheSegment(key, v)
	s.health.ErrorCode = ""
	return true, nil
}
func copyValues(values map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for k, v := range values {
		out[k] = v
	}
	return out
}

// Prune runs at most hourly unless forced. Only owned expired segments are
// removed. Deleted inventory remains inaccessible and expires normally.
func (s *Store) Prune(force bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	now := s.now().UTC()
	if !force && now.Sub(s.lastPrune) < time.Hour {
		return nil
	}
	s.health.PrunePending = true
	for key := range s.keys {
		hour, e := time.Parse("2006010215", key[25:])
		if e != nil {
			return s.fail(ErrCorrupt)
		}
		if hour.Add(time.Hour).After(now.Add(-Retention)) {
			continue
		}
		if s.docs != nil {
			if e := s.docs.Delete("mh:" + key); e != nil {
				return s.fail(e)
			}
		}
		e = os.Remove(filepath.Join(s.dir, key+".json"))
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return s.fail(e)
		}
		delete(s.keys, key)
		delete(s.cache, key)
	}
	s.lastPrune = now
	s.health.PrunePending = false
	s.health.ErrorCode = ""
	return nil
}
