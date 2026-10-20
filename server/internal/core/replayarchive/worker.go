package replayarchive

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
)

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.r.Read(p)
}
func digestReader(ctx context.Context, r io.Reader, size int64) (string, int64, error) {
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(contextReader{ctx, r}, size+1))
	if e != nil {
		return "", n, e
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func (s *Store) objectKey(c Config, r Record) string {
	h := hmac.New(sha256.New, s.hashKey)
	_, _ = h.Write([]byte("jms233/replay-archive-namespace/v1"))
	namespace := hex.EncodeToString(h.Sum(nil))[:32]
	identity := sha256.Sum256([]byte(refKey(r.Ref)))
	return c.Prefix + "/" + namespace + "/" + r.Kind + "/" + hex.EncodeToString(identity[:]) + "/" + r.SHA256 + ".enc"
}
func (s *Store) worker(ctx context.Context) {
	defer s.workers.Done()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		worked, e := s.ProcessNext(ctx)
		if worked && e == nil {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-ticker.C:
		}
	}
}

// ProcessNext takes one durable job. Claims are process-local because only the
// installation's active storage owner starts workers. Lost responses safely
// re-read the content-addressed object before acknowledging completion.
func (s *Store) ProcessNext(parent context.Context) (bool, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false, ErrClosed
	}
	if !s.data.History[s.data.Revision].Enabled {
		s.mu.Unlock()
		return false, nil
	}
	keys := make([]string, 0, len(s.data.Records))
	for key, r := range s.data.Records {
		if r.Status == "queued" && !r.NextAttempt.After(s.now()) && s.busy[key] == nil {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		s.mu.Unlock()
		return false, nil
	}
	key := keys[0]
	r := s.data.Records[key]
	generation := s.data.Revision
	c := s.credentials(r.ConfigRevision)
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	s.busy[key] = cancel
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); delete(s.busy, key); s.mu.Unlock() }()
	e := s.transfer(ctx, generation, c, &r)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || generation != s.data.Revision || parent.Err() != nil {
		return true, e
	}
	if ctx.Err() != nil {
		e = ErrUnavailable
	}
	st := s.copy()
	if e == nil {
		r.Status = "stored"
		r.StoredAt = s.now().UTC()
		r.VerifiedAt = r.StoredAt
		r.NextAttempt = time.Time{}
		r.ErrorCode = ""
	} else {
		r.Attempts++
		r.ErrorCode = "storage_unavailable"
		if errors.Is(e, ErrIntegrity) || errors.Is(e, replaystore.ErrIntegrity) {
			r.ErrorCode = "integrity_mismatch"
		}
		if errors.Is(e, errSource) {
			r.ErrorCode = "source_unavailable"
		}
		r.Status = "queued"
		r.NextAttempt = s.now().UTC().Add(min(time.Second*time.Duration(1<<min(r.Attempts, 9)), 10*time.Minute))
		if r.Attempts >= 10 {
			r.Status = "failed"
			r.NextAttempt = time.Time{}
		}
	}
	st.Records[key] = r
	if pe := s.persist(st); pe != nil {
		return true, pe
	}
	s.data = st
	return true, e
}

var errSource = errors.New("local replay source unavailable")

func (s *Store) transfer(ctx context.Context, generation int, c Config, r *storedRecord) error {
	f, e := s.source.Prepare(ctx, r.Ref)
	if e != nil {
		return errSource
	}
	defer f.Close()
	digest, size, e := digestReader(ctx, f, replaystore.MaxObjectBytes)
	if e != nil {
		return e
	}
	if size < 1 || size > replaystore.MaxObjectBytes {
		return ErrIntegrity
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return errSource
	}
	if r.Size != 0 && (r.Size != size || r.SHA256 != digest) {
		return ErrIntegrity
	}
	r.Size = size
	r.SHA256 = digest
	r.Key = s.objectKey(c, r.Record)
	// Persist the manifest before sending any bytes. A crash after PUT can use
	// the exact same object identity without overwriting remote content.
	s.mu.Lock()
	if s.closed || s.data.Revision != generation || ctx.Err() != nil {
		s.mu.Unlock()
		return context.Canceled
	}
	st := s.copy()
	st.Records[refKey(r.Ref)] = *r
	e = s.persist(st)
	if e == nil {
		s.data = st
	}
	s.mu.Unlock()
	if e != nil {
		return e
	}
	objects, e := s.factory(ctx, c)
	if e != nil {
		return ErrUnavailable
	}
	defer objects.Close()
	e = objects.Put(ctx, r.Key, f, r.Size, r.SHA256)
	if e != nil && !errors.Is(e, replaystore.ErrExists) {
		return e
	}
	return verifyObject(ctx, objects, *r, nil)
}
func verifyObject(ctx context.Context, objects replaystore.Objects, r storedRecord, w io.Writer) error {
	reader, e := objects.Get(ctx, r.Key)
	if e != nil {
		return ErrUnavailable
	}
	defer reader.Close()
	var source io.Reader = reader
	if w != nil {
		source = io.TeeReader(reader, w)
	}
	digest, n, e := digestReader(ctx, source, r.Size)
	if e != nil {
		return ErrUnavailable
	}
	if n != r.Size || digest != r.SHA256 {
		return ErrIntegrity
	}
	return nil
}
func (s *Store) snapshot(ref Ref) (storedRecord, Config, error) {
	if !ValidRef(ref) {
		return storedRecord{}, Config{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return storedRecord{}, Config{}, ErrClosed
	}
	r, ok := s.data.Records[refKey(ref)]
	if !ok || r.Status != "stored" {
		return storedRecord{}, Config{}, ErrNotFound
	}
	return r, s.credentials(r.ConfigRevision), nil
}

// OpenCiphertext returns only SHA-256 verified ciphertext. The existing broker
// must still check session authorization and authenticate/decrypt its format.
func (s *Store) OpenCiphertext(ctx context.Context, ref Ref) (SeekCloser, error) {
	r, c, e := s.snapshot(ref)
	if e != nil {
		return nil, e
	}
	return s.cache.open(ctx, r.Key, r.Size, func(ctx context.Context, w io.Writer) error {
		o, e := s.factory(ctx, c)
		if e != nil {
			return ErrUnavailable
		}
		defer o.Close()
		return verifyObject(ctx, o, r, w)
	})
}

// Verify bypasses the local cache, checks the full remote ciphertext, and adds
// an audit event only after readback succeeds. It never removes local content.
func (s *Store) Verify(ctx context.Context, ref Ref, actor string) (Record, error) {
	if !validActor(actor) {
		return Record{}, ErrInvalid
	}
	r, c, e := s.snapshot(ref)
	if e != nil {
		return Record{}, e
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	o, e := s.factory(ctx, c)
	if e != nil {
		return Record{}, ErrUnavailable
	}
	defer o.Close()
	if e = verifyObject(ctx, o, r, nil); e != nil {
		return Record{}, e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, ErrClosed
	}
	current, ok := s.data.Records[refKey(ref)]
	if !ok || current.Key != r.Key || current.Status != "stored" {
		return Record{}, ErrConflict
	}
	current.VerifiedAt = s.now().UTC()
	st := s.copy()
	st.Records[refKey(ref)] = current
	addAudit(&st, Audit{At: s.now().UTC(), ActorID: actor, Action: "verify", Ref: &ref, Revision: s.data.Revision})
	if e = s.persist(st); e != nil {
		return Record{}, e
	}
	s.data = st
	return current.Record, nil
}
