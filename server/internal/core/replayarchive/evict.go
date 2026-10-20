package replayarchive

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/neko233-com/jumpserver233/server/internal/recorder"
)

type localEvictor interface {
	Evict(context.Context, Ref, SeekCloser, int64, string) error
}

// Evict obtains a fresh fully verified remote copy before comparing and removing
// finalized local ciphertext. Audit indexes, manifests, keys and remote objects
// are never deleted. A partial interruption can retry without a full local copy.
func (s *Store) Evict(ctx context.Context, ref Ref, actor, request string) (Record, error) {
	if !ValidRef(ref) || !validActor(actor) || !requestPattern.MatchString(request) {
		return Record{}, ErrInvalid
	}
	local, ok := s.source.(localEvictor)
	if !ok {
		return Record{}, ErrUnavailable
	}
	hash := s.requestHash([]any{"evict", ref})
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Record{}, ErrClosed
	}
	if previous, yes, e := s.replay(actor, request, hash); yes {
		s.mu.Unlock()
		if e != nil {
			return Record{}, e
		}
		if previous.Record == nil {
			return Record{}, ErrConflict
		}
		return *previous.Record, nil
	}
	r, ok := s.data.Records[refKey(ref)]
	if !ok || r.Status != "stored" {
		s.mu.Unlock()
		return Record{}, ErrNotFound
	}
	if s.busy[refKey(ref)] != nil {
		s.mu.Unlock()
		return Record{}, ErrConflict
	}
	if len(s.data.Receipts) >= 4000 {
		s.mu.Unlock()
		return Record{}, ErrCapacity
	}
	c := s.credentials(r.ConfigRevision)
	ctx, cancel := s.operationContext(ctx)
	s.busy[refKey(ref)] = cancel
	s.operations.Add(1)
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); delete(s.busy, refKey(ref)); s.mu.Unlock(); s.operations.Done() }()
	if r.LocalEvictedAt.IsZero() {
		identity := make([]byte, 16)
		if _, e := rand.Read(identity); e != nil {
			return Record{}, e
		}
		// Fresh readback shares the normal cache budget rather than reserving an
		// additional unbounded scratch copy beside active replay downloads.
		reader, e := s.cache.open(ctx, r.Key+":evict:"+hex.EncodeToString(identity), r.Size, func(ctx context.Context, w io.Writer) error {
			o, e := s.factory(ctx, c)
			if e != nil {
				return ErrUnavailable
			}
			defer o.Close()
			return verifyObject(ctx, o, r, w)
		})
		if e != nil {
			return Record{}, e
		}
		e = local.Evict(ctx, ref, reader, r.Size, r.SHA256)
		ce := reader.Close()
		if e != nil {
			return Record{}, e
		}
		if ce != nil {
			return Record{}, ce
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Record{}, ErrClosed
	}
	if e := ctx.Err(); e != nil {
		return Record{}, e
	}
	current, ok := s.data.Records[refKey(ref)]
	if !ok || current.Status != "stored" || current.Key != r.Key {
		return Record{}, ErrConflict
	}
	if current.LocalEvictedAt.IsZero() {
		current.LocalEvictedAt = s.now().UTC()
		current.VerifiedAt = current.LocalEvictedAt
	}
	st := s.copy()
	st.Records[refKey(ref)] = current
	out := current.Record
	e := s.commit(st, receipt{Actor: actor, Request: request, Hash: hash, Record: &out}, Audit{At: s.now().UTC(), ActorID: actor, Action: "evict", Ref: &ref, Revision: s.data.Revision})
	return out, e
}

func sameFileForRemoval(path string, expected os.FileInfo) error {
	current, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !current.Mode().IsRegular() || !os.SameFile(current, expected) || current.Size() != expected.Size() || !current.ModTime().Equal(expected.ModTime()) {
		return ErrIntegrity
	}
	return nil
}
func (r *Recordings) Evict(ctx context.Context, ref Ref, remote SeekCloser, size int64, digest string) error {
	if !ValidRef(ref) {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if ref.Kind == "desktop" {
		return r.evictDesktop(ctx, ref.SessionID, remote, size)
	}
	if !r.endedTerminal(ctx, ref.SessionID) {
		return ErrNotFound
	}
	path := filepath.Join(r.root, "sessions", ref.SessionID+".json.gz.enc")
	f, e := regularFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return e
	}
	observed, n, e := digestReader(ctx, f, size)
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if observed != digest || n != size {
		return ErrIntegrity
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = sameFileForRemoval(path, info); e != nil {
		return e
	}
	if e = os.Remove(path); os.IsNotExist(e) {
		return nil
	}
	return e
}
func (r *Recordings) evictDesktop(ctx context.Context, id string, remote SeekCloser, size int64) error {
	dir := filepath.Join(r.root, "desktop-sessions", id)
	info, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrIntegrity
	}
	path := filepath.Join(dir, "index.json")
	f, e := regularFile(path)
	if e != nil {
		return e
	}
	indexInfo, e := f.Stat()
	if e != nil {
		f.Close()
		return e
	}
	raw, e := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	f.Close()
	if e != nil || len(raw) > 2<<20 {
		return ErrIntegrity
	}
	var index struct {
		ID     string                  `json:"session_id"`
		Status string                  `json:"status"`
		Frames []recorder.DesktopFrame `json:"frames"`
	}
	if json.Unmarshal(raw, &index) != nil || index.ID != id || index.Status != "ended" || len(index.Frames) < 1 || len(index.Frames) > recorder.MaxDesktopFrames {
		return ErrIntegrity
	}
	reader, ok := remote.(io.ReaderAt)
	if !ok {
		return ErrUnavailable
	}
	archive, e := zip.NewReader(reader, size)
	if e != nil || len(archive.File) != len(index.Frames) {
		return ErrIntegrity
	}
	entries := map[string]*zip.File{}
	for _, entry := range archive.File {
		if entries[entry.Name] != nil {
			return ErrIntegrity
		}
		entries[entry.Name] = entry
	}
	files := map[string]os.FileInfo{}
	for i, frame := range index.Frames {
		if e = ctx.Err(); e != nil {
			return e
		}
		if frame.Index != i {
			return ErrIntegrity
		}
		name := fmt.Sprintf("%06d.png.enc", i)
		entry := entries[name]
		if entry == nil || entry.Method != zip.Store || entry.UncompressedSize64 > (40<<20)+128 {
			return ErrIntegrity
		}
		input, er := entry.Open()
		if er != nil {
			return ErrIntegrity
		}
		data, er := io.ReadAll(io.LimitReader(input, (40<<20)+129))
		input.Close()
		if er != nil {
			return ErrIntegrity
		}
		if _, er = recorder.DecodeDesktopFrame(id, r.key, frame, data); er != nil {
			return ErrIntegrity
		}
		localPath := filepath.Join(dir, name)
		local, er := regularFile(localPath)
		if errors.Is(er, os.ErrNotExist) {
			continue
		}
		if er != nil {
			return er
		}
		info, er := local.Stat()
		if er != nil {
			local.Close()
			return er
		}
		digest, n, er := digestReader(ctx, local, int64(len(data)))
		ce := local.Close()
		expected := sha256.Sum256(data)
		if er != nil {
			return er
		}
		if ce != nil {
			return ce
		}
		if n != int64(len(data)) || digest != hex.EncodeToString(expected[:]) {
			return ErrIntegrity
		}
		files[localPath] = info
	}
	// Validate every remaining frame and the index before the first deletion.
	if e = sameFileForRemoval(path, indexInfo); e != nil {
		return e
	}
	if _, e = os.Lstat(path); e != nil {
		return ErrIntegrity
	}
	for localPath, info := range files {
		if e = sameFileForRemoval(localPath, info); e != nil {
			return e
		}
	}
	for localPath, info := range files {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = sameFileForRemoval(localPath, info); e != nil {
			return e
		}
		if e = os.Remove(localPath); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}
