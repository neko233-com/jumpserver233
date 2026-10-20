package replayarchive

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
	"github.com/neko233-com/jumpserver233/server/internal/recorder"
)

type Recordings struct {
	root string
	key  []byte
}

func NewRecordings(root string, key []byte) (*Recordings, error) {
	if root == "" || len(key) != 32 {
		return nil, ErrInvalid
	}
	return &Recordings{root: root, key: append([]byte(nil), key...)}, nil
}
func regularFile(path string) (*os.File, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, ErrIntegrity
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	opened, e := f.Stat()
	if e != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		f.Close()
		return nil, ErrIntegrity
	}
	return f, nil
}
func (r *Recordings) endedTerminal(ctx context.Context, id string) bool {
	f, e := regularFile(filepath.Join(r.root, "sessions", "index.jsonl"))
	if e != nil {
		return false
	}
	defer f.Close()
	scan := bufio.NewScanner(contextReader{ctx, f})
	scan.Buffer(make([]byte, 4096), 2<<20)
	ended := false
	started := false
	for scan.Scan() {
		var event struct {
			SessionID string `json:"session_id"`
			Event     string `json:"event"`
		}
		if json.Unmarshal(scan.Bytes(), &event) != nil || event.SessionID != id {
			continue
		}
		if event.Event == "started" {
			started = true
			ended = false
		}
		if event.Event == "ended" && started {
			ended = true
		}
	}
	return scan.Err() == nil && ended
}
func (r *Recordings) Prepare(ctx context.Context, ref Ref) (SeekCloser, error) {
	if !ValidRef(ref) {
		return nil, ErrInvalid
	}
	if ref.Kind == "desktop" {
		return r.prepareDesktop(ctx, ref.SessionID)
	}
	if !r.endedTerminal(ctx, ref.SessionID) {
		return nil, errSource
	}
	f, e := regularFile(filepath.Join(r.root, "sessions", ref.SessionID+".json.gz.enc"))
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil || info.Size() < 1 || info.Size() > replaystore.MaxObjectBytes {
		f.Close()
		return nil, ErrCapacity
	}
	decoded, e := recorder.OpenReplayReader(io.NopCloser(f), ref.SessionID, r.key)
	if e != nil {
		f.Close()
		return nil, ErrIntegrity
	}
	// Ciphertext is bounded by 1 GiB; authenticate every gzip member and bound
	// expansion to 8 GiB before allowing any external upload.
	n, e := io.Copy(io.Discard, io.LimitReader(contextReader{ctx, decoded}, (8<<30)+1))
	ce := decoded.Close()
	if e != nil || ce != nil || n > 8<<30 {
		f.Close()
		return nil, ErrIntegrity
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}

type temporaryRecording struct {
	*os.File
	path string
}

func (r *temporaryRecording) Close() error { e := r.File.Close(); _ = os.Remove(r.path); return e }
func (r *Recordings) prepareDesktop(ctx context.Context, id string) (SeekCloser, error) {
	dir := filepath.Join(r.root, "desktop-sessions", id)
	info, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIntegrity
	}
	f, e := regularFile(filepath.Join(dir, "index.json"))
	if e != nil {
		return nil, e
	}
	raw, e := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	_ = f.Close()
	if e != nil || len(raw) > 2<<20 {
		return nil, ErrIntegrity
	}
	var index struct {
		ID     string                  `json:"session_id"`
		Status string                  `json:"status"`
		Frames []recorder.DesktopFrame `json:"frames"`
	}
	if json.Unmarshal(raw, &index) != nil || index.ID != id || index.Status != "ended" || len(index.Frames) < 1 || len(index.Frames) > recorder.MaxDesktopFrames {
		return nil, errSource
	}
	cache := filepath.Join(r.root, "replay-cache")
	if e = os.MkdirAll(cache, 0700); e != nil {
		return nil, e
	}
	out, e := os.CreateTemp(cache, ".replay-pack-*")
	if e != nil {
		return nil, e
	}
	result := &temporaryRecording{File: out, path: out.Name()}
	success := false
	defer func() {
		if !success {
			result.Close()
		}
	}()
	if e = out.Chmod(0600); e != nil {
		return nil, e
	}
	writer := zip.NewWriter(out)
	var total int64
	for i, frame := range index.Frames {
		if e = ctx.Err(); e != nil {
			_ = writer.Close()
			return nil, e
		}
		if frame.Index != i {
			_ = writer.Close()
			return nil, ErrIntegrity
		}
		name := fmt.Sprintf("%06d.png.enc", i)
		input, er := regularFile(filepath.Join(dir, name))
		if er != nil {
			_ = writer.Close()
			return nil, er
		}
		data, er := io.ReadAll(io.LimitReader(input, (40<<20)+129))
		_ = input.Close()
		if er != nil {
			_ = writer.Close()
			return nil, er
		}
		if _, er = recorder.DecodeDesktopFrame(id, r.key, frame, data); er != nil {
			_ = writer.Close()
			return nil, ErrIntegrity
		}
		total += int64(len(data))
		if total > recorder.MaxDesktopBytes+128 {
			_ = writer.Close()
			return nil, ErrCapacity
		}
		entry, er := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if er == nil {
			_, er = entry.Write(data)
		}
		if er != nil {
			_ = writer.Close()
			return nil, er
		}
	}
	if e = writer.Close(); e != nil {
		return nil, e
	}
	if e = out.Sync(); e != nil {
		return nil, e
	}
	if _, e = out.Seek(0, io.SeekStart); e != nil {
		return nil, e
	}
	success = true
	return result, nil
}

func (s *Store) OpenReplay(ctx context.Context, id string, key []byte) (io.ReadCloser, error) {
	f, e := s.OpenCiphertext(ctx, Ref{Kind: "terminal", SessionID: id})
	if e != nil {
		return nil, e
	}
	return recorder.OpenReplayReader(f, id, key)
}

// DesktopFrame reads one encrypted ZIP entry using a shared, bounded ciphertext
// cache. The broker supplies frame metadata only after its ownership check.
func (s *Store) DesktopFrame(ctx context.Context, id string, frame recorder.DesktopFrame, key []byte) ([]byte, error) {
	ref := Ref{Kind: "desktop", SessionID: id}
	record, _, e := s.snapshot(ref)
	if e != nil {
		return nil, e
	}
	f, e := s.OpenCiphertext(ctx, ref)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	reader, ok := f.(io.ReaderAt)
	if !ok {
		return nil, ErrUnavailable
	}
	archive, e := zip.NewReader(reader, record.Size)
	if e != nil || len(archive.File) > recorder.MaxDesktopFrames {
		return nil, ErrIntegrity
	}
	name := fmt.Sprintf("%06d.png.enc", frame.Index)
	var entry *zip.File
	for _, item := range archive.File {
		if item.Name == name {
			if entry != nil {
				return nil, ErrIntegrity
			}
			entry = item
		}
	}
	if entry == nil || entry.Method != zip.Store || entry.UncompressedSize64 > (40<<20)+128 {
		return nil, ErrIntegrity
	}
	input, e := entry.Open()
	if e != nil {
		return nil, ErrIntegrity
	}
	defer input.Close()
	data, e := io.ReadAll(io.LimitReader(input, (40<<20)+129))
	if e != nil {
		return nil, ErrIntegrity
	}
	return recorder.DecodeDesktopFrame(id, key, frame, data)
}
