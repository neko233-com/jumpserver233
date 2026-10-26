// Package runtimelog bounds operational logs independently of business audit data.
package runtimelog

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"sync"
	"time"
)

var ErrConflict = errors.New("runtime log revision changed")
var ErrInvalid = errors.New("invalid runtime log request")
var archiveName = regexp.MustCompile(`^server-[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[a-f0-9]{16}\.log$`)

type Options struct {
	Dir      string
	MaxBytes int64
	Backups  int
	Days     int
}

type Snapshot struct {
	Instance         string    `json:"instance"`
	Revision         int       `json:"revision"`
	MaxBytes         int64     `json:"max_bytes"`
	MaxBackups       int       `json:"max_backups"`
	MaxAgeDays       int       `json:"max_age_days"`
	CurrentBytes     int64     `json:"current_bytes"`
	TotalBytes       int64     `json:"total_bytes"`
	Backups          int       `json:"backups"`
	LastRotation     time.Time `json:"last_rotation"`
	ErrorCode        string    `json:"error_code,omitempty"`
	TruncatedRecords uint64    `json:"truncated_records"`
}

type Input struct {
	Instance  string `json:"instance"`
	Revision  int    `json:"revision"`
	RequestID string `json:"request_id"`
}

type Writer struct {
	mu             sync.Mutex
	opts           Options
	file           *os.File
	state          Snapshot
	day            string
	now            func() time.Time
	seen           map[string]bool
	order          []string
	stop           chan struct{}
	done           chan struct{}
	closed         bool
	captureCrashes bool
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b[:])
}

func Open(opts Options) (*Writer, error) {
	if opts.Dir == "" || opts.MaxBytes < 128 || opts.Backups < 1 || opts.Backups > 30 || opts.Days < 1 || opts.Days > 365 {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(opts.Dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(opts.Dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalid
	}
	if err = os.Chmod(opts.Dir, 0700); err != nil {
		return nil, err
	}
	w := &Writer{opts: opts, now: time.Now, seen: map[string]bool{}, stop: make(chan struct{}), done: make(chan struct{})}
	w.state = Snapshot{Instance: randomID(), Revision: 1, MaxBytes: opts.MaxBytes, MaxBackups: opts.Backups, MaxAgeDays: opts.Days}
	if err = w.openCurrent(); err != nil {
		return nil, err
	}
	w.day = info.ModTime().UTC().Format("2006-01-02")
	if stat, e := w.file.Stat(); e == nil {
		w.day = stat.ModTime().UTC().Format("2006-01-02")
	}
	if w.state.CurrentBytes >= opts.MaxBytes || w.state.CurrentBytes > 0 && w.day != w.now().UTC().Format("2006-01-02") {
		err = w.rotate()
	} else {
		err = w.prune()
	}
	if err != nil {
		if w.file != nil {
			w.file.Close()
		}
		return nil, err
	}
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-w.stop:
				return
			case <-ticker.C:
				w.mu.Lock()
				if !w.closed {
					var e error
					if w.file == nil {
						e = w.openCurrent()
					}
					if e == nil {
						e = w.maintain()
					}
					w.recordError(e)
				}
				w.mu.Unlock()
			}
		}
	}()
	return w, nil
}

func (w *Writer) openCurrent() error {
	p := filepath.Join(w.opts.Dir, "server.log")
	if info, e := os.Lstat(p); e == nil && !info.Mode().IsRegular() {
		return ErrInvalid
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	stat, err := f.Stat()
	named, ne := os.Lstat(p)
	if err != nil || ne != nil || !named.Mode().IsRegular() || !os.SameFile(stat, named) {
		f.Close()
		return ErrInvalid
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.state.CurrentBytes = stat.Size()
	if w.captureCrashes {
		return debug.SetCrashOutput(f, debug.CrashOptions{})
	}
	return nil
}

// CaptureCrashes keeps fatal Go runtime output in the current operational file.
// The runtime duplicates the descriptor; every rotation replaces that duplicate.
func (w *Writer) CaptureCrashes() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return os.ErrClosed
	}
	if err := debug.SetCrashOutput(w.file, debug.CrashOptions{}); err != nil {
		return err
	}
	w.captureCrashes = true
	return nil
}

type archive struct {
	name string
	size int64
	at   time.Time
}

func (w *Writer) archives() ([]archive, error) {
	entries, err := os.ReadDir(w.opts.Dir)
	if err != nil {
		return nil, err
	}
	var out []archive
	for _, e := range entries {
		if !archiveName.MatchString(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		out = append(out, archive{e.Name(), info.Size(), info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name > out[j].name })
	return out, nil
}

func (w *Writer) prune() error {
	files, err := w.archives()
	if err != nil {
		return err
	}
	w.state.TotalBytes, w.state.Backups = w.state.CurrentBytes, 0
	for i, f := range files {
		if i >= w.opts.Backups || f.at.Before(w.now().Add(-time.Duration(w.opts.Days)*24*time.Hour)) {
			if err := os.Remove(filepath.Join(w.opts.Dir, f.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		w.state.TotalBytes += f.size
		w.state.Backups++
	}
	return nil
}

func (w *Writer) recordError(err error) {
	if err != nil {
		w.state.ErrorCode = "log_io_failed"
	} else {
		w.state.ErrorCode = ""
	}
}

func (w *Writer) rotate() error {
	if w.file == nil {
		if err := w.openCurrent(); err != nil {
			return err
		}
	}
	if w.state.CurrentBytes == 0 {
		return w.prune()
	}
	if err := w.file.Sync(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	name := "server-" + w.now().UTC().Format("20060102T150405.000000000Z") + "-" + randomID() + ".log"
	err := os.Rename(filepath.Join(w.opts.Dir, "server.log"), filepath.Join(w.opts.Dir, name))
	if err != nil {
		// Reopen the original file so a transient rename error does not poison the writer.
		_ = w.openCurrent()
		return err
	}
	if err = w.openCurrent(); err != nil {
		return err
	}
	w.day = w.now().UTC().Format("2006-01-02")
	w.state.Revision++
	w.state.LastRotation = w.now().UTC()
	return w.prune()
}

func (w *Writer) maintain() error {
	if w.state.CurrentBytes > 0 && w.day != w.now().UTC().Format("2006-01-02") {
		return w.rotate()
	}
	return w.prune()
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.file == nil {
		if err := w.openCurrent(); err != nil {
			w.recordError(err)
			return 0, err
		}
	}
	original := len(p)
	if int64(len(p)) > w.opts.MaxBytes {
		const suffix = " [record truncated]\n"
		p = append(append([]byte{}, p[:w.opts.MaxBytes-int64(len(suffix))]...), suffix...)
		w.state.TruncatedRecords++
	}
	var err error
	if w.state.CurrentBytes > 0 && (w.state.CurrentBytes+int64(len(p)) > w.opts.MaxBytes || w.day != w.now().UTC().Format("2006-01-02")) {
		err = w.rotate()
	}
	if err == nil {
		var n int
		n, err = w.file.Write(p)
		w.state.CurrentBytes += int64(n)
		w.state.TotalBytes += int64(n)
		if err == nil && n != len(p) {
			err = io.ErrShortWrite
		}
	}
	w.recordError(err)
	if err != nil {
		return 0, err
	}
	return original, nil
}

func (w *Writer) Snapshot() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

func (w *Writer) Rotate(in Input) (Snapshot, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if in.Instance != w.state.Instance {
		return w.state, ErrConflict
	}
	if len(in.RequestID) < 8 || len(in.RequestID) > 128 {
		return w.state, ErrInvalid
	}
	if w.seen[in.RequestID] {
		return w.state, nil
	}
	if in.Revision != w.state.Revision {
		return w.state, ErrConflict
	}
	if w.closed {
		return w.state, os.ErrClosed
	}
	err := w.rotate()
	w.recordError(err)
	if err == nil {
		w.seen[in.RequestID] = true
		w.order = append(w.order, in.RequestID)
		if len(w.order) > 128 {
			delete(w.seen, w.order[0])
			w.order = w.order[1:]
		}
	}
	return w.state, err
}

func (w *Writer) Close() error {
	w.mu.Lock()
	select {
	case <-w.stop:
		w.mu.Unlock()
		<-w.done
		return nil
	default:
		close(w.stop)
	}
	w.closed = true
	var err error
	if w.captureCrashes {
		err = debug.SetCrashOutput(nil, debug.CrashOptions{})
	}
	if w.file != nil {
		err = errors.Join(w.file.Sync(), w.file.Close())
		w.file = nil
	}
	w.mu.Unlock()
	<-w.done
	return err
}
