package replayarchive

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
)

type cacheEntry struct {
	path    string
	size    int64
	refs    int
	readers map[*os.File]bool
	used    time.Time
	ready   chan struct{}
	err     error
}
type cipherCache struct {
	mu      sync.Mutex
	root    string
	entries map[string]*cacheEntry
	bytes   int64
	closed  bool
}

func newCipherCache(root string) *cipherCache {
	return &cipherCache{root: root, entries: map[string]*cacheEntry{}}
}

var cacheTemporaryName = regexp.MustCompile(`^\.replay-(cipher|pack)-[0-9]+$`)

// Only Start under the installation's active-owner gate calls this cleanup.
// Opening a store for offline preflight/backup never removes cached files.
func (c *cipherCache) cleanStale() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if len(c.entries) > 0 {
		return nil
	}
	info, e := os.Lstat(c.root)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	entries, e := os.ReadDir(c.root)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if !cacheTemporaryName.MatchString(entry.Name()) {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return ErrInvalid
		}
		if e = os.Remove(filepath.Join(c.root, entry.Name())); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}

type cachedReader struct {
	*os.File
	once    sync.Once
	release func()
}

func (r *cachedReader) Close() error {
	var e error
	r.once.Do(func() {
		e = r.File.Close()
		if errors.Is(e, os.ErrClosed) {
			e = nil
		}
		r.release()
	})
	return e
}
func (c *cipherCache) remove(key string, e *cacheEntry) {
	if c.entries[key] != e {
		return
	}
	delete(c.entries, key)
	c.bytes -= e.size
	_ = os.Remove(e.path)
}
func (c *cipherCache) open(ctx context.Context, key string, size int64, load func(context.Context, io.Writer) error) (SeekCloser, error) {
	if size < 1 || size > replaystore.MaxObjectBytes {
		return nil, ErrIntegrity
	}
	for {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, ErrClosed
		}
		if e, ok := c.entries[key]; ok {
			if e.ready != nil {
				ready := e.ready
				c.mu.Unlock()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-ready:
				}
				if e.err != nil {
					return nil, e.err
				}
				continue
			}
			f, err := os.Open(e.path)
			if err != nil {
				if e.refs == 0 {
					c.remove(key, e)
				}
				c.mu.Unlock()
				return nil, ErrUnavailable
			}
			e.refs++
			if e.readers == nil {
				e.readers = map[*os.File]bool{}
			}
			e.readers[f] = true
			e.used = time.Now()
			c.mu.Unlock()
			return &cachedReader{File: f, release: func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				e.refs--
				delete(e.readers, f)
				if c.closed && e.refs == 0 {
					c.remove(key, e)
				}
			}}, nil
		}
		// Bound both ciphertext bytes and file count. Active leases and in-flight
		// downloads are never removed to make room for another request.
		for c.bytes+size > replaystore.MaxObjectBytes || len(c.entries) >= 4 {
			var oldestKey string
			var oldest *cacheEntry
			for k, e := range c.entries {
				if e.ready == nil && e.refs == 0 && (oldest == nil || e.used.Before(oldest.used)) {
					oldestKey, oldest = k, e
				}
			}
			if oldest == nil {
				c.mu.Unlock()
				return nil, ErrCapacity
			}
			c.remove(oldestKey, oldest)
		}
		e := &cacheEntry{size: size, ready: make(chan struct{}), used: time.Now()}
		c.entries[key] = e
		c.bytes += size
		c.mu.Unlock()
		err := os.MkdirAll(c.root, 0700)
		var f *os.File
		if err == nil {
			f, err = os.CreateTemp(c.root, ".replay-cipher-*")
		}
		if err == nil {
			e.path = f.Name()
			err = f.Chmod(0600)
			if err == nil {
				err = load(ctx, f)
			}
			if err == nil {
				err = f.Sync()
			}
			ce := f.Close()
			if err == nil {
				err = ce
			}
		}
		c.mu.Lock()
		if c.closed && err == nil {
			err = ErrClosed
		}
		e.err = err
		ready := e.ready
		e.ready = nil
		if err != nil {
			c.remove(key, e)
		}
		close(ready)
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
}
func (c *cipherCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for key, e := range c.entries {
		if e.ready == nil {
			for f := range e.readers {
				_ = f.Close()
			}
			c.remove(key, e)
		}
	}
}
