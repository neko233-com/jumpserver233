package replayarchive

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/replaystore"
)

type cacheEntry struct {
	path  string
	size  int64
	refs  int
	used  time.Time
	ready chan struct{}
	err   error
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

type cachedReader struct {
	*os.File
	once    sync.Once
	release func()
}

func (r *cachedReader) Close() error {
	var e error
	r.once.Do(func() { e = r.File.Close(); r.release() })
	return e
}
func (c *cipherCache) remove(key string, e *cacheEntry) {
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
			e.used = time.Now()
			c.mu.Unlock()
			return &cachedReader{File: f, release: func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				e.refs--
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
		if e.ready == nil && e.refs == 0 {
			c.remove(key, e)
		}
	}
}
