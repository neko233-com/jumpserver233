package desktop

import (
	"context"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/reporting"
	"io"
	"os"
	"path/filepath"
	"time"
)

func (b *Broker) ReportMetadata(ctx context.Context, owner string, all bool, emit func(reporting.Entry) error) error {
	dir, e := os.Open(b.root)
	if e != nil {
		return e
	}
	defer dir.Close()
	b.mu.Lock()
	active := make(map[string]bool, len(b.live))
	for id := range b.live {
		active[id] = true
	}
	b.mu.Unlock()
	var bytesRead int64
	scanned := 0
	for {
		entries, e := dir.ReadDir(128)
		if e != nil && e != io.EOF {
			return e
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
				continue
			}
			scanned++
			if scanned > reporting.MaxEntries {
				return reporting.ErrLimit
			}
			b.indexMu.Lock()
			f, err := os.Open(filepath.Join(b.root, entry.Name(), "index.json"))
			var raw []byte
			if err == nil {
				raw, err = io.ReadAll(io.LimitReader(f, (2<<20)+1))
				_ = f.Close()
			}
			b.indexMu.Unlock()
			if err != nil {
				return err
			}
			bytesRead += int64(len(raw))
			if len(raw) > 2<<20 || bytesRead > 64<<20 {
				return reporting.ErrLimit
			}
			var v struct {
				ID    string    `json:"session_id"`
				Owner string    `json:"operator_id"`
				At    time.Time `json:"started_at"`
				State string    `json:"status"`
			}
			if json.Unmarshal(raw, &v) != nil || v.ID != entry.Name() || v.At.IsZero() {
				return reporting.ErrInvalid
			}
			if !all && (owner == "" || v.Owner != owner) {
				continue
			}
			if v.State == "active" && !active[v.ID] {
				v.State = "interrupted"
			}
			if err = emit(reporting.Entry{At: v.At, State: v.State}); err != nil {
				return err
			}
		}
		if e == io.EOF {
			return nil
		}
	}
}
