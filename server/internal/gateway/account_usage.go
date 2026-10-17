package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// AccountUsage reads only audit metadata, with one bounded-memory pass. The
// snapshot length is captured under the append lock; parsing does not block PTY
// audit writes. A corrupt/truncated snapshot aborts a risk scan.
func (b *Broker) AccountUsage(ctx context.Context, wanted map[string]bool) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	b.auditMu.Lock()
	file, e := os.Open(b.auditPath)
	var size int64
	if e == nil {
		var stat os.FileInfo
		stat, e = file.Stat()
		if e == nil {
			size = stat.Size()
		}
	}
	b.auditMu.Unlock()
	if errors.Is(e, os.ErrNotExist) {
		return out, nil
	}
	if e != nil {
		if file != nil {
			file.Close()
		}
		return nil, e
	}
	defer file.Close()
	reader := io.NewSectionReader(file, 0, size)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var bytes int64
	for scanner.Scan() {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		raw := scanner.Bytes()
		bytes += int64(len(raw)) + 1
		var event struct {
			AssetID string    `json:"asset_id"`
			Event   string    `json:"event"`
			At      time.Time `json:"at"`
		}
		if json.Unmarshal(raw, &event) != nil || event.Event == "" || event.At.IsZero() {
			return nil, errors.New("invalid session usage metadata")
		}
		// Viewer/collaboration events share this journal and intentionally omit an
		// asset ID. Only actual session lifecycle events prove remote account use.
		if event.Event == "started" || event.Event == "ended" {
			if event.AssetID == "" {
				return nil, errors.New("invalid session usage metadata")
			}
			if wanted[event.AssetID] && event.At.After(out[event.AssetID]) {
				out[event.AssetID] = event.At
			}
		}
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	if bytes != size {
		return nil, errors.New("incomplete session usage metadata")
	}
	now := time.Now().UTC()
	b.mu.Lock()
	for _, v := range b.sessions {
		if wanted[v.asset.ID] {
			out[v.asset.ID] = now
		}
	}
	b.mu.Unlock()
	return out, nil
}
