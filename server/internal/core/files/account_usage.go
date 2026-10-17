package files

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

func (s *Service) AccountUsage(ctx context.Context, wanted map[string]bool) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if s.audit == nil {
		return out, nil
	}
	s.audit.mu.Lock()
	file, e := os.Open(s.audit.path)
	var size int64
	if e == nil {
		var stat os.FileInfo
		stat, e = file.Stat()
		if e == nil {
			size = stat.Size()
		}
	}
	s.audit.mu.Unlock()
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
	scanner := bufio.NewScanner(io.NewSectionReader(file, 0, size))
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
			At      time.Time `json:"at"`
			Success bool      `json:"success"`
		}
		if json.Unmarshal(raw, &event) != nil || event.AssetID == "" || event.At.IsZero() {
			return nil, errors.New("invalid file usage metadata")
		}
		if wanted[event.AssetID] && event.Success && event.At.After(out[event.AssetID]) {
			out[event.AssetID] = event.At
		}
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	if bytes != size {
		return nil, errors.New("incomplete file usage metadata")
	}
	return out, nil
}
