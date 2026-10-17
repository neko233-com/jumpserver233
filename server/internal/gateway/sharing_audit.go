package gateway

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/neko233-com/jumpserver233/server/internal/core/sessionshares"
)

func (b *Broker) appendShareAudit(event sessionshares.Event) error {
	if !validSessionID(event.SessionID) {
		return ErrInvalidSessionRequest
	}
	return b.appendAuditFile(filepath.Join(b.dataDir, "sessions", event.SessionID+".shares.jsonl"), event)
}

func (b *Broker) ListShareEvents(id, actorID string, all bool, offset, limit int) ([]sessionshares.Event, int, error) {
	if !validSessionID(id) || offset < 0 || offset > 1000000 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalidSessionRequest
	}
	if !all {
		if e := b.requireSessionOperator(id, actorID); e != nil {
			return nil, 0, e
		}
	}
	f, e := os.Open(filepath.Join(b.dataDir, "sessions", id+".shares.jsonl"))
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return []sessionshares.Event{}, 0, nil
		}
		return nil, 0, e
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	out := []sessionshares.Event{}
	total := 0
	for scan.Scan() {
		var row sessionshares.Event
		if json.Unmarshal(scan.Bytes(), &row) != nil || row.SessionID != id || !strings.HasPrefix(row.Kind, "share_") {
			continue
		}
		total++
	}
	if scan.Err() != nil {
		return nil, 0, scan.Err()
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return nil, 0, e
	}
	scan = bufio.NewScanner(f)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	index := 0
	for scan.Scan() {
		var row sessionshares.Event
		if json.Unmarshal(scan.Bytes(), &row) != nil || row.SessionID != id || !strings.HasPrefix(row.Kind, "share_") {
			continue
		}
		position := total - 1 - index
		index++
		if position >= offset && position < offset+limit {
			out = append(out, row)
		}
	}
	slices.Reverse(out)
	return out, total, scan.Err()
}
