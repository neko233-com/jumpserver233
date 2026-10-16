package files

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Transfer struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	AssetID   string    `json:"asset_id"`
	Action    string    `json:"action"`
	Path      string    `json:"path"`
	Bytes     int64     `json:"bytes"`
	Success   bool      `json:"success"`
	ErrorCode string    `json:"error_code,omitempty"`
	At        time.Time `json:"at"`
}

type AuditStore struct {
	mu   sync.Mutex
	path string
}

func OpenAuditStore(filePath string) (*AuditStore, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return nil, fmt.Errorf("create file-transfer audit directory: %w", err)
	}
	return &AuditStore{path: filePath}, nil
}

func (s *AuditStore) Append(entry Transfer) error {
	if entry.ID == "" {
		var id [12]byte
		if _, err := rand.Read(id[:]); err != nil {
			return fmt.Errorf("generate file-transfer audit ID: %w", err)
		}
		entry.ID = hex.EncodeToString(id[:])
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open file-transfer audit index: %w", err)
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("append file-transfer audit index: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync file-transfer audit index: %w", err)
	}
	return file.Close()
}

func (s *AuditStore) List(actor string, offset, limit int) ([]Transfer, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return []Transfer{}, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("open file-transfer audit index: %w", err)
	}
	defer file.Close()
	entries := make([]Transfer, 0)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var entry Transfer
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			return nil, 0, fmt.Errorf("decode file-transfer audit index: %w", err)
		}
		if actor == "" || entry.Actor == actor {
			entries = append(entries, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("read file-transfer audit index: %w", err)
	}
	total := len(entries)
	for left, right := 0, len(entries)-1; left < right; left, right = left+1, right-1 {
		entries[left], entries[right] = entries[right], entries[left]
	}
	if offset >= len(entries) {
		return []Transfer{}, total, nil
	}
	end := offset + limit
	if end > len(entries) {
		end = len(entries)
	}
	return entries[offset:end], total, nil
}
