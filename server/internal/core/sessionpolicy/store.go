// Package sessionpolicy stores global resource-session security settings.
package sessionpolicy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

var ErrInvalid = errors.New("invalid session security settings")
var ErrConflict = errors.New("session security revision changed")

type Settings struct {
	IdleMinutes int  `json:"idle_minutes"`
	MaxHours    int  `json:"max_hours"`
	Watermark   bool `json:"watermark"`
	Sharing     bool `json:"sharing"`
	Revision    int  `json:"revision"`
}

func Defaults() Settings { return Settings{IdleMinutes: 30, MaxHours: 8, Watermark: true, Revision: 1} }
func (s Settings) valid() bool {
	return s.IdleMinutes >= 0 && s.IdleMinutes <= 1440 && s.MaxHours >= 0 && s.MaxHours <= 168 && s.Revision >= 1
}
func (s Settings) EndReason(started, lastInput, now time.Time) string {
	if s.MaxHours > 0 && !now.Before(started.Add(time.Duration(s.MaxHours)*time.Hour)) {
		return "duration_limit"
	}
	if s.IdleMinutes > 0 && !now.Before(lastInput.Add(time.Duration(s.IdleMinutes)*time.Minute)) {
		return "idle_timeout"
	}
	return ""
}

type Audit struct {
	At      time.Time `json:"at"`
	ActorID string    `json:"actor_id"`
	Actor   string    `json:"actor"`
	Before  Settings  `json:"before"`
	After   Settings  `json:"after"`
}
type state struct {
	Settings Settings `json:"settings"`
	Audit    []Audit  `json:"audit"`
}
type Store struct {
	mu   sync.RWMutex
	path string
	docs *storage.Documents
	data state
}

func Open(path string, docs *storage.Documents) (*Store, error) {
	s := &Store{path: path, docs: docs, data: state{Settings: Defaults(), Audit: []Audit{}}}
	var data []byte
	var err error
	if docs != nil {
		data, err = docs.LoadOrImport("session-security", path)
	} else {
		data, err = os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		if json.Unmarshal(data, &s.data) != nil || !s.data.Settings.valid() || len(s.data.Audit) > 200 {
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func (s *Store) Snapshot() Settings { s.mu.RLock(); defer s.mu.RUnlock(); return s.data.Settings }
func (s *Store) Audit() []Audit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Audit{}, s.data.Audit...)
}
func (s *Store) Save(in Settings, actorID, actor string) (Settings, error) {
	if !in.valid() || strings.TrimSpace(actorID) == "" || len(actorID) > 128 || len(actor) > 128 {
		return Settings{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Revision != s.data.Settings.Revision {
		return Settings{}, ErrConflict
	}
	before := s.data.Settings
	in.Revision++
	next := state{Settings: in, Audit: append([]Audit{}, s.data.Audit...)}
	next.Audit = append(next.Audit, Audit{At: time.Now().UTC(), ActorID: actorID, Actor: actor, Before: before, After: in})
	if len(next.Audit) > 200 {
		next.Audit = next.Audit[len(next.Audit)-200:]
	}
	data, err := json.Marshal(next)
	if err != nil {
		return Settings{}, err
	}
	if s.docs != nil {
		err = s.docs.Save("session-security", data)
	} else {
		err = atomicWrite(s.path, data)
	}
	if err != nil {
		return Settings{}, err
	}
	s.data = next
	return in, nil
}
func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".session-security-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
