package branding

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/storage"
)

type Audit struct {
	At      time.Time `json:"at"`
	ActorID string    `json:"actor_id"`
	Actor   string    `json:"actor"`
	Before  Settings  `json:"before"`
	After   Settings  `json:"after"`
}
type state struct {
	Version    int      `json:"version"`
	Settings   Settings `json:"settings"`
	Logo       []byte   `json:"logo,omitempty"`
	Icon       []byte   `json:"icon,omitempty"`
	Mark       []byte   `json:"mark,omitempty"`
	LoginImage []byte   `json:"login_image,omitempty"`
	Audit      []Audit  `json:"audit"`
}
type Store struct {
	mu           sync.RWMutex
	path         string
	docs         *storage.Documents
	data         state
	saveHook     func([]byte) error
	reloadNeeded bool
}

func Open(path string, docs *storage.Documents) (*Store, error) {
	s := &Store{path: path, docs: docs, data: state{Version: 1, Settings: Defaults(), Audit: []Audit{}}}
	var data []byte
	var err error
	if docs != nil {
		data, err = docs.LoadOrImport("branding", path)
	} else {
		f, e := os.Open(path)
		if errors.Is(e, os.ErrNotExist) {
			return s, nil
		}
		if e != nil {
			return nil, e
		}
		defer f.Close()
		data, err = io.ReadAll(io.LimitReader(f, MaxStateBytes+1))
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return s, nil
	}
	if len(data) > MaxStateBytes {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s.data) != nil || decoder.Decode(new(any)) != io.EOF || s.data.Version != 1 || s.data.Settings.validate() != nil || len(s.data.Audit) > 200 || imageDigest(s.data.Logo) != s.data.Settings.LogoDigest || imageDigest(s.data.Icon) != s.data.Settings.IconDigest {
		return nil, ErrInvalid
	}
	if imageDigest(s.data.Mark) != s.data.Settings.MarkDigest || imageDigest(s.data.LoginImage) != s.data.Settings.LoginDigest {
		return nil, ErrInvalid
	}
	for _, slot := range []struct {
		data []byte
		icon bool
	}{{s.data.Logo, false}, {s.data.Icon, true}, {s.data.Mark, true}} {
		if len(slot.data) > 0 && !bytes.HasPrefix(slot.data, []byte("\x89PNG\r\n\x1a\n")) {
			return nil, ErrImage
		}
		if _, e := PrepareImage(slot.data, slot.icon); e != nil {
			return nil, e
		}
	}
	if len(s.data.LoginImage) > 0 && !bytes.HasPrefix(s.data.LoginImage, []byte("\x89PNG\r\n\x1a\n")) {
		return nil, ErrImage
	}
	if _, e := PrepareLoginImage(s.data.LoginImage); e != nil {
		return nil, e
	}
	for _, a := range s.data.Audit {
		if a.At.IsZero() || !validText(a.ActorID, 128) || !validText(a.Actor, 128) || a.Before.validate() != nil || a.After.validate() != nil || a.After.Revision != a.Before.Revision+1 || a.After.Revision > s.data.Settings.Revision {
			return nil, ErrInvalid
		}
	}
	return s, nil
}

// Refresh reconciles a shared write whose acknowledgement may have been lost.
func (s *Store) Refresh() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshLocked()
}
func (s *Store) refreshLocked() error {
	if !s.reloadNeeded {
		return nil
	}
	next, err := Open(s.path, s.docs)
	if err != nil {
		return err
	}
	s.data = next.data
	s.reloadNeeded = false
	return nil
}
func (s *Store) Snapshot() Public {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Settings.Public()
}
func (s *Store) Image(digest string) ([]byte, bool) {
	if !digestPattern.MatchString(digest) {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var data []byte
	if digest == s.data.Settings.LogoDigest {
		data = s.data.Logo
	} else if digest == s.data.Settings.IconDigest {
		data = s.data.Icon
	} else if digest == s.data.Settings.MarkDigest {
		data = s.data.Mark
	} else if digest == s.data.Settings.LoginDigest {
		data = s.data.LoginImage
	} else {
		return nil, false
	}
	return append([]byte{}, data...), true
}
func (s *Store) Audit(offset, limit int) ([]Audit, int, error) {
	if offset < 0 || offset > 100000 || limit < 1 || limit > 100 {
		return nil, 0, ErrInvalid
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Audit{}
	for i := len(s.data.Audit) - 1 - offset; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.data.Audit[i])
	}
	return out, len(s.data.Audit), nil
}
func (s *Store) Save(in Input, actorID, actor string) (Public, error) {
	in, e := Prepare(in)
	if e != nil {
		return Public{}, e
	}
	desired := in.settings()
	if !validText(actorID, 128) || !validText(actor, 128) {
		return Public{}, ErrInvalid
	}
	var logo, icon, mark, loginImage []byte
	if in.Logo != nil {
		logo = *in.Logo
	}
	if in.Icon != nil {
		icon = *in.Icon
	}
	if in.Mark != nil {
		mark = *in.Mark
	}
	if in.LoginImage != nil {
		loginImage = *in.LoginImage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e = s.refreshLocked(); e != nil {
		return Public{}, e
	}
	before := s.data.Settings
	if in.Logo == nil {
		logo = s.data.Logo
	}
	if in.Icon == nil {
		icon = s.data.Icon
	}
	if in.Mark == nil {
		mark = s.data.Mark
	}
	if in.LoginImage == nil {
		loginImage = s.data.LoginImage
	}
	desired.LogoDigest = imageDigest(logo)
	desired.IconDigest = imageDigest(icon)
	desired.MarkDigest = imageDigest(mark)
	desired.LoginDigest = imageDigest(loginImage)
	desired.Revision = before.Revision
	if in.Revision <= before.Revision && desired == before {
		return before.Public(), nil
	}
	if in.Revision != before.Revision {
		return Public{}, ErrConflict
	}
	desired.Revision++
	next := state{Version: 1, Settings: desired, Logo: logo, Icon: icon, Mark: mark, LoginImage: loginImage, Audit: append([]Audit{}, s.data.Audit...)}
	next.Audit = append(next.Audit, Audit{time.Now().UTC(), actorID, actor, before, desired})
	if len(next.Audit) > 200 {
		next.Audit = next.Audit[len(next.Audit)-200:]
	}
	data, e := json.Marshal(next)
	if e != nil {
		return Public{}, e
	}
	if len(data) > MaxStateBytes {
		return Public{}, ErrInvalid
	}
	if s.saveHook != nil {
		if e = s.saveHook(data); e != nil {
			return Public{}, e
		}
	}
	if s.docs != nil {
		e = s.docs.Save("branding", data)
	} else {
		e = atomicWrite(s.path, data)
	}
	if e != nil {
		if s.docs != nil {
			s.reloadNeeded = true
		}
		return Public{}, e
	}
	s.data = next
	return desired.Public(), nil
}
func atomicWrite(path string, data []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".branding-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeError := f.Close()
	if e != nil {
		return e
	}
	if closeError != nil {
		return closeError
	}
	return os.Rename(f.Name(), path)
}
