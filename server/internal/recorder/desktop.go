package recorder

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const MaxDesktopBytes = 256 << 20
const MaxDesktopFrames = 14400

type DesktopFrame struct {
	Index    int    `json:"index"`
	AtMS     int64  `json:"at_ms"`
	Sequence uint64 `json:"sequence"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
}
type Desktop struct {
	directory, session string
	aead               cipher.AEAD
	bytes              int64
}

func NewDesktop(directory, id string, key []byte) (*Desktop, error) {
	a, e := newSessionAEAD(key, "desktop:"+id)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(directory, 0700); e != nil {
		return nil, e
	}
	return &Desktop{directory: directory, session: id, aead: a}, nil
}
func (d *Desktop) Record(frame DesktopFrame, png []byte) error {
	if frame.Index < 0 || frame.Index >= MaxDesktopFrames || frame.AtMS < 0 || frame.Width < 1 || frame.Height < 1 || len(png) < 8 || len(png) > 40<<20 || d.bytes+int64(len(png)) > MaxDesktopBytes {
		return errors.New("desktop recording limit reached")
	}
	aad, _ := json.Marshal(frame)
	nonce := make([]byte, d.aead.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return e
	}
	encrypted := d.aead.Seal(nonce, nonce, png, append([]byte(d.session+":"), aad...))
	file, e := os.OpenFile(filepath.Join(d.directory, fmt.Sprintf("%06d.png.enc", frame.Index)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = file.Write(encrypted)
	if e == nil {
		e = file.Sync()
	}
	closeErr := file.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	d.bytes += int64(len(encrypted))
	return nil
}
func (d *Desktop) Read(frame DesktopFrame) ([]byte, error) {
	if frame.Index < 0 || frame.Index >= MaxDesktopFrames {
		return nil, os.ErrNotExist
	}
	file, e := os.Open(filepath.Join(d.directory, fmt.Sprintf("%06d.png.enc", frame.Index)))
	if e != nil {
		return nil, e
	}
	defer file.Close()
	data, e := io.ReadAll(io.LimitReader(file, (40<<20)+1024))
	if e != nil || len(data) < d.aead.NonceSize()+d.aead.Overhead() || len(data) > (40<<20)+128 {
		return nil, errors.New("invalid desktop frame")
	}
	aad, _ := json.Marshal(frame)
	return d.aead.Open(nil, data[:d.aead.NonceSize()], data[d.aead.NonceSize():], append([]byte(d.session+":"), aad...))
}
