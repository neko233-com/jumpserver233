package recorder

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	recordingMagic = "JMSREC1\n"
	maxFrameSize   = 16 << 20
)

// Asciinema writes an asciinema v2 gzip stream encrypted at rest with a
// session-specific key derived from the local credential-vault key.
type Asciinema struct {
	mu      sync.Mutex
	file    *os.File
	aead    cipher.AEAD
	session string
	started time.Time
	closed  bool
}

type header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env"`
}

// NewAsciinema creates an encrypted replay file. OpenReplay returns decrypted
// asciinema text; the authorized HTTP endpoint applies transport gzip.
func NewAsciinema(path, sessionID, assetID string, cols, rows int, started time.Time, vaultKey []byte, watermark ...string) (*Asciinema, error) {
	if cols < 2 || cols > 500 || rows < 2 || rows > 500 {
		return nil, fmt.Errorf("recording terminal dimensions must be between 2 and 500")
	}
	aead, err := newSessionAEAD(vaultKey, sessionID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create recording directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create session recording: %w", err)
	}
	recording := &Asciinema{file: file, aead: aead, session: sessionID, started: started}
	if _, err := file.WriteString(recordingMagic); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write session recording marker: %w", err)
	}
	value := header{
		Version:   2,
		Width:     cols,
		Height:    rows,
		Timestamp: started.Unix(),
		Env: map[string]string{
			"TERM":           "xterm-256color",
			"SHELL":          "ssh",
			"JMS_SESSION_ID": sessionID,
			"JMS_ASSET_ID":   assetID,
		},
	}
	if len(watermark) > 0 && watermark[0] != "" {
		value.Env["JMS_WATERMARK"] = watermark[0]
	}
	data, err := json.Marshal(value)
	if err == nil {
		err = recording.writeLine(append(data, '\n'))
	}
	if err != nil {
		_ = recording.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write session recording header: %w", err)
	}
	return recording, nil
}

// Record writes one asciinema v2 input or output event as an authenticated
// encrypted frame. Each event is a gzip member; concatenated members form a
// standard gzip stream and can be replayed by OpenReplay.
func (r *Asciinema) Record(direction byte, data []byte) error {
	if direction != 'i' && direction != 'o' {
		return fmt.Errorf("recording direction must be input or output")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	event := [3]any{time.Since(r.started).Seconds(), string(direction), string(data)}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode session recording event: %w", err)
	}
	return r.writeLine(append(encoded, '\n'))
}

func (r *Asciinema) writeLine(line []byte) error {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Header.ModTime = time.Time{}
	if _, err := gz.Write(line); err != nil {
		_ = gz.Close()
		return fmt.Errorf("compress session recording frame: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("finish compressed session recording frame: %w", err)
	}
	if compressed.Len() > maxFrameSize {
		return fmt.Errorf("session recording frame exceeds size limit")
	}
	nonce := make([]byte, r.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate session recording nonce: %w", err)
	}
	ciphertext := r.aead.Seal(nil, nonce, compressed.Bytes(), []byte(r.session))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(ciphertext)))
	if err := writeAll(r.file, length[:]); err != nil {
		return fmt.Errorf("write session recording frame length: %w", err)
	}
	if err := writeAll(r.file, nonce); err != nil {
		return fmt.Errorf("write session recording nonce: %w", err)
	}
	if err := writeAll(r.file, ciphertext); err != nil {
		return fmt.Errorf("write encrypted session recording frame: %w", err)
	}
	return nil
}

func (r *Asciinema) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var result error
	if err := r.file.Sync(); err != nil {
		result = errors.Join(result, fmt.Errorf("sync session recording: %w", err))
	}
	if err := r.file.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close session recording: %w", err))
	}
	return result
}

// OpenReplay decrypts an at-rest recording and returns its asciinema v2 gzip
// stream. Authorization is deliberately left to the caller.
func OpenReplay(path, sessionID string, vaultKey []byte) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open session recording: %w", err)
	}
	marker := make([]byte, len(recordingMagic))
	if _, err := io.ReadFull(file, marker); err != nil || string(marker) != recordingMagic {
		_ = file.Close()
		return nil, fmt.Errorf("session recording has an unsupported format")
	}
	aead, err := newSessionAEAD(vaultKey, sessionID)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	reader := &encryptedReader{file: file, aead: aead, session: sessionID}
	gz, err := gzip.NewReader(reader)
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("open asciinema replay stream: %w", err)
	}
	return &replayReadCloser{gzip: gz, file: file}, nil
}

type replayReadCloser struct {
	gzip *gzip.Reader
	file *os.File
}

func (r *replayReadCloser) Read(p []byte) (int, error) { return r.gzip.Read(p) }

func (r *replayReadCloser) Close() error {
	return errors.Join(r.gzip.Close(), r.file.Close())
}

type encryptedReader struct {
	file    io.Reader
	aead    cipher.AEAD
	session string
	frame   []byte
	offset  int
	ended   bool
}

func (r *encryptedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for r.offset >= len(r.frame) {
		if r.ended {
			return 0, io.EOF
		}
		var length [4]byte
		if _, err := io.ReadFull(r.file, length[:]); err != nil {
			if errors.Is(err, io.EOF) {
				r.ended = true
				return 0, io.EOF
			}
			return 0, fmt.Errorf("read session recording frame: %w", err)
		}
		cipherLength := binary.BigEndian.Uint32(length[:])
		if cipherLength < uint32(r.aead.Overhead()) || cipherLength > maxFrameSize {
			return 0, fmt.Errorf("session recording frame length is invalid")
		}
		nonce := make([]byte, r.aead.NonceSize())
		if _, err := io.ReadFull(r.file, nonce); err != nil {
			return 0, fmt.Errorf("read session recording nonce: %w", err)
		}
		ciphertext := make([]byte, cipherLength)
		if _, err := io.ReadFull(r.file, ciphertext); err != nil {
			return 0, fmt.Errorf("read encrypted session recording frame: %w", err)
		}
		plaintext, err := r.aead.Open(nil, nonce, ciphertext, []byte(r.session))
		if err != nil {
			return 0, fmt.Errorf("authenticate session recording frame: %w", err)
		}
		r.frame = plaintext
		r.offset = 0
	}
	count := copy(p, r.frame[r.offset:])
	r.offset += count
	return count, nil
}

func newSessionAEAD(vaultKey []byte, sessionID string) (cipher.AEAD, error) {
	if len(vaultKey) != 32 || sessionID == "" {
		return nil, fmt.Errorf("a 32-byte vault key and session ID are required for recordings")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("jumpserver233/asciinema-recording/v1\x00"))
	_, _ = hash.Write(vaultKey)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(sessionID))
	block, err := aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("create session recording cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create session recording AEAD: %w", err)
	}
	return aead, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}
