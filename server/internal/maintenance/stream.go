package maintenance

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/scrypt"
)

const magic = "JMS233BK1\n"
const chunkSize = 1 << 20
const headerSize = len(magic) + 16 + 8

// Frames authenticate the immutable format header, sequence number and length.
// A final authenticated empty frame and physical EOF reject truncation, replay,
// reordering and appended data. Every backup uses a fresh salt and nonce prefix.
type encryptedWriter struct {
	out    io.Writer
	aead   cipher.AEAD
	header []byte
	seq    uint64
	buffer []byte
	closed bool
}

func newEncryptedWriter(out io.Writer, password []byte) (*encryptedWriter, error) {
	if len(password) < 12 || len(password) > 1024 {
		return nil, ErrInvalid
	}
	h := make([]byte, headerSize)
	copy(h, magic)
	if _, e := rand.Read(h[len(magic):]); e != nil {
		return nil, e
	}
	a, e := backupCipher(password, h)
	if e != nil {
		return nil, e
	}
	if e = writeAll(out, h); e != nil {
		return nil, e
	}
	return &encryptedWriter{out: out, aead: a, header: h, buffer: make([]byte, 0, chunkSize)}, nil
}
func backupCipher(password, header []byte) (cipher.AEAD, error) {
	key, e := scrypt.Key(password, header[len(magic):len(magic)+16], 32768, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func frameAuth(header []byte, seq uint64, length uint32) ([]byte, []byte, error) {
	if seq > 0xffffffff {
		return nil, nil, ErrInvalid
	}
	nonce := make([]byte, 12)
	copy(nonce, header[len(magic)+16:])
	binary.BigEndian.PutUint32(nonce[8:], uint32(seq))
	aad := append([]byte{}, header...)
	aad = binary.BigEndian.AppendUint32(aad, uint32(seq))
	aad = binary.BigEndian.AppendUint32(aad, length)
	return nonce, aad, nil
}
func (w *encryptedWriter) frame(data []byte) error {
	nonce, aad, e := frameAuth(w.header, w.seq, uint32(len(data)))
	if e != nil {
		return e
	}
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	frame = w.aead.Seal(frame, nonce, data, aad)
	e = writeAll(w.out, frame)
	w.seq++
	return e
}
func (w *encryptedWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), chunkSize-len(w.buffer))
		w.buffer = append(w.buffer, p[:n]...)
		p = p[n:]
		total += n
		if len(w.buffer) == chunkSize {
			if e := w.frame(w.buffer); e != nil {
				return total, e
			}
			clear(w.buffer)
			w.buffer = w.buffer[:0]
		}
	}
	return total, nil
}
func (w *encryptedWriter) Close() error {
	if w.closed {
		return io.ErrClosedPipe
	}
	w.closed = true
	defer clear(w.buffer)
	if len(w.buffer) > 0 {
		if e := w.frame(w.buffer); e != nil {
			return e
		}
	}
	return w.frame(nil)
}

type encryptedReader struct {
	in     io.Reader
	aead   cipher.AEAD
	header []byte
	seq    uint64
	buffer []byte
	final  bool
}

func (r *encryptedReader) ReadByte() (byte, error) {
	var b [1]byte
	_, e := r.Read(b[:])
	return b[0], e
}
func newEncryptedReader(in io.Reader, password []byte) (*encryptedReader, error) {
	if len(password) < 12 || len(password) > 1024 {
		return nil, ErrInvalid
	}
	h := make([]byte, headerSize)
	if _, e := io.ReadFull(in, h); e != nil || !bytes.Equal(h[:len(magic)], []byte(magic)) {
		return nil, ErrIntegrity
	}
	a, e := backupCipher(password, h)
	if e != nil {
		return nil, e
	}
	return &encryptedReader{in: in, aead: a, header: h}, nil
}
func (r *encryptedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.buffer) > 0 {
		n := copy(p, r.buffer)
		clear(r.buffer[:n])
		r.buffer = r.buffer[n:]
		return n, nil
	}
	if r.final {
		return 0, io.EOF
	}
	var length [4]byte
	if _, e := io.ReadFull(r.in, length[:]); e != nil {
		return 0, ErrIntegrity
	}
	n := binary.BigEndian.Uint32(length[:])
	if n > chunkSize {
		return 0, ErrIntegrity
	}
	sealed := make([]byte, int(n)+r.aead.Overhead())
	if _, e := io.ReadFull(r.in, sealed); e != nil {
		return 0, ErrIntegrity
	}
	nonce, aad, e := frameAuth(r.header, r.seq, n)
	if e != nil {
		return 0, ErrIntegrity
	}
	r.seq++
	data, e := r.aead.Open(sealed[:0], nonce, sealed, aad)
	if e != nil {
		return 0, ErrIntegrity
	}
	if n == 0 {
		var extra [1]byte
		count, e := r.in.Read(extra[:])
		if count != 0 || e != io.EOF {
			return 0, ErrIntegrity
		}
		r.final = true
		return 0, io.EOF
	}
	r.buffer = data
	return r.Read(p)
}
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(data)) > limit {
		return nil, ErrInvalid
	}
	return data, nil
}
func writeAll(w io.Writer, body []byte) error {
	n, e := w.Write(body)
	if e == nil && n != len(body) {
		return io.ErrShortWrite
	}
	return e
}
