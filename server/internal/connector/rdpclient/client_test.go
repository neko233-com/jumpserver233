package rdpclient

import (
	"bytes"
	"encoding/binary"
	"github.com/adfnekc/grdp/orders"
	"github.com/adfnekc/grdp/protocol/pdu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"image"
	"net"
	"strings"
	"testing"
)

func TestSettingsAndNoDowngrade(t *testing.T) {
	s, e := Normalize(Settings{})
	require.NoError(t, e)
	assert.Equal(t, "nla", s.Security)
	assert.Equal(t, 1280, s.Width)
	assert.False(t, s.Clipboard)
	for _, v := range []Settings{{Security: "rdp"}, {Width: 9999}, {Height: 1}, {Domain: "x\\y"}, {ServerName: "host:3389"}, {RootCAPEM: "invalid"}} {
		_, e := Normalize(v)
		assert.Error(t, e)
	}
	for _, v := range []string{"", "injected\nvalue", "a\x00b", strings.Repeat("a", 4097)} {
		assert.False(t, ValidCredential(v))
	}
	packet := []byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, 2, 0, 8, 0, 2, 0, 0, 0}
	_, e = readConfirm(bytes.NewReader(packet), 2)
	require.NoError(t, e)
	for _, mode := range []uint32{0, 1, 4, 8} {
		p := append([]byte(nil), packet...)
		binary.LittleEndian.PutUint32(p[15:], mode)
		_, e = readConfirm(bytes.NewReader(p), 2)
		assert.Error(t, e)
	}
	for _, length := range []int{0, 3, 4, 18} {
		_, e = readConfirm(bytes.NewReader(packet[:length]), 2)
		assert.Error(t, e)
	}
	for _, index := range []int{0, 1, 5, 11, 13} {
		p := append([]byte(nil), packet...)
		p[index] ^= 0xff
		_, e = readConfirm(bytes.NewReader(p), 2)
		assert.Error(t, e)
	}
	cfg, e := tlsConfig(Target{Host: "example.invalid", Settings: s})
	require.NoError(t, e)
	assert.False(t, cfg.InsecureSkipVerify)
	assert.GreaterOrEqual(t, int(cfg.MinVersion), 0x303)
}
func newTestClient(t *testing.T) *Client {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return &Client{conn: a, settings: Settings{ReadOnly: true}, done: make(chan struct{}), changed: make(chan struct{}, 1), first: make(chan struct{}), image: image.NewRGBA(image.Rect(0, 0, 320, 200)), screen: orders.NewScreen(320, 200)}
}
func TestRenderBoundsSnapshotAndReadOnly(t *testing.T) {
	c := newTestClient(t)
	_, e := c.Snapshot()
	require.Error(t, e)
	require.NoError(t, c.applyBitmaps([]pdu.BitmapData{{Width: 2, Height: 1, BitsPerPixel: 24, BitmapDataStream: []byte{0, 0, 255, 0, 255, 0, 0, 0}}}))
	frame, e := c.Snapshot()
	require.NoError(t, e)
	assert.Greater(t, len(frame.PNG), 8)
	assert.Equal(t, uint64(1), frame.Sequence)
	r, g, b, _ := c.image.At(0, 0).RGBA()
	assert.Equal(t, uint32(65535), r)
	assert.Zero(t, g)
	assert.Zero(t, b)
	for _, v := range []pdu.BitmapData{{Width: 65535, Height: 65535, BitsPerPixel: 32}, {Width: 1, Height: 1, BitsPerPixel: 8}, {Width: 1, Height: 1, BitsPerPixel: 32, BitmapDataStream: []byte{1}}, {DestLeft: 500, Width: 1, Height: 1, BitsPerPixel: 32}} {
		assert.Error(t, c.applyBitmaps([]pdu.BitmapData{v}))
	}
	for _, v := range []Input{{Type: "key", Code: 30}, {Type: "text", Text: "secret"}, {Type: "pointer", X: 1, Y: 1}, {Type: "clipboard_write", Text: "secret"}} {
		assert.ErrorIs(t, c.Input(v), ErrReadOnly)
	}
	assert.ErrorIs(t, c.Input(Input{Type: "clipboard_read"}), ErrClipboard)
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	assert.ErrorIs(t, c.Input(Input{}), ErrUnavailable)
}

func TestUnadvertisedUnicodeInputIsRejectedBeforeWriting(t *testing.T) {
	c := newTestClient(t)
	c.settings.ReadOnly = false
	assert.False(t, c.SupportsUnicodeInput())
	assert.ErrorIs(t, c.Input(Input{Type: "text", Text: "中文"}), ErrTextUnsupported)
}

type channelSink struct {
	messages [][]byte
	onFormat func()
}

func TestClipboardRepeatedEmptyAndFailedResponses(t *testing.T) {
	c := newTestClient(t)
	c.SetClipboardGuard(func(string) error { return nil })
	c.clip = newClipboard(c, &channelSink{})
	assert.ErrorIs(t, c.Input(Input{Type: "clipboard_read"}), ErrClipboardNotReady)
	c.clip.ready, c.clip.remoteUnicode = true, true
	for i, text := range []string{"same", "same", ""} {
		require.NoError(t, c.Input(Input{Type: "clipboard_read"}))
		response := make([]byte, 10+len(text)*2)
		binary.LittleEndian.PutUint16(response, 5)
		binary.LittleEndian.PutUint16(response[2:], 1)
		binary.LittleEndian.PutUint32(response[4:], uint32(len(response)-8))
		for at, ch := range text {
			binary.LittleEndian.PutUint16(response[8+2*at:], uint16(ch))
		}
		require.NoError(t, c.clip.process(response))
		assert.Equal(t, ClipboardState{Text: text, Revision: uint64(i + 1)}, c.ClipboardSnapshot())
	}
	require.NoError(t, c.Input(Input{Type: "clipboard_read"}))
	response := []byte{5, 0, 2, 0, 0, 0, 0, 0}
	require.NoError(t, c.clip.process(response))
	assert.Equal(t, ClipboardState{Revision: 4, Failed: true}, c.ClipboardSnapshot())
	c.SetClipboardGuard(func(string) error { return ErrClipboard })
	assert.Empty(t, c.ClipboardSnapshot())
}

func (s *channelSink) SendToChannel(_ string, p []byte) (int, error) {
	s.messages = append(s.messages, append([]byte(nil), p...))
	if len(p) >= 10 && binary.LittleEndian.Uint16(p[8:]) == 2 && s.onFormat != nil {
		s.onFormat()
	}
	return len(p), nil
}
func TestClipboardBoundedSessionLocalAndRevocation(t *testing.T) {
	a, b := newTestClient(t), newTestClient(t)
	sink := &channelSink{}
	a.clip = newClipboard(a, sink)
	sink.onFormat = func() { require.NoError(t, a.clip.process([]byte{3, 0, 1, 0, 0, 0, 0, 0})) }
	b.clip = newClipboard(b, &channelSink{})
	a.SetClipboardGuard(func(string) error { return nil })
	b.SetClipboardGuard(func(string) error { return nil })
	ready := make([]byte, 8)
	binary.LittleEndian.PutUint16(ready, 1)
	require.NoError(t, a.clip.process(ready))
	require.NoError(t, b.clip.process(ready))
	require.NoError(t, a.clip.set("private session text"))
	assert.Empty(t, b.clip.local)
	request := make([]byte, 12)
	binary.LittleEndian.PutUint16(request, 4)
	binary.LittleEndian.PutUint32(request[4:], 4)
	binary.LittleEndian.PutUint32(request[8:], 13)
	require.NoError(t, a.clip.process(request))
	assert.Contains(t, sink.messages[len(sink.messages)-1], byte('p'))
	a.SetClipboardGuard(func(string) error { return ErrClipboard })
	require.NoError(t, a.clip.process(request))
	assert.Equal(t, uint16(2), binary.LittleEndian.Uint16(sink.messages[len(sink.messages)-1][10:]))
	malicious := make([]byte, 8)
	binary.LittleEndian.PutUint32(malicious, clipboardWireLimit+1)
	a.clip.receive("cliprdr", malicious)
	select {
	case <-a.Done():
	default:
		t.Fatal("oversized channel was accepted")
	}
}
