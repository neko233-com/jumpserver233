package rdpclient

import (
	"bytes"
	"context"
	"fmt"
	"github.com/adfnekc/grdp/core"
	"github.com/adfnekc/grdp/orders"
	"github.com/adfnekc/grdp/protocol/nla"
	"github.com/adfnekc/grdp/protocol/pdu"
	"github.com/adfnekc/grdp/protocol/sec"
	"github.com/adfnekc/grdp/protocol/t125"
	"github.com/adfnekc/grdp/protocol/tpkt"
	"github.com/adfnekc/grdp/protocol/x224"
	"image"
	"image/png"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

type Frame struct {
	Sequence      uint64
	Width, Height int
	PNG           []byte
}
type Client struct {
	conn      net.Conn
	pdu       *pdu.Client
	settings  Settings
	once      sync.Once
	done      chan struct{}
	changed   chan struct{}
	first     chan struct{}
	firstOnce sync.Once
	mu        sync.Mutex
	image     *image.RGBA
	screen    *orders.Screen
	sequence  uint64
	encodeMu  sync.Mutex
	cached    Frame
	inputMu   sync.Mutex
	clip      *clipboard
	clipGuard func(string) error
	errMu     sync.Mutex
	failure   string
}

func Open(ctx context.Context, t Target, username, password string) (*Client, error) {
	settings, e := Normalize(t.Settings)
	if e != nil || !ValidCredential(username) || !ValidCredential(password) {
		return nil, ErrInvalid
	}
	t.Settings = settings
	conn, e := dial(ctx, t)
	if e != nil {
		return nil, e
	}
	c := &Client{conn: conn, settings: settings, done: make(chan struct{}), changed: make(chan struct{}, 1), first: make(chan struct{}), image: image.NewRGBA(image.Rect(0, 0, settings.Width, settings.Height)), screen: orders.NewScreen(settings.Width, settings.Height)}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(20 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, ErrUnavailable
	}
	cfg, e := tlsConfig(t)
	if e != nil {
		return nil, e
	}
	socket := core.NewSocketLayer(&negotiatedConn{Conn: conn, expected: protocol(settings), started: make(chan struct{})})
	socket.SetTLSConfig(cfg)
	domain, user := settings.Domain, username
	if domain == "" && strings.Contains(user, "\\") {
		v := strings.SplitN(user, "\\", 2)
		domain, user = v[0], v[1]
	}
	tp := tpkt.New(socket, nla.NewNTLMv2(domain, user, password))
	tp.SetStrictPubKeyAuth(true)
	x := x224.New(tp)
	mcs := t125.NewMCSClient(x)
	security := sec.NewClient(mcs)
	pd := pdu.NewClient(security)
	pd.SetBitmapOnly()
	c.pdu = pd
	recoverer := func(interface{}, interface{}, error) { c.fail("protocol_panic") }
	tp.RecoverWith(recoverer)
	x.RecoverWith(recoverer)
	mcs.RecoverWith(recoverer)
	security.RecoverWith(recoverer)
	pd.RecoverWith(recoverer)
	ready := make(chan struct{})
	var readyOnce sync.Once
	pd.On("error", func(error) { c.fail("protocol_error") })
	pd.On("close", func() { c.Close() })
	pd.On("ready", func() { readyOnce.Do(func() { close(ready) }) })
	pd.On("bitmap", func(data interface{}) {
		v, yes := data.([]pdu.BitmapData)
		if !yes {
			c.Close()
			return
		}
		if c.applyBitmaps(v) != nil {
			c.fail("invalid_bitmap")
		}
	})
	pd.On("surface-bits", func(data interface{}) {
		v, yes := data.(*pdu.SurfaceBitsCommand)
		if !yes || c.applySurface(v) != nil {
			c.fail("invalid_surface")
		}
	})
	pd.On("orders", func(data interface{}) {
		v, yes := data.([]pdu.OrderPdu)
		if !yes || c.applyOrders(v) != nil {
			c.fail("invalid_orders")
		}
	})
	pd.On("frame-marker", func(data interface{}) {
		marker, ok := data.(*pdu.FrameMarkerCommand)
		if !ok {
			c.Close()
			return
		}
		if marker.FrameAction == 1 {
			c.inputMu.Lock()
			pd.AcknowledgeFrame(marker.FrameID)
			c.inputMu.Unlock()
		}
	})
	if settings.Clipboard {
		c.clip = newClipboard(c, security)
		security.On("channel", c.clip.receive)
		mcs.SetClientCliprdr()
	}
	mcs.SetClientDesktop(uint16(settings.Width), uint16(settings.Height))
	security.SetUser(user)
	security.SetPwd(password)
	security.SetDomain(domain)
	security.SetRequireVerifiedCertificate(true)
	tp.SetFastPathListener(security)
	pd.SetFastPathSender(tp)
	security.SetFastPathListener(pd)
	security.SetChannelSender(mcs)
	x.SetRequestedProtocol(protocol(settings))
	x.SetConnectTimeout(time.Until(deadline))
	if e = x.Connect(); e != nil {
		return nil, ErrUnavailable
	}
	select {
	case <-ready:
	case <-c.done:
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, c.FailureCode())
	case <-ctx.Done():
		return nil, ErrUnavailable
	case <-time.After(time.Until(deadline)):
		return nil, ErrUnavailable
	}
	select {
	case <-c.first:
	case <-c.done:
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, c.FailureCode())
	case <-ctx.Done():
		return nil, ErrUnavailable
	case <-time.After(time.Until(deadline)):
		return nil, ErrUnavailable
	}
	if !stop() || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if e = conn.SetDeadline(time.Time{}); e != nil {
		return nil, ErrUnavailable
	}
	ok = true
	// A newly started desktop may map its first window after activation. Request
	// bounded startup refreshes so delayed Xorg/Explorer painting is synchronized.
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for i := 0; i < 5; i++ {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				w, h := c.Size()
				c.inputMu.Lock()
				pd.RefreshDesktop(w, h)
				c.inputMu.Unlock()
			}
		}
	}()
	return c, nil
}
func (c *Client) Close() error { c.once.Do(func() { close(c.done); _ = c.conn.Close() }); return nil }

// FailureCode names a local stage without retaining remote data.
func (c *Client) FailureCode() string { c.errMu.Lock(); defer c.errMu.Unlock(); return c.failure }
func (c *Client) fail(code string) {
	c.errMu.Lock()
	if c.failure == "" {
		c.failure = code
	}
	c.errMu.Unlock()
	_ = c.Close()
}
func (c *Client) Done() <-chan struct{}    { return c.done }
func (c *Client) Changed() <-chan struct{} { return c.changed }
func (c *Client) Size() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.image.Bounds().Dx(), c.image.Bounds().Dy()
}
func (c *Client) SetClipboardGuard(f func(string) error) { c.mu.Lock(); c.clipGuard = f; c.mu.Unlock() }
func (c *Client) clipboardAllowed(action string) bool {
	c.mu.Lock()
	f := c.clipGuard
	c.mu.Unlock()
	return f != nil && f(action) == nil
}
func (c *Client) notify() {
	c.sequence++
	c.firstOnce.Do(func() { close(c.first) })
	select {
	case c.changed <- struct{}{}:
	default:
	}
}
func (c *Client) Snapshot() (Frame, error) {
	c.encodeMu.Lock()
	defer c.encodeMu.Unlock()
	c.mu.Lock()
	sequence := c.sequence
	if c.cached.Sequence == sequence && sequence > 0 {
		f := c.cached
		c.mu.Unlock()
		return f, nil
	}
	copyImage := image.NewRGBA(c.image.Bounds())
	copy(copyImage.Pix, c.image.Pix)
	c.mu.Unlock()
	if sequence == 0 {
		return Frame{}, ErrUnavailable
	}
	var b bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if e := encoder.Encode(&b, copyImage); e != nil {
		return Frame{}, ErrUnavailable
	}
	if b.Len() > 40*1024*1024 {
		return Frame{}, ErrUnavailable
	}
	f := Frame{Sequence: sequence, Width: copyImage.Bounds().Dx(), Height: copyImage.Bounds().Dy(), PNG: b.Bytes()}
	c.cached = f
	return f, nil
}
func (c *Client) SupportsUnicodeInput() bool {
	if c.pdu == nil {
		return false
	}
	input, ok := c.pdu.ServerCapabilities()[pdu.CAPSTYPE_INPUT].(*pdu.InputCapability)
	return ok && input.Flags&pdu.INPUT_FLAG_UNICODE != 0
}
func (c *Client) Input(v Input) error {
	select {
	case <-c.done:
		return ErrUnavailable
	default:
	}
	if v.Type == "clipboard_read" {
		if c.clip == nil || !c.clipboardAllowed("rdp_clipboard_read") {
			return ErrClipboard
		}
		return c.clip.request()
	}
	if c.settings.ReadOnly {
		return ErrReadOnly
	}
	c.inputMu.Lock()
	defer c.inputMu.Unlock()
	switch v.Type {
	case "key":
		if v.Code < 1 || v.Code > 127 {
			return ErrInvalid
		}
		flags := uint16(0)
		if v.Extended {
			flags |= pdu.KBDFLAGS_EXTENDED
		}
		if !v.Down {
			flags |= pdu.KBDFLAGS_RELEASE
		}
		c.pdu.SendInputEvents(pdu.INPUT_EVENT_SCANCODE, []pdu.InputEventsInterface{&pdu.ScancodeKeyEvent{KeyCode: uint16(v.Code), KeyboardFlags: flags}})
	case "text":
		if !utf8.ValidString(v.Text) || len(v.Text) > 4096 || strings.ContainsRune(v.Text, 0) {
			return ErrInvalid
		}
		if !c.SupportsUnicodeInput() {
			for _, r := range v.Text {
				if r > 127 {
					return ErrTextUnsupported
				}
			}
		}
		for _, code := range utf16.Encode([]rune(v.Text)) {
			c.pdu.SendInputEvents(pdu.INPUT_EVENT_UNICODE, []pdu.InputEventsInterface{&pdu.UnicodeKeyEvent{Unicode: code}, &pdu.UnicodeKeyEvent{Unicode: code, KeyboardFlags: pdu.KBDFLAGS_RELEASE}})
		}
	case "pointer":
		w, h := c.Size()
		if v.X < 0 || v.Y < 0 || v.X >= w || v.Y >= h {
			return ErrInvalid
		}
		event := &pdu.PointerEvent{XPos: uint16(v.X), YPos: uint16(v.Y)}
		switch v.Action {
		case "move":
			event.PointerFlags = pdu.PTRFLAGS_MOVE
		case "button":
			switch v.Button {
			case "left":
				event.PointerFlags = pdu.PTRFLAGS_BUTTON1
			case "right":
				event.PointerFlags = pdu.PTRFLAGS_BUTTON2
			case "middle":
				event.PointerFlags = pdu.PTRFLAGS_BUTTON3
			default:
				return ErrInvalid
			}
			if v.Down {
				event.PointerFlags |= pdu.PTRFLAGS_DOWN
			}
		case "wheel":
			if v.Delta < -240 || v.Delta > 240 {
				return ErrInvalid
			}
			event.PointerFlags = pdu.PTRFLAGS_WHEEL | uint16(v.Delta)&0x1ff
		default:
			return ErrInvalid
		}
		c.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{event})
	case "clipboard_write":
		if c.clip == nil || !c.clipboardAllowed("rdp_clipboard_write") || !utf8.ValidString(v.Text) || len(v.Text) > MaxClipboard || strings.ContainsRune(v.Text, 0) {
			return ErrClipboard
		}
		return c.clip.set(v.Text)
	default:
		return ErrInvalid
	}
	return nil
}
func (c *Client) Clipboard() string {
	return c.ClipboardSnapshot().Text
}

type ClipboardState struct {
	Text     string
	Revision uint64
	Failed   bool
}

func (c *Client) ClipboardSnapshot() ClipboardState {
	if c.clip == nil || !c.clipboardAllowed("rdp_clipboard_read") {
		return ClipboardState{}
	}
	return c.clip.snapshot()
}
