package rdpclient

// This channel is session-local and never reads or writes the server process's
// operating-system clipboard. File/drive redirection is not advertised.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/adfnekc/grdp/core"
	"sync"
	"unicode/utf16"
)

const clipboardWireLimit = 2*MaxClipboard + 4096

type clipboard struct {
	owner                                    *Client
	sender                                   core.ChannelSender
	mu                                       sync.Mutex
	tx                                       sync.Mutex
	buffer                                   []byte
	total                                    uint32
	ready, longNames, remoteUnicode, pending bool
	local, remote                            string
	revision                                 uint64
	failed                                   bool
}

func newClipboard(c *Client, s core.ChannelSender) *clipboard { return &clipboard{owner: c, sender: s} }
func (c *clipboard) send(kind, flags uint16, data []byte) error {
	if len(data) > clipboardWireLimit {
		return ErrClipboard
	}
	message := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint16(message, kind)
	binary.LittleEndian.PutUint16(message[2:], flags)
	binary.LittleEndian.PutUint32(message[4:], uint32(len(data)))
	copy(message[8:], data)
	c.tx.Lock()
	defer c.tx.Unlock()
	for offset := 0; offset < len(message); {
		n := len(message) - offset
		if n > 1600 {
			n = 1600
		}
		chunk := make([]byte, 8+n)
		binary.LittleEndian.PutUint32(chunk, uint32(len(message)))
		var flags uint32
		if offset == 0 {
			flags |= 1
		}
		if offset+n == len(message) {
			flags |= 2
		}
		binary.LittleEndian.PutUint32(chunk[4:], flags)
		copy(chunk[8:], message[offset:offset+n])
		if _, e := c.sender.SendToChannel("cliprdr", chunk); e != nil {
			return ErrClipboard
		}
		offset += n
	}
	return nil
}
func (c *clipboard) receive(name string, raw []byte) {
	if name != "cliprdr" {
		return
	}
	if len(raw) < 8 {
		c.owner.fail("clipboard_fragment")
		return
	}
	total, flags := binary.LittleEndian.Uint32(raw), binary.LittleEndian.Uint32(raw[4:])
	if total > clipboardWireLimit || total < 8 {
		c.owner.fail("clipboard_fragment")
		return
	}
	c.mu.Lock()
	if flags&1 != 0 {
		c.buffer = nil
		c.total = total
	}
	if c.total != total || len(c.buffer)+len(raw)-8 > int(total) {
		c.mu.Unlock()
		c.owner.fail("clipboard_fragment")
		return
	}
	c.buffer = append(c.buffer, raw[8:]...)
	if flags&2 == 0 {
		c.mu.Unlock()
		return
	}
	message := c.buffer
	c.buffer = nil
	c.total = 0
	c.mu.Unlock()
	if len(message) != int(total) || c.processMessages(message) != nil {
		c.owner.fail("clipboard_message")
	}
}
func (c *clipboard) processMessages(raw []byte) error {
	for count := 0; len(raw) >= 8; count++ {
		if count >= 64 {
			return ErrProtocol
		}
		n := int(binary.LittleEndian.Uint32(raw[4:])) + 8
		if n < 8 || n > len(raw) {
			return ErrProtocol
		}
		if e := c.process(raw[:n]); e != nil {
			return e
		}
		raw = raw[n:]
	}
	// xrdp appends up to four zero padding octets after some clipboard PDUs.
	if len(raw) > 4 {
		return ErrProtocol
	}
	for _, v := range raw {
		if v != 0 {
			return ErrProtocol
		}
	}
	return nil
}
func (c *clipboard) formatList() error {
	c.mu.Lock()
	long := c.longNames
	c.mu.Unlock()
	n := 36
	if long {
		n = 6
	}
	data := make([]byte, n)
	binary.LittleEndian.PutUint32(data, 13)
	return c.send(2, 0, data)
}
func (c *clipboard) process(raw []byte) error {
	if len(raw) < 8 || int(binary.LittleEndian.Uint32(raw[4:])) != len(raw)-8 {
		return ErrProtocol
	}
	kind, flags := binary.LittleEndian.Uint16(raw), binary.LittleEndian.Uint16(raw[2:])
	data := raw[8:]
	switch kind {
	case 1:
		caps := []byte{1, 0, 0, 0, 1, 0, 12, 0, 2, 0, 0, 0, 2, 0, 0, 0}
		if e := c.send(7, 0, caps); e != nil {
			return e
		}
		c.mu.Lock()
		c.ready = true
		c.mu.Unlock()
		return c.formatList()
	case 7:
		if len(data) < 4 {
			return ErrProtocol
		}
		count := int(binary.LittleEndian.Uint16(data))
		if count > 16 {
			return ErrProtocol
		}
		at := 4
		for i := 0; i < count; i++ {
			if at+4 > len(data) {
				return ErrProtocol
			}
			typ, n := binary.LittleEndian.Uint16(data[at:]), int(binary.LittleEndian.Uint16(data[at+2:]))
			if n < 4 || at+n > len(data) {
				return ErrProtocol
			}
			if typ == 1 && n >= 12 {
				c.mu.Lock()
				c.longNames = binary.LittleEndian.Uint32(data[at+8:])&2 != 0
				c.mu.Unlock()
			}
			at += n
		}
	case 2:
		c.mu.Lock()
		long := c.longNames
		c.mu.Unlock()
		found := false
		at := 0
		for count := 0; at < len(data); count++ {
			if count >= 64 || at+4 > len(data) {
				return ErrProtocol
			}
			if binary.LittleEndian.Uint32(data[at:]) == 13 {
				found = true
			}
			at += 4
			if long {
				end := false
				for at+2 <= len(data) {
					v := binary.LittleEndian.Uint16(data[at:])
					at += 2
					if v == 0 {
						end = true
						break
					}
				}
				if !end {
					return ErrProtocol
				}
			} else {
				if at+32 > len(data) {
					return ErrProtocol
				}
				at += 32
			}
		}
		c.mu.Lock()
		c.remoteUnicode = found
		c.remote = ""
		c.mu.Unlock()
		return c.send(3, 1, nil)
	case 4:
		if len(data) != 4 || binary.LittleEndian.Uint32(data) != 13 || !c.owner.clipboardAllowed("rdp_clipboard_write") {
			return c.send(5, 2, nil)
		}
		c.mu.Lock()
		local := c.local
		c.mu.Unlock()
		var b bytes.Buffer
		for _, v := range utf16.Encode([]rune(local)) {
			_ = binary.Write(&b, binary.LittleEndian, v)
		}
		_ = binary.Write(&b, binary.LittleEndian, uint16(0))
		return c.send(5, 1, b.Bytes())
	case 5:
		c.mu.Lock()
		pending := c.pending
		c.pending = false
		c.mu.Unlock()
		if !pending {
			return nil
		}
		if !c.owner.clipboardAllowed("rdp_clipboard_read") {
			return nil
		}
		if flags&1 == 0 {
			c.mu.Lock()
			c.remote = ""
			c.failed = true
			c.revision++
			c.mu.Unlock()
			return nil
		}
		if len(data)%2 != 0 || len(data) > 2*MaxClipboard+2 {
			return ErrProtocol
		}
		units := make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			v := binary.LittleEndian.Uint16(data[i:])
			if v == 0 {
				break
			}
			units = append(units, v)
		}
		value := string(utf16.Decode(units))
		if len(value) > MaxClipboard {
			return ErrProtocol
		}
		c.mu.Lock()
		c.remote = value
		c.failed = false
		c.revision++
		c.mu.Unlock()
	case 3, 6: // Format acknowledgement and deprecated temporary directory.
	default:
		return errors.New("unsupported RDP clipboard message")
	}
	return nil
}
func (c *clipboard) set(value string) error {
	c.mu.Lock()
	c.local = value
	ready := c.ready
	c.mu.Unlock()
	if !ready {
		return ErrClipboardNotReady
	}
	return c.formatList()
}
func (c *clipboard) request() error {
	c.mu.Lock()
	if !c.ready || !c.remoteUnicode {
		c.mu.Unlock()
		return ErrClipboardNotReady
	}
	c.pending = true
	c.mu.Unlock()
	data := []byte{13, 0, 0, 0}
	return c.send(4, 0, data)
}
func (c *clipboard) snapshot() ClipboardState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ClipboardState{Text: c.remote, Revision: c.revision, Failed: c.failed}
}
