package pdu

import "io"

// Frame acknowledgements bound the server's outstanding surface frames. Without
// acknowledging END markers, a newly logged-in desktop stalls after two frames.
type frameAcknowledge struct {
	FrameID uint32 `struc:"little"`
}

func (*frameAcknowledge) Type2() uint8           { return 0x38 }
func (*frameAcknowledge) Unpack(io.Reader) error { return nil }
func (c *Client) AcknowledgeFrame(id uint32)     { c.sendDataPDU(&frameAcknowledge{FrameID: id}) }
