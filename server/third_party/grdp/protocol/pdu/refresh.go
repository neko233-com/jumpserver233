package pdu

import "io"

type refreshDesktop struct {
	NumberOfAreas            uint8
	Padding                  [3]byte
	Left, Top, Right, Bottom uint16 `struc:"little"`
}

func (*refreshDesktop) Type2() uint8           { return 0x21 }
func (*refreshDesktop) Unpack(io.Reader) error { return nil }
func (c *Client) RefreshDesktop(width, height int) {
	if width > 0 && height > 0 && width <= 3840 && height <= 2160 {
		c.sendDataPDU(&refreshDesktop{NumberOfAreas: 1, Right: uint16(width - 1), Bottom: uint16(height - 1)})
	}
}
