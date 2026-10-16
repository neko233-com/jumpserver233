package pdu

// SetBitmapOnly negotiates only standard bitmap output. Declining optional
// codecs, drawing caches and frame windows keeps the advertised capabilities
// aligned with the bastion's supported baseline desktop protocol.
func (c *Client) SetBitmapOnly() {
	c.bitmapOnly = true
	for _, kind := range []CapsType{CAPSETTYPE_BITMAP_CODECS, CAPSETTYPE_SURFACE_COMMANDS, CAPSSETTYPE_FRAME_ACKNOWLEDGE, CAPSTYPE_RAIL} {
		delete(c.clientCapabilities, kind)
	}
}
