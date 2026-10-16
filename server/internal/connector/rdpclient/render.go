package rdpclient

import (
	"github.com/adfnekc/grdp/codec"
	"github.com/adfnekc/grdp/core"
	"github.com/adfnekc/grdp/protocol/pdu"
	"image"
)

func (c *Client) resizeFromCaps() error {
	if c.pdu == nil {
		return nil
	}
	capability := c.pdu.ServerCapabilities()[pdu.CAPSTYPE_BITMAP]
	if capability == nil {
		return nil
	}
	v, ok := capability.(*pdu.BitmapCapability)
	if !ok {
		return ErrProtocol
	}
	w, h := int(v.DesktopWidth), int(v.DesktopHeight)
	if w == 0 && h == 0 {
		return nil
	}
	if !validSize(w, h) {
		return ErrProtocol
	}
	if w != c.image.Bounds().Dx() || h != c.image.Bounds().Dy() {
		c.image = image.NewRGBA(image.Rect(0, 0, w, h))
		c.screen.Resize(w, h)
	}
	return nil
}
func (c *Client) updateImage() {
	src := c.screen.Buffer()
	for i := 0; i+3 < len(src); i += 4 {
		c.image.Pix[i] = src[i+2]
		c.image.Pix[i+1] = src[i+1]
		c.image.Pix[i+2] = src[i]
		c.image.Pix[i+3] = 255
	}
	c.notify()
}
func (c *Client) validRect(x, y, w, h int) bool {
	return x >= 0 && y >= 0 && w > 0 && h > 0 && w*h <= MaxPixels && x+w <= c.image.Bounds().Dx()+3 && y+h <= c.image.Bounds().Dy()
}
func (c *Client) applyBitmaps(bitmaps []pdu.BitmapData) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(bitmaps) > 4096 {
		return ErrProtocol
	}
	if e := c.resizeFromCaps(); e != nil {
		return e
	}
	changed := false
	for _, v := range bitmaps {
		w, h, x, y := int(v.Width), int(v.Height), int(v.DestLeft), int(v.DestTop)
		if !c.validRect(x, y, w, h) {
			return ErrProtocol
		}
		bpp := (int(v.BitsPerPixel) + 7) / 8
		if v.BitsPerPixel != 16 && v.BitsPerPixel != 24 && v.BitsPerPixel != 32 {
			return ErrProtocol
		}
		data := v.BitmapDataStream
		if v.IsCompress() {
			var e error
			data, e = core.Decompress(data, w, h, bpp)
			if e != nil {
				return ErrProtocol
			}
		} else {
			stride := (w*bpp + 3) &^ 3
			if len(data) < stride*h {
				return ErrProtocol
			}
			pixels := make([]byte, w*h*bpp)
			for row := 0; row < h; row++ {
				copy(pixels[row*w*bpp:(row+1)*w*bpp], data[(h-1-row)*stride:(h-1-row)*stride+w*bpp])
			}
			if bpp == 2 {
				for i := 0; i+1 < len(pixels); i += 2 {
					pixels[i], pixels[i+1] = pixels[i+1], pixels[i]
				}
			}
			data = pixels
		}
		if len(data) < w*h*bpp {
			return ErrProtocol
		}
		if !c.screen.Blit(data, w, h, bpp, image.Rect(x, y, x+w, y+h)).Empty() {
			changed = true
		}
	}
	if changed {
		c.updateImage()
	}
	return nil
}
func (c *Client) applySurface(v *pdu.SurfaceBitsCommand) error {
	if v == nil {
		return ErrProtocol
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.resizeFromCaps(); e != nil {
		return e
	}
	b := v.Bitmap
	w, h, x, y := int(b.Width), int(b.Height), int(v.DestLeft), int(v.DestTop)
	if !c.validRect(x, y, w, h) || len(b.BitmapData) > 16*1024*1024 {
		return ErrProtocol
	}
	data, e := codec.Decompress(b.CodecID, b.BitmapData, w, h, int(b.Bpp))
	if e != nil {
		return ErrProtocol
	}
	bpp := 4
	if b.CodecID == codec.CodecIDNone {
		bpp = int(b.Bpp) / 8
	}
	if bpp < 2 || bpp > 4 || len(data) < w*h*bpp {
		return ErrProtocol
	}
	if !c.screen.Blit(data, w, h, bpp, image.Rect(x, y, x+w, y+h)).Empty() {
		c.updateImage()
	}
	return nil
}
func (c *Client) applyOrders(values []pdu.OrderPdu) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(values) > 4096 {
		return ErrProtocol
	}
	if e := c.resizeFromCaps(); e != nil {
		return e
	}
	rect, e := c.screen.Draw(values)
	if e != nil {
		return ErrProtocol
	}
	if !rect.Empty() {
		c.updateImage()
	}
	return nil
}
