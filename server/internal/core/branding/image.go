package branding

import (
	"bytes"
	"image"
	"image/draw"
	"image/jpeg"
	"image/png"
)

// Images are decoded under explicit byte/pixel bounds and re-encoded as PNG.
// SVG, external URLs and original image metadata never reach the public endpoint.
func PrepareImage(data []byte, icon bool) ([]byte, error) {
	return prepareImage(data, icon, MaxImageBytes, 512*1024, 1024)
}
func PrepareLoginImage(data []byte) ([]byte, error) {
	return prepareImage(data, false, MaxLoginImageBytes, 1024*1024, 2048)
}
func prepareImage(data []byte, icon bool, limit, maxPixels, maxHeight int) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	if len(data) > limit {
		return nil, ErrImage
	}
	var cfg image.Config
	var err error
	var kind string
	if bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		cfg, err = png.DecodeConfig(bytes.NewReader(data))
		kind = "png"
	} else if bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}) {
		cfg, err = jpeg.DecodeConfig(bytes.NewReader(data))
		kind = "jpeg"
	} else {
		return nil, ErrImage
	}
	if err != nil || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 2048 || cfg.Height > maxHeight || cfg.Width*cfg.Height > maxPixels || icon && (cfg.Width != cfg.Height || cfg.Width > 512) {
		return nil, ErrImage
	}
	var decoded image.Image
	if kind == "png" {
		decoded, err = png.Decode(bytes.NewReader(data))
	} else {
		decoded, err = jpeg.Decode(bytes.NewReader(data))
	}
	if err != nil {
		return nil, ErrImage
	}
	clean := image.NewNRGBA(image.Rect(0, 0, cfg.Width, cfg.Height))
	draw.Draw(clean, clean.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
	var output bytes.Buffer
	if err = (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(&output, clean); err != nil || output.Len() > limit {
		return nil, ErrImage
	}
	return output.Bytes(), nil
}
