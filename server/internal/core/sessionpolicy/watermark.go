package sessionpolicy

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"time"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

func Label(operatorID, sessionID string, at time.Time) string {
	return fmt.Sprintf("JMS %s | %s | %s", operatorID, sessionID, at.UTC().Format(time.RFC3339))
}

// StampPNG burns an ASCII identity footer into the server's desktop image.
// Caller caches by source frame sequence; no rendering is done on unchanged frames.
func StampPNG(data []byte, label string) ([]byte, error) {
	if label == "" {
		return data, nil
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if config.Width < 1 || config.Height < 1 || config.Width > 3840 || config.Height > 2160 {
		return nil, ErrInvalid
	}
	src, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	im := image.NewRGBA(src.Bounds())
	draw.Draw(im, im.Bounds(), src, src.Bounds().Min, draw.Src)
	max := (config.Width - 12) / 7
	if max < 1 {
		return data, nil
	}
	if len(label) > max {
		label = label[:max]
	}
	y := config.Height - 4
	draw.Draw(im, image.Rect(0, y-13, min(config.Width, len(label)*7+12), config.Height), image.NewUniform(color.RGBA{0, 0, 0, 100}), image.Point{}, draw.Over)
	d := font.Drawer{Dst: im, Src: image.NewUniform(color.NRGBA{220, 230, 245, 180}), Face: basicfont.Face7x13, Dot: fixed.P(6, y)}
	d.DrawString(label)
	var out bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if err = encoder.Encode(&out, im); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
