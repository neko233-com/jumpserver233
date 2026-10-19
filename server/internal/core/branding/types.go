// Package branding stores public site identity and controlled color palettes.
package branding

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxImageBytes = 512 << 10
const MaxLoginImageBytes = 2 << 20
const MaxStateBytes = 16 << 20

var (
	ErrInvalid    = errors.New("invalid branding settings")
	ErrImage      = errors.New("invalid branding image")
	ErrContrast   = errors.New("branding accent has insufficient contrast")
	ErrConflict   = errors.New("branding revision changed")
	hexColor      = regexp.MustCompile(`^#[0-9a-f]{6}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Settings struct {
	Revision          int    `json:"revision"`
	NameEN            string `json:"name_en"`
	NameZH            string `json:"name_zh"`
	Theme             string `json:"theme"`
	Accent            string `json:"accent"`
	LogoDigest        string `json:"logo_digest"`
	IconDigest        string `json:"icon_digest"`
	MarkDigest        string `json:"mark_digest"`
	LoginDigest       string `json:"login_digest"`
	LoginTitleEN      string `json:"login_title_en"`
	LoginTitleZH      string `json:"login_title_zh"`
	FooterEN          string `json:"footer_en"`
	FooterZH          string `json:"footer_zh"`
	RegistrationLabel string `json:"registration_label"`
	RegistrationURL   string `json:"registration_url"`
}
type Input struct {
	Revision          int    `json:"revision"`
	NameEN            string `json:"name_en"`
	NameZH            string `json:"name_zh"`
	Theme             string `json:"theme"`
	Accent            string `json:"accent"`
	LoginTitleEN      string `json:"login_title_en"`
	LoginTitleZH      string `json:"login_title_zh"`
	FooterEN          string `json:"footer_en"`
	FooterZH          string `json:"footer_zh"`
	RegistrationLabel string `json:"registration_label"`
	RegistrationURL   string `json:"registration_url"`
	// Absent preserves the current image. An empty byte slice clears it.
	Logo       *[]byte `json:"logo,omitempty"`
	Icon       *[]byte `json:"icon,omitempty"`
	Mark       *[]byte `json:"mark,omitempty"`
	LoginImage *[]byte `json:"login_image,omitempty"`
}
type Colors struct {
	Background string `json:"bg"`
	Panel      string `json:"panel"`
	Text       string `json:"text"`
	Muted      string `json:"muted"`
	Border     string `json:"border"`
	Accent     string `json:"accent"`
	AccentText string `json:"accent_text"`
}
type Public struct {
	Settings
	Colors Colors `json:"colors"`
}
type ThemeOption struct {
	ID     string `json:"id"`
	Colors Colors `json:"colors"`
}

func Themes() []ThemeOption {
	out := []ThemeOption{}
	for _, id := range []string{"graphite", "midnight", "forest", "plum", "crimson"} {
		c, _ := palette(id)
		out = append(out, ThemeOption{id, c})
	}
	return out
}

func Defaults() Settings {
	return Settings{Revision: 1, NameEN: "JumpServer233", NameZH: "JumpServer233", Theme: "graphite", Accent: "#2f81f7"}
}
func palette(name string) (Colors, bool) {
	c := Colors{Text: "#e6edf3", Muted: "#8b949e", Border: "#30363d"}
	switch name {
	case "graphite":
		c.Background, c.Panel = "#0d1117", "#161b22"
		c.Accent = "#2f81f7"
	case "midnight":
		c.Background, c.Panel = "#080f1d", "#111a27"
		c.Border = "#34435e"
		c.Accent = "#66b7ff"
	case "forest":
		c.Background, c.Panel = "#0b1410", "#111d18"
		c.Border = "#30483a"
		c.Accent = "#65d8a1"
	case "plum":
		c.Background, c.Panel = "#140d19", "#1e1723"
		c.Border = "#48354f"
		c.Accent = "#d6a5ef"
	case "crimson":
		c.Background, c.Panel, c.Border, c.Accent = "#180d11", "#20151b", "#51313d", "#ff8a93"
	default:
		return Colors{}, false
	}
	c.AccentText = "#000000"
	return c, true
}
func luminance(color string) float64 {
	var channels [3]float64
	for i := range channels {
		n, _ := strconv.ParseUint(color[1+2*i:3+2*i], 16, 8)
		v := float64(n) / 255
		if v <= 0.04045 {
			v /= 12.92
		} else {
			v = math.Pow((v+0.055)/1.055, 2.4)
		}
		channels[i] = v
	}
	return 0.2126*channels[0] + 0.7152*channels[1] + 0.0722*channels[2]
}
func contrast(a, b string) float64 {
	x, y := luminance(a), luminance(b)
	return (max(x, y) + 0.05) / (min(x, y) + 0.05)
}
func (s Settings) Public() Public {
	c, _ := palette(s.Theme)
	c.Accent = s.Accent
	c.AccentText = "#ffffff"
	if contrast(s.Accent, "#000000") > contrast(s.Accent, c.AccentText) {
		c.AccentText = "#000000"
	}
	return Public{s, c}
}
func validText(s string, maxRunes int) bool {
	if !utf8.ValidString(s) || strings.TrimSpace(s) != s || utf8.RuneCountInString(s) < 1 || utf8.RuneCountInString(s) > maxRunes {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u202a' || r == '\u202b' || r == '\u202d' || r == '\u202e' || r == '\u202c' || r == '\u2066' || r == '\u2067' || r == '\u2068' || r == '\u2069' {
			return false
		}
	}
	return true
}
func (s Settings) validate() error {
	c, ok := palette(s.Theme)
	if !ok || s.Revision < 1 || !validText(s.NameEN, 64) || !validText(s.NameZH, 64) || !hexColor.MatchString(s.Accent) || s.LogoDigest != "" && !digestPattern.MatchString(s.LogoDigest) || s.IconDigest != "" && !digestPattern.MatchString(s.IconDigest) {
		return ErrInvalid
	}
	for _, value := range []struct {
		value string
		limit int
	}{{s.LoginTitleEN, 64}, {s.LoginTitleZH, 64}, {s.FooterEN, 160}, {s.FooterZH, 160}, {s.RegistrationLabel, 80}} {
		if value.value != "" && !validText(value.value, value.limit) {
			return ErrInvalid
		}
	}
	if s.RegistrationURL != "" {
		parsed, e := url.Parse(s.RegistrationURL)
		if e != nil || len(s.RegistrationURL) > 1024 || !validText(s.RegistrationURL, 1024) || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || s.RegistrationLabel == "" {
			return ErrInvalid
		}
	}
	for _, digest := range []string{s.MarkDigest, s.LoginDigest} {
		if digest != "" && !digestPattern.MatchString(digest) {
			return ErrInvalid
		}
	}
	if contrast(s.Accent, c.Background) < 4.5 || contrast(s.Accent, c.Panel) < 4.5 {
		return ErrContrast
	}
	return nil
}
func imageDigest(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func Prepare(in Input) (Input, error) {
	in.NameEN = strings.TrimSpace(in.NameEN)
	in.NameZH = strings.TrimSpace(in.NameZH)
	in.Accent = strings.ToLower(strings.TrimSpace(in.Accent))
	in.LoginTitleEN = strings.TrimSpace(in.LoginTitleEN)
	in.LoginTitleZH = strings.TrimSpace(in.LoginTitleZH)
	in.FooterEN = strings.TrimSpace(in.FooterEN)
	in.FooterZH = strings.TrimSpace(in.FooterZH)
	in.RegistrationLabel = strings.TrimSpace(in.RegistrationLabel)
	in.RegistrationURL = strings.TrimSpace(in.RegistrationURL)
	s := in.settings()
	if e := s.validate(); e != nil {
		return Input{}, e
	}
	if in.Logo != nil {
		data, e := PrepareImage(*in.Logo, false)
		if e != nil {
			return Input{}, e
		}
		in.Logo = &data
	}
	if in.Icon != nil {
		data, e := PrepareImage(*in.Icon, true)
		if e != nil {
			return Input{}, e
		}
		in.Icon = &data
	}
	if in.Mark != nil {
		data, e := PrepareImage(*in.Mark, true)
		if e != nil {
			return Input{}, e
		}
		in.Mark = &data
	}
	if in.LoginImage != nil {
		data, e := PrepareLoginImage(*in.LoginImage)
		if e != nil {
			return Input{}, e
		}
		in.LoginImage = &data
	}
	return in, nil
}
func (in Input) settings() Settings {
	return Settings{Revision: in.Revision, NameEN: in.NameEN, NameZH: in.NameZH, Theme: in.Theme, Accent: in.Accent, LoginTitleEN: in.LoginTitleEN, LoginTitleZH: in.LoginTitleZH, FooterEN: in.FooterEN, FooterZH: in.FooterZH, RegistrationLabel: in.RegistrationLabel, RegistrationURL: in.RegistrationURL}
}
func AsInput(s Settings) Input {
	return Input{Revision: s.Revision, NameEN: s.NameEN, NameZH: s.NameZH, Theme: s.Theme, Accent: s.Accent, LoginTitleEN: s.LoginTitleEN, LoginTitleZH: s.LoginTitleZH, FooterEN: s.FooterEN, FooterZH: s.FooterZH, RegistrationLabel: s.RegistrationLabel, RegistrationURL: s.RegistrationURL}
}
