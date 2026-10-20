// Package pamtypes defines credential-free PAM inventory and guarded mutations.
package pamtypes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid PAM account request")
var ErrUnavailable = errors.New("PAM target unavailable")
var ErrChanged = errors.New("PAM principal changed")
var ErrScope = errors.New("PAM transport or account scope refused")

const MaxPrincipals = 1000

type Principal struct {
	Username string `json:"username"`
	Host     string `json:"host,omitempty"`
	ID       string `json:"principal_id"`
	Scope    string `json:"scope"`
	Plugin   string `json:"auth_plugin,omitempty"`
	Enabled  bool   `json:"enabled"`
}
type Guard func() error

func Text(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func ValidPassword(s string) bool { return Text(s, 4096) }
func Check(ctx context.Context, guard Guard) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if guard == nil {
		return ErrInvalid
	}
	if e := guard(); e != nil {
		return e
	}
	return nil
}
func MySQLID(user, host string) string {
	h := sha256.Sum256([]byte(user + "\x00" + host))
	return "mysql-" + hex.EncodeToString(h[:])
}
