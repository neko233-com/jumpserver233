// Package accountdiscovery owns collected account metadata and human review.
// Collection never creates target users, stores password hashes or grants access.
package accountdiscovery

import (
	"encoding/hex"
	"errors"
	"strings"
)

var ErrInvalid = errors.New("invalid account discovery data")
var ErrConflict = errors.New("account discovery revision conflict")
var ErrCapacity = errors.New("account discovery storage capacity reached")
var ErrClosed = errors.New("account discovery store closed")

type Operation struct {
	Binding string `json:"binding"`
	Target  string `json:"target"`
}

func (o Operation) Validate() error {
	b, e := hex.DecodeString(o.Binding)
	if e != nil || len(b) != 32 || strings.ToLower(o.Binding) != o.Binding {
		return ErrInvalid
	}
	b, e = hex.DecodeString(o.Target)
	if e != nil || len(b) != 32 || strings.ToLower(o.Target) != o.Target {
		return ErrInvalid
	}
	return nil
}
func (o Operation) Command() string {
	return "account-discovery linux-local version=1 binding=" + o.Binding + " target=" + o.Target
}
func (o Operation) Clone() Operation { return o }
