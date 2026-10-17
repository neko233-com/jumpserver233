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
	Binding       string `json:"binding"`
	Target        string `json:"target"`
	PlanID        string `json:"plan_id,omitempty"`
	Sequence      uint64 `json:"sequence,omitempty"`
	ParentAssetID string `json:"parent_asset_id,omitempty"`
	Account       string `json:"account,omitempty"`
}

func (o Operation) Validate() error {
	if o.PlanID == "" {
		if o.Sequence != 0 || o.ParentAssetID != "" || o.Account != "" {
			return ErrInvalid
		}
	} else {
		if !strings.HasPrefix(o.PlanID, "plan-") || len(o.PlanID) != 37 {
			return ErrInvalid
		}
		p, e := hex.DecodeString(o.PlanID[5:])
		if e != nil || len(p) != 16 || strings.ToLower(o.PlanID) != o.PlanID || !assetPattern.MatchString(o.ParentAssetID) || o.Account == "" || !validText(o.Account, 128) || o.Sequence > 1<<53-1 {
			return ErrInvalid
		}
	}
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
