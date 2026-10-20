package rotationplans

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/internal/core/credentialpolicy"
	"time"
)

type saveReceipt struct {
	RequestID string    `json:"request_id"`
	ActorID   string    `json:"actor_id"`
	PlanID    string    `json:"plan_id"`
	Digest    string    `json:"digest"`
	At        time.Time `json:"at"`
}

func validFixedRecord(mode, password, id string, completed bool) bool {
	if !validPasswordMode(mode) {
		return false
	}
	if mode != "fixed" {
		return password == "" && id == ""
	}
	return IDPattern.MatchString(id) && ((completed && password == "") || (!completed && credentialpolicy.ValidFixedPassword(password)))
}

func (s *Service) saveDigest(actor, id string, input SaveInput) (string, error) {
	raw, err := json.Marshal(struct {
		Actor, ID string
		Input     SaveInput
	}{actor, id, input})
	if err != nil {
		return "", ErrInvalid
	}
	mac := hmac.New(sha256.New, s.receiptKey)
	_, _ = mac.Write(raw)
	clear(raw)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func savedPlan(d state, actor, request, digest string, all, allowFixed bool) (Plan, bool, error) {
	for _, v := range d.SaveReceipts {
		if v.RequestID != request {
			continue
		}
		if v.ActorID != actor || v.Digest != digest {
			return Plan{}, true, ErrConflict
		}
		p, ok := d.Plans[v.PlanID]
		if !ok || p.Actor.ID != actor && !all {
			return Plan{}, true, ErrNotFound
		}
		if p.PasswordMode == "fixed" && !allowFixed {
			return Plan{}, true, ErrDenied
		}
		return clonePlan(p.Plan), true, nil
	}
	return Plan{}, false, nil
}
