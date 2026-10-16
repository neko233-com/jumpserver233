// Package passkeyauth generates real ES256 WebAuthn messages for isolated tests.
// Its private keys are ephemeral synthetic authenticator keys, never user keys.
package passkeyauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

type Authenticator struct {
	mu           sync.Mutex
	Key          *ecdsa.PrivateKey
	ID, Handle   []byte
	Counter      uint32
	RPID, Origin string
}
type Overrides struct {
	Origin, RPID, Challenge, Type             string
	NoUV, NoUP, CrossOrigin, CorruptSignature bool
	Counter                                   *uint32
	Handle                                    []byte
}

func New(origin, rpID string) (*Authenticator, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	id := make([]byte, 32)
	if _, e = rand.Read(id); e != nil {
		return nil, e
	}
	return &Authenticator{Key: key, ID: id, Origin: origin, RPID: rpID}, nil
}
func enc(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
func options(value any) (string, []byte, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		return "", nil, e
	}
	var p struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(raw, &p) != nil || p.PublicKey.Challenge == "" {
		return "", nil, fmt.Errorf("invalid synthetic options")
	}
	h, e := base64.RawURLEncoding.DecodeString(p.PublicKey.User.ID)
	return p.PublicKey.Challenge, h, e
}
func (a *Authenticator) clientData(challenge, kind string, o Overrides) ([]byte, error) {
	if o.Origin == "" {
		o.Origin = a.Origin
	}
	if o.Type != "" {
		kind = o.Type
	}
	if o.Challenge != "" {
		challenge = o.Challenge
	}
	return json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": o.Origin, "crossOrigin": o.CrossOrigin})
}
func (a *Authenticator) data(registration bool, o Overrides) ([]byte, error) {
	rp := a.RPID
	if o.RPID != "" {
		rp = o.RPID
	}
	h := sha256.Sum256([]byte(rp))
	data := append([]byte{}, h[:]...)
	flags := byte(0x05)
	if o.NoUV {
		flags &^= 0x04
	}
	if o.NoUP {
		flags &^= 0x01
	}
	if registration {
		flags |= 0x40
	}
	data = append(data, flags)
	count := a.Counter
	if o.Counter != nil {
		count = *o.Counter
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], count)
	data = append(data, b[:]...)
	if registration {
		data = append(data, make([]byte, 16)...)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(a.ID)))
		data = append(data, length[:]...)
		data = append(data, a.ID...)
		pub, e := webauthncbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: a.Key.X.FillBytes(make([]byte, 32)), -3: a.Key.Y.FillBytes(make([]byte, 32))})
		if e != nil {
			return nil, e
		}
		data = append(data, pub...)
	}
	return data, nil
}
func (a *Authenticator) Registration(value any, o Overrides) (json.RawMessage, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	challenge, handle, e := options(value)
	if e != nil {
		return nil, e
	}
	a.Handle = handle
	client, e := a.clientData(challenge, "webauthn.create", o)
	if e != nil {
		return nil, e
	}
	data, e := a.data(true, o)
	if e != nil {
		return nil, e
	}
	att, e := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
	if e != nil {
		return nil, e
	}
	return json.Marshal(map[string]any{"id": enc(a.ID), "rawId": enc(a.ID), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{"credProps": map[string]bool{"rk": true}}, "response": map[string]any{"clientDataJSON": enc(client), "attestationObject": enc(att), "transports": []string{"internal"}}})
}
func (a *Authenticator) Assertion(value any, o Overrides) (json.RawMessage, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	challenge, _, e := options(value)
	if e != nil {
		return nil, e
	}
	a.Counter++
	client, e := a.clientData(challenge, "webauthn.get", o)
	if e != nil {
		return nil, e
	}
	data, e := a.data(false, o)
	if e != nil {
		return nil, e
	}
	clientHash := sha256.Sum256(client)
	signed := sha256.Sum256(append(append([]byte{}, data...), clientHash[:]...))
	signature, e := ecdsa.SignASN1(rand.Reader, a.Key, signed[:])
	if e != nil {
		return nil, e
	}
	if o.CorruptSignature {
		signature[len(signature)-1] ^= 0xff
	}
	handle := a.Handle
	if o.Handle != nil {
		handle = o.Handle
	}
	return json.Marshal(map[string]any{"id": enc(a.ID), "rawId": enc(a.ID), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": enc(client), "authenticatorData": enc(data), "signature": enc(signature), "userHandle": enc(handle)}})
}
