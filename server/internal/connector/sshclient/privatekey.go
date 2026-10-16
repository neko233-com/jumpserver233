package sshclient

import (
	"bytes"
	"crypto/rsa"
	"encoding/pem"
	"errors"

	xssh "golang.org/x/crypto/ssh"
)

const MaxPrivateKeyBytes = 64 * 1024

var ErrPrivateKey = errors.New("invalid or unsupported SSH private key")

// ImportPrivateKey validates an imported key and removes its input passphrase.
// Only the normalized key is returned for encryption by the server vault.
func ImportPrivateKey(input []byte, passphrase string) ([]byte, string, error) {
	if len(input) == 0 || len(input) > MaxPrivateKeyBytes || len(passphrase) > 1024 {
		return nil, "", ErrPrivateKey
	}
	block, rest := pem.Decode(input)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", ErrPrivateKey
	}
	if block.Type == "OPENSSH PRIVATE KEY" {
		magic := []byte("openssh-key-v1\x00")
		if !bytes.HasPrefix(block.Bytes, magic) {
			return nil, "", ErrPrivateKey
		}
		var header struct {
			Cipher, KDF, Options string
			Count                uint32
			Public, Private      []byte
		}
		if xssh.Unmarshal(block.Bytes[len(magic):], &header) != nil || header.Count != 1 {
			return nil, "", ErrPrivateKey
		}
		if header.KDF == "bcrypt" {
			var options struct {
				Salt   string
				Rounds uint32
			}
			if xssh.Unmarshal([]byte(header.Options), &options) != nil || options.Rounds == 0 || options.Rounds > 64 || len(options.Salt) > 1024 {
				return nil, "", ErrPrivateKey
			}
		} else if header.KDF != "none" {
			return nil, "", ErrPrivateKey
		}
	}
	var key any
	var err error
	if passphrase != "" {
		key, err = xssh.ParseRawPrivateKeyWithPassphrase(input, []byte(passphrase))
	} else {
		key, err = xssh.ParseRawPrivateKey(input)
	}
	if err != nil {
		return nil, "", ErrPrivateKey
	}
	signer, err := xssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", ErrPrivateKey
	}
	switch signer.PublicKey().Type() {
	case xssh.KeyAlgoED25519, xssh.KeyAlgoECDSA256, xssh.KeyAlgoECDSA384, xssh.KeyAlgoECDSA521:
	case xssh.KeyAlgoRSA:
		public, ok := signer.PublicKey().(xssh.CryptoPublicKey)
		if !ok {
			return nil, "", ErrPrivateKey
		}
		rsaKey, ok := public.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() < 2048 || rsaKey.N.BitLen() > 8192 {
			return nil, "", ErrPrivateKey
		}
	default:
		return nil, "", ErrPrivateKey
	}
	normalized, err := xssh.MarshalPrivateKey(key, "")
	if err != nil {
		return nil, "", ErrPrivateKey
	}
	return pem.EncodeToMemory(normalized), xssh.FingerprintSHA256(signer.PublicKey()), nil
}
