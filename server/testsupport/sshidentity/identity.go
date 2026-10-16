// Package sshidentity provides a public synthetic identity for local tests only.
// Never install this key on real hosts or use the fixture as a production identity.
package sshidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
)

const Passphrase = "synthetic-import-key-passphrase"

func Key() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("jumpserver233 synthetic imported SSH identity"))
	return ed25519.NewKeyFromSeed(seed[:])
}
func Signer() ssh.Signer {
	signer, e := ssh.NewSignerFromKey(Key())
	if e != nil {
		panic(e)
	}
	return signer
}
func PEM(passphrase string) []byte {
	var block *pem.Block
	var e error
	if passphrase == "" {
		block, e = ssh.MarshalPrivateKey(Key(), "synthetic-only")
	} else {
		block, e = ssh.MarshalPrivateKeyWithPassphrase(Key(), "synthetic-only", []byte(passphrase))
	}
	if e != nil {
		panic(e)
	}
	return pem.EncodeToMemory(block)
}
func PublicKeyCallback(username string) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	return func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != username || !bytes.Equal(key.Marshal(), Signer().PublicKey().Marshal()) {
			return nil, ssh.ErrNoAuth
		}
		return nil, nil
	}
}
