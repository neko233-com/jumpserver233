package sec

import (
	"crypto/rsa"
	"errors"
	"github.com/adfnekc/grdp/core"
	"math/big"
)

// MS-RDPELE 5.1.1.1 uses RDP's little-endian, zero-padded RSA operation,
// not TLS's PKCS#1 v1.5 encoding. This key protects licensing only; our caller
// independently verifies the TLS certificate before any licensing exchange.
func licenseRSA(key *rsa.PublicKey, secret []byte) ([]byte, error) {
	if key == nil || key.N == nil || key.Size() < 64 || key.N.BitLen() > 8192 || key.N.Bit(0) != 1 || key.E < 3 || key.E > 0x7fffffff || key.E&1 == 0 || len(secret) != 48 {
		return nil, errors.New("invalid licensing RSA key")
	}
	message := new(big.Int).SetBytes(core.Reverse(secret))
	if message.Cmp(key.N) >= 0 {
		return nil, errors.New("invalid licensing secret")
	}
	encrypted := new(big.Int).Exp(message, big.NewInt(int64(key.E)), key.N)
	result := make([]byte, (key.N.BitLen()+7)/8)
	encrypted.FillBytes(result)
	return core.Reverse(result), nil
}
