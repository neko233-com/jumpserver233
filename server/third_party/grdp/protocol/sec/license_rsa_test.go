package sec

import (
	"bytes"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestLicensingLittleEndianRSA(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 510)
	n.Add(n, big.NewInt(123))
	key := &rsa.PublicKey{N: n, E: 65537}
	secret := make([]byte, 48)
	secret[0] = 7
	got, e := licenseRSA(key, secret)
	if e != nil {
		t.Fatal(e)
	}
	expected := new(big.Int).Exp(big.NewInt(7), big.NewInt(65537), n)
	wire := make([]byte, 64)
	for i, b := range expected.Bytes() {
		wire[len(expected.Bytes())-1-i] = b
	}
	if !bytes.Equal(wire, got) {
		t.Fatal("not little-endian raw licensing RSA")
	}
	if _, e = licenseRSA(nil, secret); e == nil {
		t.Fatal("nil key accepted")
	}
	key.E = 2
	if _, e = licenseRSA(key, secret); e == nil {
		t.Fatal("even exponent accepted")
	}
}
