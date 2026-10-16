package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		panic("certificate output directory required")
	}
	root := os.Args[1]
	if e := os.MkdirAll(root, 0700); e != nil {
		panic(e)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		panic(e)
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "mysql.synthetic.invalid"}, DNSNames: []string{"mysql.synthetic.invalid", "mariadb.synthetic.invalid", "sqlserver.synthetic.invalid", "clickhouse.synthetic.invalid", "redis.synthetic.invalid", "mongodb.synthetic.invalid", "telnet.synthetic.invalid", "rdp.synthetic.invalid"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join(root, "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join(root, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); e != nil {
		panic(e)
	}
	combined := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)
	if e = os.WriteFile(filepath.Join(root, "server.pem"), combined, 0600); e != nil {
		panic(e)
	}
	fmt.Println("QA certificate prepared")
}
