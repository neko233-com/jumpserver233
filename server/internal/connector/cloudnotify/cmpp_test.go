package cloudnotify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeNotificationCMPPMutualAuthenticationFramingAndUnknownReceipt(t *testing.T) {
	for _, scenario := range []string{"accepted", "bad-auth", "wrong-sequence", "rejected", "lost-receipt"} {
		t.Run(scenario, func(t *testing.T) {
			key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			require.NoError(t, e)
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"cmpp.example.invalid"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			require.NoError(t, e)
			listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
			require.NoError(t, e)
			defer listener.Close()
			done := make(chan struct{})
			var submits atomic.Int32
			go func() {
				defer close(done)
				conn, e := listener.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				body, e := readFrame(conn, 1, 1)
				if e != nil || len(body) != 27 {
					return
				}
				stamp := binary.BigEndian.Uint32(body[23:])
				_ = stamp
				proof := append([]byte{0}, body[6:22]...)
				proof = append(proof, []byte("synthetic-cmpp-secret")...)
				digest := md5.Sum(proof)
				reply := append([]byte{0}, digest[:]...)
				reply = append(reply, 0x20)
				if scenario == "bad-auth" {
					reply[1] ^= 0xff
				}
				if writeFrame(conn, 0x80000001, 1, reply) != nil {
					return
				}
				body, e = readFrame(conn, 4, 2)
				if e != nil {
					return
				}
				submits.Add(1)
				if len(body) < 160 || body[12+10+1+21+2] != 8 {
					return
				}
				if scenario == "lost-receipt" {
					return
				}
				reply = binary.BigEndian.AppendUint64(nil, 1234)
				result := byte(0)
				if scenario == "rejected" {
					result = 8
				}
				reply = append(reply, result)
				sequence := uint32(2)
				if scenario == "wrong-sequence" {
					sequence = 3
				}
				_ = writeFrame(conn, 0x80000004, sequence, reply)
			}()
			client := New()
			client.DialTLS = func(ctx context.Context, address string, tc *tls.Config) (net.Conn, error) {
				return (&tls.Dialer{Config: tc}).DialContext(ctx, "tcp", listener.Addr().String())
			}
			cfg := SMSConfig{AccessKeyID: "123456", Endpoint: "tls://cmpp.example.invalid:7890", Sender: "106900001", SignName: "Synthetic", Verification: Template{ID: "Code {code}", Parameters: []string{"code"}}, Notification: Template{ID: "{state}", Parameters: []string{"state"}}}
			ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			out := client.SendSMS(t.Context(), "cmpp", cfg, "synthetic-cmpp-secret", ca, "+8613800000000", "synthetic-cmpp-001", true, map[string]string{"code": "123456"}, nil)
			want := "sent"
			if scenario == "bad-auth" || scenario == "rejected" {
				want = "failed"
			}
			if scenario == "wrong-sequence" || scenario == "lost-receipt" {
				want = "uncertain"
			}
			assert.Equal(t, want, out.State)
			if scenario == "bad-auth" {
				assert.Zero(t, submits.Load())
			} else {
				assert.EqualValues(t, 1, submits.Load())
			}
			assert.NotContains(t, out.Code, "123456")
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("CMPP fixture did not stop")
			}
		})
	}
}
func TestNativeNotificationCMPPRejectsOversizeAndPartialFrame(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer a.Close()
		_, _ = a.Write([]byte{0, 0, 0, 100, 0, 0, 0, 4, 0, 0, 0, 2, 1})
	}()
	_, e := readFrame(b, 4, 2)
	require.Error(t, e)
	_ = b.Close()
	<-done
	c := New()
	cfg := SMSConfig{AccessKeyID: "123456", Endpoint: "tls://cmpp.example.invalid:7890", Sender: "106900001", SignName: "Synthetic", Verification: Template{ID: "Code {code}", Parameters: []string{"code"}}, Notification: Template{ID: strings.Repeat("x", 71), Parameters: []string{}}}
	out := c.SendSMS(t.Context(), "cmpp", cfg, "synthetic-cmpp-secret", "", "+8613800000000", "id", false, map[string]string{}, nil)
	assert.Equal(t, "failed", out.State)
	var sink io.Writer = io.Discard
	require.NoError(t, writeFrame(sink, 4, 2, []byte("payload")))
}
