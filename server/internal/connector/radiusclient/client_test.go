package radiusclient

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test server encoding is independent of the production response decoder.
func responsePacket(request []byte, code byte, secret []byte, attributes ...[]byte) []byte {
	p := make([]byte, 20)
	p[0] = code
	p[1] = request[1]
	copy(p[4:20], request[4:20])
	for _, a := range attributes {
		p = append(p, a...)
	}
	p = append(p, 80, 18)
	p = append(p, make([]byte, 16)...)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	h := hmac.New(md5.New, secret)
	h.Write(p)
	copy(p[len(p)-16:], h.Sum(nil))
	signResponse(p, request, secret)
	return p
}
func signResponse(p, request, secret []byte) {
	h := md5.New()
	h.Write(p[:4])
	h.Write(request[4:20])
	h.Write(p[20:])
	h.Write(secret)
	copy(p[4:20], h.Sum(nil))
}
func attributes(p []byte) map[byte][][]byte {
	out := map[byte][][]byte{}
	for pos := 20; pos < len(p); {
		n := int(p[pos+1])
		out[p[pos]] = append(out[p[pos]], p[pos+2:pos+n])
		pos += n
	}
	return out
}
func TestPAPRequestAndAuthenticatedReplies(t *testing.T) {
	secret := []byte("synthetic-radius-shared-secret-233")
	password := strings.Repeat("p", 65)
	p, e := EncodeRequest(Request{Username: "alice", Password: password, State: []byte("state")}, "nas", secret)
	require.NoError(t, e)
	assert.Equal(t, len(p), int(binary.BigEndian.Uint16(p[2:4])))
	a := attributes(p)
	assert.Equal(t, []byte("alice"), a[1][0])
	assert.Equal(t, []byte("state"), a[24][0])
	assert.NotContains(t, string(p), password)
	cipher := a[2][0]
	plain := make([]byte, len(cipher))
	previous := p[4:20]
	for pos := 0; pos < len(cipher); pos += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(previous)
		mask := h.Sum(nil)
		for i := 0; i < 16; i++ {
			plain[pos+i] = cipher[pos+i] ^ mask[i]
		}
		previous = cipher[pos : pos+16]
	}
	assert.Equal(t, password, string(bytes.TrimRight(plain, "\x00")))
	normalized := bytes.Clone(p)
	clear(normalized[len(p)-16:])
	h := hmac.New(md5.New, secret)
	h.Write(normalized)
	assert.Equal(t, h.Sum(nil), a[80][0])
	for _, code := range []byte{AccessAccept, AccessReject, AccessChallenge} {
		reply := responsePacket(p, code, secret, []byte{24, 5, 'a', 'b', 'c'})
		got, e := DecodeReply(p, reply, secret)
		require.NoError(t, e)
		assert.Equal(t, code, got.Code)
		if code == AccessChallenge {
			assert.Equal(t, []byte("abc"), got.State)
		} else {
			assert.Empty(t, got.State)
		}
	}
	_, e = DecodeReply(p, responsePacket(p, AccessChallenge, secret), secret)
	require.NoError(t, e, "State is optional in Access-Challenge")
}
func TestRejectForgedOrAmbiguousPackets(t *testing.T) {
	secret := []byte("synthetic-radius-shared-secret-233")
	request, e := EncodeRequest(Request{Username: "qa", Password: "code"}, "nas", secret)
	require.NoError(t, e)
	cases := map[string]func([]byte) []byte{
		"authenticator": func(p []byte) []byte { p[4] ^= 1; return p }, "identifier": func(p []byte) []byte { p[1]++; return p }, "length": func(p []byte) []byte { p[3]--; return p }, "code": func(p []byte) []byte { p[0] = 5; return p },
		"bad MAC with valid response MD5": func(p []byte) []byte { p[len(p)-1] ^= 1; signResponse(p, request, secret); return p },
		"missing MAC": func(p []byte) []byte {
			p = p[:20]
			binary.BigEndian.PutUint16(p[2:4], 20)
			signResponse(p, request, secret)
			return p
		},
		"duplicate MAC": func(p []byte) []byte {
			return responsePacket(request, AccessAccept, secret, append([]byte{80, 18}, make([]byte, 16)...))
		},
		"duplicate state": func(p []byte) []byte {
			return responsePacket(request, AccessChallenge, secret, []byte{24, 3, 1}, []byte{24, 3, 2})
		},
		"unsolicited proxy state": func(p []byte) []byte { return responsePacket(request, AccessAccept, secret, []byte{33, 3, 1}) },
		"invalid attribute":       func(p []byte) []byte { return responsePacket(request, AccessAccept, secret, []byte{1, 1}) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, e := DecodeReply(request, mutate(responsePacket(request, AccessAccept, secret)), secret)
			require.ErrorIs(t, e, ErrProtocol)
		})
	}
	for _, in := range []Request{{Username: ""}, {Username: "qa", Password: strings.Repeat("p", 129)}, {Username: "qa", State: make([]byte, 254)}, {Username: "qa", Password: "a\x00b"}} {
		_, e := EncodeRequest(in, "nas", secret)
		assert.ErrorIs(t, e, ErrCredentials)
	}
}
func TestUDPBoundedTransportAndCancellation(t *testing.T) {
	listener, e := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, e)
	defer listener.Close()
	secret := []byte("synthetic-radius-shared-secret-233")
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		n, addr, e := listener.ReadFrom(buf)
		if e != nil {
			return
		}
		p := bytes.Clone(buf[:n])
		forged := responsePacket(p, AccessAccept, secret)
		forged[1]++
		listener.WriteTo(forged, addr)
		listener.WriteTo(responsePacket(p, AccessAccept, secret), addr)
	}()
	addr := listener.LocalAddr().(*net.UDPAddr)
	cfg := Config{Host: "127.0.0.1", Port: addr.Port, Transport: "udp", AllowUDP: true, TimeoutSeconds: 1, Attempts: 1}
	got, e := (Native{}).Exchange(t.Context(), cfg, Secrets{SharedSecret: string(secret)}, Request{Username: "qa", Password: "password"})
	require.NoError(t, e)
	assert.Equal(t, AccessAccept, got.Code)
	<-done
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = (Native{}).Exchange(ctx, cfg, Secrets{SharedSecret: string(secret)}, Request{Username: "qa"})
	require.Error(t, e)
	cfg.AllowUDP = false
	require.ErrorIs(t, Validate(cfg, Secrets{SharedSecret: string(secret)}), ErrConfig)
	cfg.AllowUDP = true
	assert.ErrorIs(t, Validate(cfg, Secrets{SharedSecret: "short"}), ErrConfig)
	cfg.Transport = "tcp"
	assert.ErrorIs(t, Validate(cfg, Secrets{}), ErrConfig)
}
func TestRealFreeRADIUSUDPAndMutualTLS(t *testing.T) {
	url := os.Getenv("JMS_TEST_RADIUS_FIXTURE_URL")
	if url == "" {
		t.Skip("set JMS_TEST_RADIUS_FIXTURE_URL for native FreeRADIUS UDP/mTLS integration")
	}
	url = strings.TrimSuffix(url, "/health") + "/credentials"
	fixtureURL, e := neturl.Parse(url)
	require.NoError(t, e)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	require.NoError(t, e)
	res, e := http.DefaultClient.Do(req)
	require.NoError(t, e)
	defer res.Body.Close()
	require.Equal(t, 200, res.StatusCode)
	var fixture struct {
		UDPPort int    `json:"udp_port"`
		TLSPort int    `json:"tls_port"`
		CA      string `json:"root_ca_pem"`
		Cert    string `json:"client_certificate"`
		Key     string `json:"client_key"`
		Secret  string `json:"shared_secret"`
		Name    string `json:"server_name"`
	}
	require.NoError(t, json.NewDecoder(io.LimitReader(res.Body, 128<<10)).Decode(&fixture))
	for _, transport := range []string{"udp", "tls"} {
		t.Run(transport, func(t *testing.T) {
			cfg := Config{Host: fixtureURL.Hostname(), Port: fixture.UDPPort, Transport: transport, AllowUDP: true, TimeoutSeconds: 2, Attempts: 2}
			secrets := Secrets{SharedSecret: fixture.Secret}
			if transport == "tls" {
				cfg.Port = fixture.TLSPort
				cfg.AllowUDP = false
				cfg.ServerName = fixture.Name
				cfg.CAPEM = fixture.CA
				cfg.ClientCertificate = fixture.Cert
				secrets.ClientKey = fixture.Key
			}
			got, e := (Native{}).Exchange(ctx, cfg, secrets, Request{Username: "radius.qa", Password: "synthetic-radius-password-233"})
			require.NoError(t, e)
			assert.Equal(t, AccessAccept, got.Code)
			got, e = (Native{}).Exchange(ctx, cfg, secrets, Request{Username: "radius.qa", Password: "incorrect"})
			require.NoError(t, e)
			assert.Equal(t, AccessReject, got.Code)
			got, e = (Native{}).Exchange(ctx, cfg, secrets, Request{Username: "radius.challenge.qa", Password: "start"})
			require.NoError(t, e)
			require.Equal(t, AccessChallenge, got.Code)
			require.NotEmpty(t, got.State)
			got, e = (Native{}).Exchange(ctx, cfg, secrets, Request{Username: "radius.challenge.qa", Password: "654321", State: got.State})
			require.NoError(t, e)
			assert.Equal(t, AccessAccept, got.Code)
			if transport == "tls" {
				cfg.ServerName = "wrong.synthetic.invalid"
				_, e = (Native{}).Exchange(ctx, cfg, secrets, Request{Username: "radius.qa"})
				assert.Error(t, e)
				cfg.ServerName = fixture.Name
				cfg.CAPEM = ""
				_, e = (Native{}).Exchange(ctx, cfg, secrets, Request{Username: "radius.qa"})
				assert.Error(t, e)
				cfg.CAPEM = fixture.CA
				secrets.ClientKey = ""
				assert.ErrorIs(t, Validate(cfg, secrets), ErrConfig)
			}

		})
	}
}
