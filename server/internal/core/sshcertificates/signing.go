package sshcertificates

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	xssh "golang.org/x/crypto/ssh"
)

func encodePEM(block *pem.Block) []byte { return pem.EncodeToMemory(block) }
func parseAuthority(value string) (xssh.PublicKey, error) {
	if len(value) > 16384 {
		return nil, ErrInvalid
	}
	key, _, options, rest, e := xssh.ParseAuthorizedKey([]byte(value))
	if e != nil || len(options) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, ErrInvalid
	}
	switch key.Type() {
	case xssh.KeyAlgoED25519, xssh.KeyAlgoECDSA256, xssh.KeyAlgoECDSA384, xssh.KeyAlgoECDSA521, xssh.KeyAlgoRSA:
		return key, nil
	}
	return nil, ErrInvalid
}
func validateRemote(in Input) error {
	u, e := url.Parse(in.Endpoint)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || len(in.Endpoint) > 2048 {
		return ErrInvalid
	}
	loopback := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return ErrInvalid
	}
	for _, path := range []string{in.Mount, in.Role} {
		if !resourcePattern.MatchString(path) {
			return ErrInvalid
		}
	}
	if strings.Contains(in.Namespace, "..") || strings.HasPrefix(in.Namespace, "/") {
		return ErrInvalid
	}
	if in.RootCAPEM != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(in.RootCAPEM)) {
			return ErrInvalid
		}
	}
	return nil
}
func remoteSign(a authority, publicKey, keyID, principal string) (*xssh.Certificate, error) {
	body, _ := json.Marshal(map[string]any{"public_key": publicKey, "valid_principals": principal, "key_id": keyID, "cert_type": "user", "ttl": fmt.Sprintf("%ds", a.TTLSeconds), "critical_options": map[string]string{}, "extensions": map[string]string{"permit-pty": "", "permit-port-forwarding": ""}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", a.Endpoint+"/v1/"+a.Mount+"/sign/"+a.Role, bytes.NewReader(body))
	if e != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", a.SecretToken)
	if a.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", a.Namespace)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if a.RootCAPEM != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(a.RootCAPEM)) {
			return nil, ErrInvalid
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, ErrUnavailable
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(raw) > 65536 {
		return nil, ErrUnavailable
	}
	var value struct {
		Data struct {
			SignedKey string `json:"signed_key"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return nil, ErrUnavailable
	}
	key, _, options, rest, e := xssh.ParseAuthorizedKey([]byte(value.Data.SignedKey))
	if e != nil || len(options) > 0 || len(bytes.TrimSpace(rest)) > 0 {
		return nil, ErrUnavailable
	}
	cert, ok := key.(*xssh.Certificate)
	if !ok {
		return nil, ErrUnavailable
	}
	return cert, nil
}
func validateCertificate(a authority, t Target, cert *xssh.Certificate, key xssh.PublicKey, now time.Time) error {
	ca, e := parseAuthority(a.PublicKey)
	if e != nil || cert == nil || cert.Key == nil || cert.SignatureKey == nil || cert.CertType != xssh.UserCert || !bytes.Equal(cert.Key.Marshal(), key.Marshal()) || !bytes.Equal(cert.SignatureKey.Marshal(), ca.Marshal()) || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != t.Username || len(cert.CriticalOptions) > 0 || cert.ValidAfter > uint64(now.Unix()+5) || cert.ValidBefore > uint64(now.Add(time.Duration(a.TTLSeconds)*time.Second+5*time.Second).Unix()) || cert.ValidBefore <= uint64(now.Add(15*time.Second).Unix()) {
		return ErrUnavailable
	}
	for name, value := range cert.Extensions {
		if value != "" || name != "permit-pty" && name != "permit-port-forwarding" {
			return ErrUnavailable
		}
	}
	if cert.Signature == nil || cert.Signature.Format == xssh.KeyAlgoRSA {
		return ErrUnavailable
	}
	checker := xssh.CertChecker{Clock: func() time.Time { return now }}
	if checker.CheckCert(t.Username, cert) != nil {
		return ErrUnavailable
	}
	return nil
}
func cloneCredentials(c sshclient.Credentials) sshclient.Credentials {
	return sshclient.Credentials{Password: c.Password, PrivateKey: append([]byte{}, c.PrivateKey...), Certificate: append([]byte{}, c.Certificate...)}
}
func (s *Store) Resolve(t Target, fallback sshclient.Credentials) (out sshclient.Credentials, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return sshclient.Credentials{}, ErrClosed
	}
	b, exists := s.data.Bindings[t.AssetID]
	if !exists || b.IssuerID == "" {
		return fallback, nil
	}
	if !ValidTarget(t) || b.EndpointHash != digest(t) {
		return sshclient.Credentials{}, ErrConflict
	}
	a, ok := s.data.Issuers[b.IssuerID]
	if !ok || !a.Enabled {
		return sshclient.Credentials{}, ErrUnavailable
	}
	now := s.now().UTC()
	identity := s.identity(t.AssetID)
	if c, exists := s.cache[t.AssetID]; exists && c.Identity == identity && now.Before(c.Expires) {
		return cloneCredentials(c.Credentials), nil
	}
	if f, exists := s.flights[t.AssetID]; exists {
		s.mu.Unlock()
		<-f.done
		s.mu.Lock()
		if s.closed {
			return sshclient.Credentials{}, ErrClosed
		}
		if s.identity(t.AssetID) != identity {
			return sshclient.Credentials{}, ErrConflict
		}
		return cloneCredentials(f.credentials), f.err
	}
	f := &issuance{done: make(chan struct{})}
	s.flights[t.AssetID] = f
	defer func() {
		f.credentials = cloneCredentials(out)
		f.err = err
		delete(s.flights, t.AssetID)
		close(f.done)
	}()
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return sshclient.Credentials{}, e
	}
	signer, e := xssh.NewSignerFromKey(private)
	if e != nil {
		return sshclient.Credentials{}, e
	}
	keyID := "jms233/" + t.AssetID
	var cert *xssh.Certificate
	st := s.copy()
	if a.Provider == "builtin" {
		if st.Serial == math.MaxUint64 {
			return sshclient.Credentials{}, ErrCapacity
		}
		st.Serial++
		cert = &xssh.Certificate{Key: signer.PublicKey(), Serial: st.Serial, CertType: xssh.UserCert, KeyId: keyID, ValidPrincipals: []string{t.Username}, ValidAfter: uint64(now.Add(-30 * time.Second).Unix()), ValidBefore: uint64(now.Add(time.Duration(a.TTLSeconds) * time.Second).Unix()), Permissions: xssh.Permissions{Extensions: map[string]string{"permit-pty": "", "permit-port-forwarding": ""}}}
		ca, e := xssh.ParsePrivateKey(a.PrivateKey)
		if e != nil {
			return sshclient.Credentials{}, ErrUnavailable
		}
		if e = cert.SignCert(rand.Reader, ca); e != nil {
			return sshclient.Credentials{}, ErrUnavailable
		}
	} else {
		s.mu.Unlock()
		cert, e = remoteSign(a, strings.TrimSpace(string(xssh.MarshalAuthorizedKey(signer.PublicKey()))), keyID, t.Username)
		s.mu.Lock()
		if s.closed {
			return sshclient.Credentials{}, ErrClosed
		}
		if s.identity(t.AssetID) != identity {
			return sshclient.Credentials{}, ErrConflict
		}
		if e != nil {
			return sshclient.Credentials{}, e
		}
		st = s.copy()
	}
	if e = validateCertificate(a, t, cert, signer.PublicKey(), now); e != nil {
		return sshclient.Credentials{}, e
	}
	encoded, e := xssh.MarshalPrivateKey(private, "")
	if e != nil {
		return sshclient.Credentials{}, e
	}
	c := sshclient.Credentials{PrivateKey: encodePEM(encoded), Certificate: xssh.MarshalAuthorizedKey(cert)}
	before := time.Unix(int64(cert.ValidBefore), 0).UTC()
	appendAudit(&st, Audit{At: now, Action: "issue", IssuerID: a.ID, AssetID: t.AssetID, Revision: b.Revision, Serial: cert.Serial, Fingerprint: xssh.FingerprintSHA256(signer.PublicKey()), ValidBefore: before})
	if e = s.persist(st); e != nil {
		return sshclient.Credentials{}, e
	}
	s.data = st
	s.cache[t.AssetID] = cached{Identity: identity, Credentials: cloneCredentials(c), Expires: before.Add(-15 * time.Second)}
	return c, nil
}
