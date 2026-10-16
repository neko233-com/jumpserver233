// Package databasewire provides verified, pinned non-SSH database transports.
package databasewire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sqlclient"
	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	"net"
	"strconv"
	"time"
)

func Dial(ctx context.Context, t sqlclient.Target) (net.Conn, error) {
	if sqlclient.ValidateSettings(t.Settings) != nil || t.Host == "" || t.Port < 1 || t.Port > 65535 {
		return nil, sqlclient.ErrInvalid
	}
	raw, e := sshclient.DialTunnel(ctx, t.Gateways, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), 5*time.Second)
	if e != nil {
		return nil, e
	}
	if t.TLSMode == "disable" {
		return raw, nil
	}
	name := t.ServerName
	if name == "" {
		name = t.Host
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
	if t.RootCAPEM != "" {
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(t.RootCAPEM)) {
			raw.Close()
			return nil, sqlclient.ErrInvalid
		}
		tc.RootCAs = pool
	}
	secured := tls.Client(raw, tc)
	handshake, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	if e = secured.HandshakeContext(handshake); e != nil {
		raw.Close()
		return nil, e
	}
	return secured, nil
}
