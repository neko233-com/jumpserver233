// Package inventoryprobe discovers bounded TCP endpoints without authenticating
// to the discovered host. Observed SSH keys are evidence, not a trust decision.
package inventoryprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/neko233-com/jumpserver233/server/internal/connector/sshclient"
	xssh "golang.org/x/crypto/ssh"
)

type DialFunc func(context.Context, string) (net.Conn, error)
type Result struct {
	Open               bool   `json:"open"`
	SSHVerified        bool   `json:"ssh_verified"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	LatencyMS          int64  `json:"latency_ms"`
	ErrorCode          string `json:"error_code,omitempty"`
}

var errObservedKey = errors.New("inventory host key observed; authentication disabled")

func Probe(ctx context.Context, host string, port int, protocol string, timeout time.Duration, dial DialFunc) Result {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !(ip.IsGlobalUnicast() || ip.IsLoopback()) || port < 1 || port > 65535 || timeout < 100*time.Millisecond || timeout > 5*time.Second {
		return Result{ErrorCode: "scan_invalid_target"}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if dial == nil {
		dial = func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}
	}
	address := net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(port))
	start := time.Now()
	conn, err := dial(ctx, address)
	if err != nil {
		code := "scan_unreachable"
		var gateway *sshclient.GatewayError
		if errors.As(err, &gateway) {
			code = "scan_gateway_unavailable"
		}
		if ctx.Err() != nil && gateway == nil {
			code = "scan_timeout"
		}
		return Result{LatencyMS: time.Since(start).Milliseconds(), ErrorCode: code}
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	out := Result{Open: true, LatencyMS: time.Since(start).Milliseconds()}
	if protocol != "ssh" {
		return out
	}
	config := &xssh.ClientConfig{User: "inventory-probe", HostKeyCallback: func(_ string, _ net.Addr, key xssh.PublicKey) error {
		out.HostKeyFingerprint = xssh.FingerprintSHA256(key)
		out.SSHVerified = true
		return errObservedKey
	}}
	client, _, _, _ := xssh.NewClientConn(conn, address, config)
	if client != nil {
		_ = client.Close()
	}
	if !out.SSHVerified {
		out.ErrorCode = "scan_ssh_handshake"
	}
	return out
}
