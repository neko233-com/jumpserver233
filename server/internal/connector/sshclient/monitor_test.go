package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

func TestMacMetricsCommandParsesDarwinUtilities(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("POSIX shell unavailable")
	}
	fixture := `
uname() { echo Darwin; }
sysctl() { case "$2" in hw.ncpu) echo 10;; hw.memsize) echo 17179869184;; esac; }
top() { printf '%s\n' 'CPU usage: 8.82% user, 14.70% sys, 76.47% idle'; }
vm_stat() { printf '%s\n' 'Mach Virtual Memory Statistics: (page size of 16384 bytes)' 'Pages free: 1000.' 'Pages inactive: 2000.' 'Pages speculative: 100.'; }
netstat() { printf '%s\n' 'en0 1500 <Link#7> d0:11:e5:d4:9c:05 100 0 1234 200 0 5678 0' 'lo0 16384 <Link#1> 100 0 999 100 0 999 0'; }
df() { printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted' '/dev/disk 100000 60000 40000 60% /System/Volumes/Data'; }
`
	output, err := exec.Command(shell, "-c", fixture+metricsCommand).CombinedOutput()
	if err != nil {
		t.Fatalf("Darwin fixture: %v: %s", err, output)
	}
	got, err := parseMetrics(strings.NewReader(string(output)))
	if err != nil {
		t.Fatalf("invalid Darwin metrics: %v: %s", err, output)
	}
	if got.CPUCores != 10 || got.CPUPercent != 23.53 || got.MemoryTotalBytes != 17179869184 || got.NetworkReceivedBytes != 1234 || got.NetworkSentBytes != 5678 || got.DiskUsedBytes != 60000*1024 || got.DiskPercent != 60 {
		t.Fatalf("unexpected Darwin metrics: %+v", got)
	}
}

func TestProbeCollectsMetricsAndPinsHostKey(t *testing.T) {
	listener, fingerprint := startMetricsServer(t)
	defer listener.Close()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscan(portText, &port); err != nil {
		t.Fatal(err)
	}

	metrics, err := Probe(context.Background(), Target{
		Host:               host,
		Port:               port,
		Username:           "monitor",
		HostKeyFingerprint: fingerprint,
	}, Credentials{Password: "test-only"}, 2*time.Second)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if metrics.CPUCores != 8 || metrics.CPUPercent != 21.5 {
		t.Errorf("CPU metrics = %d cores, %.2f%%; want 8 cores, 21.50%%", metrics.CPUCores, metrics.CPUPercent)
	}
	if metrics.MemoryTotalBytes != 16<<30 || metrics.MemoryUsedBytes != 8<<30 || metrics.MemoryPercent != 50 {
		t.Errorf("memory metrics = total %d, used %d, %.2f%%", metrics.MemoryTotalBytes, metrics.MemoryUsedBytes, metrics.MemoryPercent)
	}
	if metrics.NetworkReceivedBytes != 1024 || metrics.NetworkSentBytes != 2048 {
		t.Errorf("network counters = %d received, %d sent", metrics.NetworkReceivedBytes, metrics.NetworkSentBytes)
	}
	if metrics.DiskTotalBytes != 10000 || metrics.DiskUsedBytes != 6500 || metrics.DiskPercent != 65 {
		t.Errorf("disk metrics = total %d, used %d, %.2f%%", metrics.DiskTotalBytes, metrics.DiskUsedBytes, metrics.DiskPercent)
	}
	if metrics.LatencyMillis < 0 || metrics.CollectedAt.IsZero() {
		t.Errorf("probe metadata is incomplete: %+v", metrics)
	}

	_, err = Probe(context.Background(), Target{
		Host:               host,
		Port:               port,
		Username:           "monitor",
		HostKeyFingerprint: "SHA256:wrong-host-key",
	}, Credentials{Password: "test-only"}, 2*time.Second)
	if err == nil {
		t.Fatal("Probe() accepted an unpinned SSH host key")
	}
}

func TestParseMetricsRejectsOutOfRangePercentages(t *testing.T) {
	input := "cpu_cores=4\ncpu_percent=120\nmemory_total_bytes=100\nmemory_used_bytes=50\nmemory_percent=50\nnetwork_received_bytes=1\nnetwork_sent_bytes=2\ndisk_total_bytes=100\ndisk_used_bytes=50\ndisk_percent=50\n"
	if _, err := parseMetrics(strings.NewReader(input)); err == nil {
		t.Fatal("parseMetrics() accepted CPU usage above 100 percent")
	}
}

func TestProbeTimeoutCoversMetricCollection(t *testing.T) {
	listener, fingerprint := startMetricsServerMode(t, true)
	defer listener.Close()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscan(portText, &port); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	_, err = Probe(context.Background(), Target{
		Host:               host,
		Port:               port,
		Username:           "monitor",
		HostKeyFingerprint: fingerprint,
	}, Credentials{Password: "test-only"}, 100*time.Millisecond)
	if err == nil {
		t.Fatal("Probe() returned success without metric output")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Probe() ignored its collection timeout; took %s", elapsed)
	}
}

func startMetricsServer(t *testing.T) (net.Listener, string) {
	return startMetricsServerMode(t, false)
}

func startMetricsServerMode(t *testing.T, stall bool) (net.Listener, string) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := xssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &xssh.ServerConfig{
		PasswordCallback: func(conn xssh.ConnMetadata, password []byte) (*xssh.Permissions, error) {
			if conn.User() != "monitor" || string(password) != "test-only" {
				return nil, xssh.ErrNoAuth
			}
			return nil, nil
		},
	}
	serverConfig.PublicKeyCallback = sshidentity.PublicKeyCallback("monitor")
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	output := "cpu_cores=8\ncpu_percent=21.50\nmemory_total_bytes=17179869184\nmemory_used_bytes=8589934592\nmemory_percent=50.00\nnetwork_received_bytes=1024\nnetwork_sent_bytes=2048\ndisk_total_bytes=10000\ndisk_used_bytes=6500\ndisk_percent=65\n"
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveMetricsConnection(connection, serverConfig, output, stall)
		}
	}()
	return listener, xssh.FingerprintSHA256(signer.PublicKey())
}

func serveMetricsConnection(connection net.Conn, config *xssh.ServerConfig, output string, stall bool) {
	serverConnection, channels, requests, err := xssh.NewServerConn(connection, config)
	if err != nil {
		_ = connection.Close()
		return
	}
	go xssh.DiscardRequests(requests)
	defer serverConnection.Close()
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(xssh.UnknownChannelType, "unsupported channel")
			continue
		}
		channel, requests, acceptErr := newChannel.Accept()
		if acceptErr != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for request := range requests {
				if request.Type != "exec" {
					_ = request.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				if err := xssh.Unmarshal(request.Payload, &payload); err != nil || payload.Command != metricsCommand {
					_ = request.Reply(false, nil)
					return
				}
				_ = request.Reply(true, nil)
				if stall {
					for range requests {
					}
					return
				}
				_, _ = channel.Write([]byte(output))
				_, _ = channel.SendRequest("exit-status", false, xssh.Marshal(struct{ Status uint32 }{Status: 0}))
				return
			}
		}()
	}
}
