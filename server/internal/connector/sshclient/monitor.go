package sshclient

import (
	"bufio"
	"context"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/internal/workgate"
	"net"
	"strconv"
	"strings"
	"time"

	xssh "golang.org/x/crypto/ssh"
)

// Target identifies an SSH endpoint and its out-of-band verified host key.
type Target struct {
	Admission          *workgate.Gate `json:"-"`
	Gateways           []Hop          `json:"-"`
	HostKeyFingerprint string
	Host               string
	Username           string
	Port               int
}

// Credentials are supplied by the server-side vault and are never returned to callers.
type Credentials struct {
	Password    string
	PrivateKey  []byte
	Certificate []byte `json:"certificate,omitempty"`
}

// Metrics contains host counters from one SSH probe. Rates are calculated by the
// monitoring service from successive NetworkReceivedBytes and NetworkSentBytes.
type Metrics struct {
	CollectedAt          time.Time `json:"collected_at"`
	CPUPercent           float64   `json:"cpu_percent"`
	MemoryPercent        float64   `json:"memory_percent"`
	DiskPercent          float64   `json:"disk_percent"`
	LatencyMillis        int64     `json:"latency_ms"`
	CPUCores             int       `json:"cpu_cores"`
	MemoryTotalBytes     int64     `json:"memory_total_bytes"`
	MemoryUsedBytes      int64     `json:"memory_used_bytes"`
	NetworkReceivedBytes int64     `json:"network_received_bytes"`
	NetworkSentBytes     int64     `json:"network_sent_bytes"`
	DiskTotalBytes       int64     `json:"disk_total_bytes"`
	DiskUsedBytes        int64     `json:"disk_used_bytes"`
}

// Probe collects Linux or macOS host metrics over SSH. It requires a pinned host-key
// fingerprint; unknown or changed host keys fail closed.
func Probe(ctx context.Context, target Target, credentials Credentials, timeout time.Duration) (Metrics, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, latency, err := dial(ctx, target, credentials, timeout)
	if err != nil {
		return Metrics{}, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return Metrics{}, fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()

	type commandResult struct {
		output []byte
		err    error
	}
	result := make(chan commandResult, 1)
	go func() {
		output, commandErr := session.Output(metricsCommand)
		result <- commandResult{output: output, err: commandErr}
	}()

	var output []byte
	select {
	case <-ctx.Done():
		_ = session.Close()
		return Metrics{}, ctx.Err()
	case command := <-result:
		if command.err != nil {
			return Metrics{}, fmt.Errorf("collect SSH metrics: %w", command.err)
		}
		output = command.output
	}

	metrics, err := parseMetrics(strings.NewReader(string(output)))
	if err != nil {
		return Metrics{}, err
	}
	metrics.LatencyMillis = latency.Milliseconds()
	metrics.CollectedAt = time.Now().UTC()
	return metrics, nil
}

func dial(ctx context.Context, target Target, credentials Credentials, timeout time.Duration) (*xssh.Client, time.Duration, error) {
	return dialRoute(ctx, target, credentials, timeout)
}
func clientConfig(target Target, credentials Credentials) (*xssh.ClientConfig, error) {
	if strings.TrimSpace(target.Host) == "" || strings.TrimSpace(target.Username) == "" {
		return nil, fmt.Errorf("SSH host and username are required")
	}
	if target.Port < 1 || target.Port > 65535 {
		return nil, fmt.Errorf("SSH port is invalid")
	}
	if !strings.HasPrefix(target.HostKeyFingerprint, "SHA256:") {
		return nil, fmt.Errorf("a pinned SHA256 SSH host-key fingerprint is required")
	}

	methods := make([]xssh.AuthMethod, 0, 2)
	if len(credentials.Certificate) > 0 && (len(credentials.PrivateKey) == 0 || credentials.Password != "") {
		return nil, fmt.Errorf("SSH certificate requires its private key without password fallback")
	}
	if credentials.Password != "" {
		methods = append(methods, xssh.Password(credentials.Password))
	}
	if len(credentials.PrivateKey) > 0 {
		signer, err := xssh.ParsePrivateKey(credentials.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		if len(credentials.Certificate) > 0 {
			public, _, options, rest, e := xssh.ParseAuthorizedKey(credentials.Certificate)
			cert, ok := public.(*xssh.Certificate)
			if e != nil || !ok || len(options) > 0 || strings.TrimSpace(string(rest)) != "" || cert.CertType != xssh.UserCert || len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != target.Username {
				return nil, fmt.Errorf("invalid SSH user certificate")
			}
			if e = (&xssh.CertChecker{}).CheckCert(target.Username, cert); e != nil {
				return nil, fmt.Errorf("invalid SSH user certificate")
			}
			signer, e = xssh.NewCertSigner(cert, signer)
			if e != nil {
				return nil, fmt.Errorf("SSH certificate key mismatch")
			}
		}
		methods = append(methods, xssh.PublicKeys(signer))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("SSH password or private key is required")
	}

	return &xssh.ClientConfig{User: target.Username, Auth: methods, HostKeyCallback: pinnedHostKey(target.HostKeyFingerprint)}, nil
}

func pinnedHostKey(expected string) xssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key xssh.PublicKey) error {
		actual := xssh.FingerprintSHA256(key)
		if actual != expected {
			return fmt.Errorf("SSH host-key fingerprint mismatch for %s", hostname)
		}
		return nil
	}
}

const metricsCommand = `set -eu
export LC_ALL=C
case "$(uname -s)" in
Darwin)
cores=$(sysctl -n hw.ncpu)
memory_total=$(sysctl -n hw.memsize)
cpu_percent=$(top -l 2 -s 1 -n 0 | awk '/^CPU usage:/ {gsub("%", "", $7); idle=$7} END {if (idle == "") exit 1; printf "%.2f", 100-idle}')
set -- $(vm_stat | awk 'NR==1 {page=$8} /^Pages free:/ {free=$3} /^Pages inactive:/ {inactive=$3} /^Pages speculative:/ {speculative=$3} END {gsub(/\./,"",free); gsub(/\./,"",inactive); gsub(/\./,"",speculative); if (page<=0) exit 1; printf "%.0f", (free+inactive+speculative)*page}')
memory_used=$(awk -v total="$memory_total" -v available="$1" 'BEGIN {used=total-available; if (used<0) used=0; if (used>total) used=total; printf "%.0f", used}')
memory_percent=$(awk -v used="$memory_used" -v total="$memory_total" 'BEGIN {if (total<=0) exit 1; printf "%.2f", 100*used/total}')
set -- $(netstat -ibn | awk '$1 != "lo0" && $3 ~ /^<Link#/ && $4 ~ /:/ {rx += $7; tx += $10} END {printf "%.0f %.0f", rx, tx}')
network_received=$1
network_sent=$2
set -- $(df -k /System/Volumes/Data | awk 'NR==2 {gsub(/%/, "", $5); printf "%.0f %.0f %s", $2*1024, $3*1024, $5}')
disk_total=$1
disk_used=$2
disk_percent=$3
;;
Linux)
cores=$(getconf _NPROCESSORS_ONLN)
set -- $(awk '/^cpu / { total=0; for (i=2; i<=NF; i++) total += $i; print total, $5+$6 }' /proc/stat)
before_total=$1
before_idle=$2
sleep 1
set -- $(awk '/^cpu / { total=0; for (i=2; i<=NF; i++) total += $i; print total, $5+$6 }' /proc/stat)
cpu_percent=$(awk -v bt="$before_total" -v bi="$before_idle" -v at="$1" -v ai="$2" 'BEGIN { dt=at-bt; di=ai-bi; if (dt <= 0) print 0; else printf "%.2f", 100*(dt-di)/dt }')
set -- $(awk '/^MemTotal:/ { total=$2 } /^MemAvailable:/ { available=$2 } END { printf "%.0f %.0f", total*1024, (total-available)*1024 }' /proc/meminfo)
memory_total=$1
memory_used=$2
memory_percent=$(awk -v used="$memory_used" -v total="$memory_total" 'BEGIN { if (total <= 0) print 0; else printf "%.2f", 100*used/total }')
set -- $(awk 'NR>2 { sub(":", "", $1); if ($1 != "lo") { rx += $2; tx += $10 } } END { printf "%.0f %.0f", rx, tx }' /proc/net/dev)
network_received=$1
network_sent=$2
set -- $(df -P -B1 / | awk 'NR==2 { gsub(/%/, "", $5); print $2, $3, $5 }')
disk_total=$1
disk_used=$2
disk_percent=$3
;;
*) exit 1 ;;
esac
printf 'cpu_cores=%s\ncpu_percent=%s\nmemory_total_bytes=%s\nmemory_used_bytes=%s\nmemory_percent=%s\nnetwork_received_bytes=%s\nnetwork_sent_bytes=%s\ndisk_total_bytes=%s\ndisk_used_bytes=%s\ndisk_percent=%s\n' "$cores" "$cpu_percent" "$memory_total" "$memory_used" "$memory_percent" "$network_received" "$network_sent" "$disk_total" "$disk_used" "$disk_percent"`

func parseMetrics(reader *strings.Reader) (Metrics, error) {
	values := make(map[string]string, 10)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || key == "" {
			return Metrics{}, fmt.Errorf("invalid SSH metrics output")
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return Metrics{}, fmt.Errorf("read SSH metrics output: %w", err)
	}

	metrics := Metrics{}
	var err error
	if metrics.CPUCores, err = parseInt(values, "cpu_cores"); err != nil || metrics.CPUCores < 1 {
		return Metrics{}, fmt.Errorf("invalid SSH CPU core count")
	}
	if metrics.CPUPercent, err = parsePercent(values, "cpu_percent"); err != nil {
		return Metrics{}, err
	}
	if metrics.MemoryTotalBytes, err = parseInt64(values, "memory_total_bytes"); err != nil || metrics.MemoryTotalBytes <= 0 {
		return Metrics{}, fmt.Errorf("invalid SSH memory total")
	}
	if metrics.MemoryUsedBytes, err = parseInt64(values, "memory_used_bytes"); err != nil || metrics.MemoryUsedBytes < 0 || metrics.MemoryUsedBytes > metrics.MemoryTotalBytes {
		return Metrics{}, fmt.Errorf("invalid SSH memory usage")
	}
	if metrics.MemoryPercent, err = parsePercent(values, "memory_percent"); err != nil {
		return Metrics{}, err
	}
	if metrics.NetworkReceivedBytes, err = parseInt64(values, "network_received_bytes"); err != nil || metrics.NetworkReceivedBytes < 0 {
		return Metrics{}, fmt.Errorf("invalid SSH received-byte counter")
	}
	if metrics.NetworkSentBytes, err = parseInt64(values, "network_sent_bytes"); err != nil || metrics.NetworkSentBytes < 0 {
		return Metrics{}, fmt.Errorf("invalid SSH sent-byte counter")
	}
	if metrics.DiskTotalBytes, err = parseInt64(values, "disk_total_bytes"); err != nil || metrics.DiskTotalBytes <= 0 {
		return Metrics{}, fmt.Errorf("invalid SSH disk total")
	}
	if metrics.DiskUsedBytes, err = parseInt64(values, "disk_used_bytes"); err != nil || metrics.DiskUsedBytes < 0 || metrics.DiskUsedBytes > metrics.DiskTotalBytes {
		return Metrics{}, fmt.Errorf("invalid SSH disk usage")
	}
	if metrics.DiskPercent, err = parsePercent(values, "disk_percent"); err != nil {
		return Metrics{}, err
	}
	return metrics, nil
}

func parseInt(values map[string]string, key string) (int, error) {
	value, err := parseInt64(values, key)
	return int(value), err
}

func parseInt64(values map[string]string, key string) (int64, error) {
	value, ok := values[key]
	if !ok {
		return 0, fmt.Errorf("missing SSH metric %q", key)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid SSH metric %q", key)
	}
	return parsed, nil
}

func parsePercent(values map[string]string, key string) (float64, error) {
	value, ok := values[key]
	if !ok {
		return 0, fmt.Errorf("missing SSH metric %q", key)
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 || parsed > 100 {
		return 0, fmt.Errorf("invalid SSH metric %q", key)
	}
	return parsed, nil
}
