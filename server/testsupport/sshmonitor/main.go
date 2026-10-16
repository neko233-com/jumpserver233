// Command sshmonitor runs a local-only synthetic SSH host for browser E2E tests.
// It must never be used as an SSH server outside the test environment.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshidentity"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshUsername   = "qa-monitor"
	sshPassword   = "synthetic-qa-only-password"
	metricsOutput = "cpu_cores=4\ncpu_percent=5.25\nmemory_total_bytes=8589934592\nmemory_used_bytes=2147483648\nmemory_percent=25.00\nnetwork_received_bytes=104857600\nnetwork_sent_bytes=52428800\ndisk_total_bytes=107374182400\ndisk_used_bytes=42949672960\ndisk_percent=40\n"
)

func main() {
	seed := sha256.Sum256([]byte("jumpserver233 local browser E2E SSH host key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatal(err)
	}
	serverConfig := &ssh.ServerConfig{PasswordCallback: func(connection ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if connection.User() != sshUsername || string(password) != sshPassword {
			return nil, errors.New("synthetic test account rejected")
		}
		return nil, nil
	}}
	serverConfig.PublicKeyCallback = sshidentity.PublicKeyCallback("qa-key")
	serverConfig.AddHostKey(signer)

	sshAddress := env("JMS_QA_SSH_ADDR", "127.0.0.1:2222")
	sshListener, err := net.Listen("tcp", sshAddress)
	if err != nil {
		log.Fatal(err)
	}
	go acceptSSH(sshListener, serverConfig)

	info := struct {
		KeyUsername    string `json:"key_username"`
		KeyFingerprint string `json:"key_fingerprint"`
		Fingerprint    string `json:"fingerprint"`
		Address        string `json:"address"`
		Username       string `json:"username"`
	}{
		KeyUsername: "qa-key", KeyFingerprint: ssh.FingerprintSHA256(sshidentity.Signer().PublicKey()),
		Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
		Address:     sshAddress,
		Username:    sshUsername,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	})
	httpAddress := env("JMS_QA_HTTP_ADDR", "127.0.0.1:2223")
	httpServer := &http.Server{
		Addr:              httpAddress,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- httpServer.ListenAndServe()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	_ = sshListener.Close()
}

func acceptSSH(listener net.Listener, config *ssh.ServerConfig) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("accept synthetic SSH connection: %v", err)
			}
			return
		}
		go serveConnection(connection, config)
	}
}

func serveConnection(connection net.Conn, config *ssh.ServerConfig) {
	serverConnection, channels, requests, err := ssh.NewServerConn(connection, config)
	if err != nil {
		_ = connection.Close()
		return
	}
	defer serverConnection.Close()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		stream, channelRequests, err := channel.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer stream.Close()
			for request := range channelRequests {
				if request.Type == "shell" {
					_ = request.Reply(true, nil)
					_, _ = stream.Write([]byte("synthetic routed terminal ready\r\n"))
					_, _ = io.Copy(stream, stream)
					return
				}
				if request.Type == "exec" {
					var payload struct{ Command string }
					if ssh.Unmarshal(request.Payload, &payload) != nil {
						_ = request.Reply(false, nil)
						return
					}
					_ = request.Reply(true, nil)
					status := uint32(0)
					switch {
					case strings.Contains(payload.Command, "cpu_cores="):
						_, _ = stream.Write([]byte(metricsOutput))
					case payload.Command == "printf browser-job-ok":
						_, _ = stream.Write([]byte("browser-job-ok\n"))
					default:
						status = 7
						_, _ = stream.Stderr().Write([]byte("unsupported synthetic command\n"))
					}
					_, _ = stream.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status}))
					return
				}
				_ = request.Reply(true, nil)
			}
		}()
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
