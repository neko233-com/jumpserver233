package main

import (
	"encoding/json"
	"fmt"
	"github.com/neko233-com/jumpserver233/server/testsupport/notificationfixture"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func port(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < 1 || n > 65535 {
		panic("invalid capture port")
	}
	return n
}
func main() {
	fixture, e := notificationfixture.Start(notificationfixture.Options{Host: "0.0.0.0", SMTPPort: port("JMS_QA_NOTIFICATION_SMTP_PORT", 12601), STARTTLSPort: port("JMS_QA_NOTIFICATION_STARTTLS_PORT", 12602), HTTPSPort: port("JMS_QA_NOTIFICATION_HTTPS_PORT", 12603)})
	if e != nil {
		panic("cannot start synthetic capture")
	}
	defer fixture.Close()
	health := map[string]any{"smtp_port": port("JMS_QA_NOTIFICATION_SMTP_PORT", 12601), "starttls_port": port("JMS_QA_NOTIFICATION_STARTTLS_PORT", 12602), "https_port": port("JMS_QA_NOTIFICATION_HTTPS_PORT", 12603), "ca": fixture.CA}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(health) })
	mux.HandleFunc("GET /messages", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(fixture.Records()) })
	listener, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port("JMS_QA_NOTIFICATION_HEALTH_PORT", 12604)))
	if e != nil {
		panic("cannot start capture control")
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go server.Serve(listener)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
	_ = server.Close()
}
