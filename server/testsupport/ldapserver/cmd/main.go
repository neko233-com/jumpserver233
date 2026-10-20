package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/neko233-com/jumpserver233/server/testsupport/ldapserver"
)

func main() {
	addr := os.Getenv("JMS_QA_LDAP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:12229"
	}
	health := os.Getenv("JMS_QA_LDAP_HEALTH_ADDR")
	if health == "" {
		health = "127.0.0.1:12230"
	}
	for _, v := range []string{addr, health} {
		h, _, e := net.SplitHostPort(v)
		if e != nil || net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback() {
			log.Fatal("synthetic directory requires literal loopback listeners")
		}
	}
	s, e := ldapserver.Start(ldapserver.Options{Addr: addr, DirectorySync: true})
	if e != nil {
		log.Fatal("synthetic directory failed")
	}
	defer s.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"url": s.URL, "ca_pem": s.CAPEM})
	})
	server := &http.Server{Addr: health, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
