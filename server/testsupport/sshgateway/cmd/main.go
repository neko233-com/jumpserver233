package main

import (
	"encoding/json"
	"github.com/neko233-com/jumpserver233/server/testsupport/sshgateway"
	"log"
	"net/http"
	"os"
)

func main() {
	address := os.Getenv("JMS_QA_GATEWAY_ADDR")
	if address == "" {
		address = "127.0.0.1:12237"
	}
	health := os.Getenv("JMS_QA_GATEWAY_HTTP_ADDR")
	if health == "" {
		health = "127.0.0.1:12238"
	}
	destination := os.Getenv("JMS_QA_GATEWAY_TARGET")
	if destination == "" {
		destination = "127.0.0.1:12222"
	}
	keyDestination := os.Getenv("JMS_QA_GATEWAY_KEY_TARGET")
	if keyDestination == "" {
		keyDestination = "127.0.0.1:12241"
	}
	s, e := sshgateway.Start(address, map[string]string{"private.synthetic.invalid:22": destination, "keyhost.synthetic.invalid:22": keyDestination, "postgres.synthetic.invalid:5432": "127.0.0.1:15444", "mysql.synthetic.invalid:3306": "127.0.0.1:15465", "mariadb.synthetic.invalid:3306": "127.0.0.1:15467", "sqlserver.synthetic.invalid:1433": "127.0.0.1:15473", "clickhouse.synthetic.invalid:8443": "127.0.0.1:15483", "redis.synthetic.invalid:6379": "127.0.0.1:15493", "mongodb.synthetic.invalid:27017": "127.0.0.1:15503", "kubernetes.synthetic.invalid:6443": "127.0.0.1:16445", "telnet.synthetic.invalid:992": "127.0.0.1:16994", "rdp.synthetic.invalid:3389": "127.0.0.1:19391"})
	if e != nil {
		log.Fatal(e)
	}
	defer s.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"address": s.Address(), "fingerprint": s.Fingerprint, "username": sshgateway.Username, "forwards": s.Forwards(), "active": s.Active()})
	})
	log.Fatal(http.ListenAndServe(health, mux))
}
