package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/neko233-com/jumpserver233/server/testsupport/casprovider"
)

func main() {
	addr := os.Getenv("JMS_QA_CAS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:12233"
	}
	host, _, e := net.SplitHostPort(addr)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("synthetic CAS requires literal loopback listener")
	}
	provider := casprovider.New("http://"+addr+"/cas", casprovider.Options{})
	server := &http.Server{Addr: addr, Handler: provider, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
