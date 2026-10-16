package main

import (
	"github.com/neko233-com/jumpserver233/server/testsupport/samlprovider"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := os.Getenv("JMS_QA_SAML_ADDR")
	if addr == "" {
		addr = "127.0.0.1:12235"
	}
	host, _, e := net.SplitHostPort(addr)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("synthetic SAML requires literal loopback listener")
	}
	p, e := samlprovider.New("http://" + addr)
	if e != nil {
		log.Fatal(e)
	}
	s := &http.Server{Addr: addr, Handler: p, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(s.ListenAndServe())
}
