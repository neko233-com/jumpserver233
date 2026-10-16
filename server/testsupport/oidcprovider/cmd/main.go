package main

import (
	"log"
	"net"
	"net/http"
	"os"

	"github.com/neko233-com/jumpserver233/server/testsupport/oidcprovider"
)

func main() {
	addr := os.Getenv("JMS_QA_OIDC_ADDR")
	if addr == "" {
		addr = "127.0.0.1:12226"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("synthetic IdP must listen on a literal loopback address")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	provider, err := oidcprovider.New("http://"+listener.Addr().String(), oidcprovider.Options{})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.Serve(listener, provider))
}
