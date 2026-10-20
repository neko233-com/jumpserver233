package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/neko233-com/jumpserver233/server/testsupport/enterpriseprovider"
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
	enterprise, err := enterpriseprovider.New()
	if err != nil {
		log.Fatal("synthetic enterprise provider failed")
	}
	defer enterprise.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /enterprise/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"ca_pem": enterprise.CAPEM})
	})
	mux.HandleFunc("GET /enterprise/notifications", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(enterprise.NotificationCaptures())
	})
	for _, kind := range []string{"wecom", "dingtalk", "feishu"} {
		mux.HandleFunc("GET /enterprise/authorize/"+kind, func(w http.ResponseWriter, r *http.Request) { enterprise.Authorize(w, r, kind) })
	}
	mux.Handle("/", provider)
	log.Fatal(http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enterprise.HandleProxy(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})))
}
