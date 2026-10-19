// Synthetic native candidate for isolated activation acceptance only.
// The production packager never includes this program.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/neko233-com/jumpserver233/server/internal/maintenance"
)

var failureMode = "before"
var version = "v0.0.2"

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "synthetic candidate startup failure")
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("activationfixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	check := flags.Bool("check-data", false, "")
	upgrade := flags.String("upgrade-id", "", "")
	id := flags.String("activation-id", "", "")
	attempt := flags.String("activation-attempt", "", "")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("invalid fixture")
	}
	data := os.Getenv("JMS_DATA_DIR")
	lock, e := maintenance.Acquire(data)
	if e != nil {
		return e
	}
	defer lock.Close()
	sha, e := maintenance.ExecutableSHA256()
	if e != nil {
		return e
	}
	if *check {
		return maintenance.CheckUpgradeGuard(data, *upgrade, sha)
	}
	g, e := maintenance.CheckActivationGuard(data, *id, *attempt, sha)
	if e != nil {
		return e
	}
	if failureMode == "before" {
		return os.WriteFile(filepath.Join(data, "trial-target-only"), []byte("discard failed trial write"), 0600)
	}
	index, e := os.ReadFile(filepath.Join(os.Getenv("JMS_WEB_DIR"), "index.html"))
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", os.Getenv("JMS_ADDR"))
	if e != nil {
		return e
	}
	defer listener.Close()
	attemptValue := g.Attempt
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-JMS-Activation", attemptValue)
		w.Header().Set("X-JMS-Activation-Phase", "trial")
		switch r.URL.Path {
		case "/api/health":
			_ = json.NewEncoder(w).Encode(map[string]string{"version": version})
		case "/":
			_, _ = w.Write(index)
		default:
			w.WriteHeader(503)
			_, _ = io.WriteString(w, `{"code":"upgrade_activation_pending"}`)
		}
	})}
	defer server.Close()
	record, e := maintenance.PublishActivation(lock, g, listener.Addr().String(), version, "trial")
	if e != nil {
		return e
	}
	defer func() { _ = maintenance.ClearActivation(lock, g) }()
	go func() { _ = server.Serve(listener) }()
	g, e = maintenance.AwaitActivation(context.Background(), lock, g, record)
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(data, "post-active-data"), []byte("preserve post-activation write"), 0600)
}
