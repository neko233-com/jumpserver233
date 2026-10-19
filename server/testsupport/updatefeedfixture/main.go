// Package main serves a synthetic HTTPS release feed inside owned Docker QA.
// Production URLs remain fixed; only this isolated process trusts the QA CA.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "synthetic release feed unavailable")
		os.Exit(1)
	}
}
func generate(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "jumpserver233 isolated QA root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(3 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caBytes, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"api.github.com", "github.com"}, Subject: pkix.Name{CommonName: "isolated release feed"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(3 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafBytes, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if e != nil {
		return e
	}
	key, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		return e
	}
	for name, block := range map[string]*pem.Block{"ca.pem": {Type: "CERTIFICATE", Bytes: caBytes}, "tls.pem": {Type: "CERTIFICATE", Bytes: leafBytes}, "tls-key.pem": {Type: "PRIVATE KEY", Bytes: key}} {
		if e = os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(block), 0600); e != nil {
			return e
		}
	}
	return nil
}
func run() error {
	dir := flag.String("dir", "", "")
	create := flag.Bool("generate", false, "")
	archive := flag.String("archive", "", "")
	version := flag.String("version", "v0.0.7", "")
	flag.Parse()
	if *dir == "" {
		return fmt.Errorf("missing fixture directory")
	}
	if *create {
		return generate(*dir)
	}
	file, e := os.ReadFile(*archive)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(file)
	sha := hex.EncodeToString(sum[:])
	name := "jumpserver233-" + *version + "-linux-" + runtime.GOARCH + ".tar.gz"
	var requests, downloads, credentials atomic.Int32
	const project = "neko233-com/jumpserver233"
	provider := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			credentials.Add(1)
			http.Error(w, "unexpected credential", 403)
			return
		}
		if r.Host == "api.github.com" && (r.URL.Path == "/repos/"+project+"/releases/latest" || r.URL.Path == "/repos/"+project+"/releases/tags/"+*version) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": *version, "draft": false, "prerelease": false, "published_at": time.Now().Add(-time.Hour).UTC(), "html_url": "https://github.com/" + project + "/releases/tag/" + *version, "assets": []map[string]any{{"name": name, "state": "uploaded", "size": len(file), "digest": "sha256:" + sha, "browser_download_url": "https://github.com/" + project + "/releases/download/" + *version + "/" + name}}})
			return
		}
		if r.Host == "github.com" && r.URL.Path == "/"+project+"/releases/download/"+*version+"/"+name {
			downloads.Add(1)
			http.ServeFile(w, r, *archive)
			return
		}
		http.NotFound(w, r)
	})
	health := &http.Server{Addr: ":9090", ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "requests": requests.Load(), "downloads": downloads.Load(), "credential_requests": credentials.Load()})
	})}
	go func() { _ = health.ListenAndServe() }()
	server := &http.Server{Addr: ":443", Handler: provider, ReadHeaderTimeout: 5 * time.Second}
	return server.ListenAndServeTLS(filepath.Join(*dir, "tls.pem"), filepath.Join(*dir, "tls-key.pem"))
}
