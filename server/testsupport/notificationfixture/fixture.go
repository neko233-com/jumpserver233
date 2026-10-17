// Package notificationfixture captures synthetic messages in memory. It never
// forwards mail, SMS or webhooks to external recipients.
package notificationfixture

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Host                                                    string
	SMTPPort, STARTTLSPort, HTTPSPort                       int
	SMTPCode, HTTPCode                                      int
	DropSMTPReceipt, DropHTTPReceipt, RejectSMS, NoSTARTTLS bool
}
type Record struct {
	Channel       string `json:"channel"`
	ID            string `json:"id"`
	To            string `json:"to"`
	Body          string `json:"body"`
	Signature     string `json:"signature,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"`
	Authenticated bool   `json:"authenticated"`
}
type Fixture struct {
	SMTPAddress, STARTTLSAddress, HTTPSURL, CA string
	options                                    Options
	mu                                         sync.Mutex
	records                                    []Record
	listeners                                  []net.Listener
	conns                                      map[net.Conn]bool
	wg                                         sync.WaitGroup
	server                                     *http.Server
	closed                                     bool
	once                                       sync.Once
}

func Start(o Options) (*Fixture, error) {
	if o.Host == "" {
		o.Host = "127.0.0.1"
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		return nil, e
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Synthetic notification capture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"localhost", "host.docker.internal"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	raw, e := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	keyraw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	pair, e := tls.X509KeyPair(ca, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyraw}))
	if e != nil {
		return nil, e
	}
	f := &Fixture{options: o, CA: string(ca), records: []Record{}, conns: map[net.Conn]bool{}}
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	for _, item := range []struct {
		port   int
		direct bool
	}{{o.SMTPPort, true}, {o.STARTTLSPort, false}} {
		l, e := net.Listen("tcp", fmt.Sprintf("%s:%d", o.Host, item.port))
		if e != nil {
			f.Close()
			return nil, e
		}
		f.listeners = append(f.listeners, l)
		if item.direct {
			f.SMTPAddress = l.Addr().String()
		} else {
			f.STARTTLSAddress = l.Addr().String()
		}
		f.wg.Add(1)
		go f.accept(l, config, item.direct)
	}
	l, e := net.Listen("tcp", fmt.Sprintf("%s:%d", o.Host, o.HTTPSPort))
	if e != nil {
		f.Close()
		return nil, e
	}
	f.listeners = append(f.listeners, l)
	f.HTTPSURL = "https://" + l.Addr().String()
	f.server = &http.Server{Handler: http.HandlerFunc(f.http), ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	f.wg.Add(1)
	go func() { defer f.wg.Done(); _ = f.server.Serve(tls.NewListener(l, config)) }()
	return f, nil
}
func (f *Fixture) capture(r Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.records) < 2000 {
		f.records = append(f.records, r)
	}
}
func (f *Fixture) Records() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record{}, f.records...)
}
func (f *Fixture) accept(l net.Listener, c *tls.Config, direct bool) {
	defer f.wg.Done()
	for {
		conn, e := l.Accept()
		if e != nil {
			return
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			_ = conn.Close()
			return
		}
		f.conns[conn] = true
		f.wg.Add(1)
		f.mu.Unlock()
		go func() {
			defer f.wg.Done()
			defer conn.Close()
			defer func() { f.mu.Lock(); delete(f.conns, conn); f.mu.Unlock() }()
			f.smtp(conn, c, direct)
		}()
	}
}
func (f *Fixture) smtp(raw net.Conn, cfg *tls.Config, direct bool) {
	_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
	conn := raw
	secure := direct
	if direct {
		tlsConn := tls.Server(raw, cfg)
		if tlsConn.Handshake() != nil {
			return
		}
		conn = tlsConn
	}
	reader := bufio.NewReader(conn)
	write := func(v string) bool { _, e := io.WriteString(conn, v+"\r\n"); return e == nil }
	if !write("220 localhost synthetic capture") {
		return
	}
	to := ""
	authenticated := false
	for {
		line, e := reader.ReadString('\n')
		if e != nil {
			return
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "EHLO") || strings.HasPrefix(line, "HELO"):
			extensions := "250-localhost\r\n"
			if !secure && !f.options.NoSTARTTLS {
				extensions += "250-STARTTLS\r\n"
			}
			if secure {
				extensions += "250-AUTH PLAIN\r\n"
			}
			if !write(extensions + "250 OK") {
				return
			}
		case line == "STARTTLS" && !secure && !f.options.NoSTARTTLS:
			if !write("220 Begin TLS") {
				return
			}
			tlsConn := tls.Server(raw, cfg)
			if tlsConn.Handshake() != nil {
				return
			}
			conn = tlsConn
			reader = bufio.NewReader(conn)
			secure = true
		case strings.HasPrefix(line, "AUTH PLAIN") && secure:
			authenticated = true
			if !write("235 Accepted") {
				return
			}
		case strings.HasPrefix(line, "MAIL FROM:") && secure:
			to = ""
			if !write("250 Sender accepted") {
				return
			}
		case strings.HasPrefix(line, "RCPT TO:") && secure:
			to = strings.TrimSuffix(strings.TrimPrefix(line, "RCPT TO:<"), ">")
			if !write("250 Recipient accepted") {
				return
			}
		case line == "DATA" && secure:
			if !write("354 End with dot") {
				return
			}
			body, e := textproto.NewReader(reader).ReadDotBytes()
			if e != nil {
				return
			}
			id := ""
			for _, header := range strings.Split(string(body), "\n") {
				if strings.HasPrefix(header, "Message-ID: <") {
					id = strings.Split(strings.TrimPrefix(header, "Message-ID: <"), "@")[0]
				}
			}
			f.capture(Record{Channel: "email", ID: id, To: to, Body: string(body), Authenticated: authenticated})
			if f.options.DropSMTPReceipt {
				return
			}
			code := f.options.SMTPCode
			if code == 0 {
				code = 250
			}
			if !write(fmt.Sprintf("%d Synthetic response", code)) {
				return
			}
		case line == "QUIT":
			write("221 Bye")
			return
		default:
			if !write("530 TLS required") {
				return
			}
		}
	}
}
func (f *Fixture) http(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != "/webhook" && r.URL.Path != "/sms" {
		http.NotFound(w, r)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 32769))
	if e != nil || len(raw) > 32768 {
		w.WriteHeader(413)
		return
	}
	channel := "webhook"
	if r.URL.Path == "/sms" {
		channel = "sms"
	}
	f.capture(Record{Channel: channel, ID: r.Header.Get("X-JMS-Notification-ID"), Body: string(raw), Signature: r.Header.Get("X-JMS-Signature"), Timestamp: r.Header.Get("X-JMS-Timestamp"), Authenticated: r.Header.Get("Authorization") != ""})
	if f.options.DropHTTPReceipt {
		if h, ok := w.(http.Hijacker); ok {
			c, _, e := h.Hijack()
			if e == nil {
				_ = c.Close()
			}
		}
		return
	}
	code := f.options.HTTPCode
	if code == 0 {
		code = 200
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]bool{"accepted": !f.options.RejectSMS})
}
func (f *Fixture) Close() {
	f.once.Do(func() {
		f.mu.Lock()
		f.closed = true
		for c := range f.conns {
			_ = c.Close()
		}
		f.mu.Unlock()
		if f.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = f.server.Shutdown(ctx)
			cancel()
		}
		for _, l := range f.listeners {
			_ = l.Close()
		}
		f.wg.Wait()
	})
}
