// Package ldapserver implements only the LDAP operations needed by isolated
// protocol/browser tests. It is never linked into the application server.
package ldapserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

const BaseDN = "dc=example,dc=test"
const BindDN = "cn=reader," + BaseDN
const BindPassword = "synthetic-directory-reader-password"
const Username = "directory.user"
const Password = "synthetic-directory-user-password"
const UserDN = "uid=directory.user," + BaseDN
const GroupBaseDN = "ou=groups," + BaseDN
const GroupDN = "cn=operators," + GroupBaseDN

type Options struct {
	DirectorySync, MissingPaging, RepeatPaging, TruncatedSearch                                        bool
	StallBinds                                                                                         bool
	Addr                                                                                               string
	StartTLS, RejectStartTLS, Duplicate, MissingIdentity, OutsideBase, Disabled, Referral, BadHostname bool
	SearchName                                                                                         string
}
type Server struct {
	URL, CAPEM  string
	Options     Options
	Binds       atomic.Int32
	Searches    atomic.Int32
	mu          sync.Mutex
	ln          net.Listener
	connections map[net.Conn]bool
	wg          sync.WaitGroup
	tlsConfig   *tls.Config
}

func Start(o Options) (*Server, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic directory QA CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if o.BadHostname {
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.2")}
	}
	cert, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{cert, der}, PrivateKey: key}}}
	addr := o.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, e := net.Listen("tcp", addr)
	if e != nil {
		return nil, e
	}
	scheme := "ldaps://"
	if o.StartTLS {
		scheme = "ldap://"
	}
	s := &Server{URL: scheme + ln.Addr().String(), CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Options: o, ln: ln, connections: map[net.Conn]bool{}, tlsConfig: tc}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			s.mu.Lock()
			s.connections[c] = true
			s.wg.Add(1)
			s.mu.Unlock()
			go func() {
				defer s.wg.Done()
				defer c.Close()
				defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
				s.serve(c)
			}()
		}
	}()
	return s, nil
}
func (s *Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for c := range s.connections {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}
func str(value string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "")
}
func result(id int64, tag ber.Tag, code int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	op.AppendChild(str(""))
	op.AppendChild(str(""))
	p.AppendChild(op)
	return p
}
func write(c net.Conn, p *ber.Packet) bool { _, e := c.Write(p.Bytes()); return e == nil }
func matchFilter(p *ber.Packet, name string) bool {
	switch p.Tag {
	case 0:
		for _, ch := range p.Children {
			if !matchFilter(ch, name) {
				return false
			}
		}
		return true
	case 1:
		for _, ch := range p.Children {
			if matchFilter(ch, name) {
				return true
			}
		}
	case 2:
		return len(p.Children) == 1 && !matchFilter(p.Children[0], name)
	case 3:
		if len(p.Children) != 2 {
			return false
		}
		attr := p.Children[0].Data.String()
		value := p.Children[1].Data.String()
		return (attr == "uid" || attr == "sAMAccountName") && value == name
	case 7:
		return p.Data.String() == "objectClass"
	}
	return false
}
func (s *Server) entry(id int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
	dn := UserDN
	if s.Options.OutsideBase {
		dn = "uid=directory.user,dc=outside,dc=test"
	}
	op.AppendChild(str(dn))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	values := map[string]string{"uid": Username, "sAMAccountName": Username, "userAccountControl": "512", "entryUUID": "synthetic-stable-directory-id", "objectGUID": "\x01\x02synthetic-binary-guid"}
	if s.Options.Disabled {
		values["userAccountControl"] = "514"
	}
	if s.Options.MissingIdentity {
		delete(values, "entryUUID")
		delete(values, "objectGUID")
	}
	for k, v := range values {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		a.AppendChild(str(k))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		set.AppendChild(str(v))
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	op.AppendChild(attrs)
	p.AppendChild(op)
	return p
}
func (s *Server) serve(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	var c net.Conn = raw
	secure := !s.Options.StartTLS
	if secure {
		t := tls.Server(raw, s.tlsConfig)
		if t.Handshake() != nil {
			return
		}
		c = t
	}
	readerBound := false
	for {
		p, e := ber.ReadPacket(c)
		if e != nil || len(p.Children) < 2 {
			return
		}
		id, ok := p.Children[0].Value.(int64)
		if !ok {
			return
		}
		op := p.Children[1]
		switch op.Tag {
		case 23:
			code := int64(0)
			if s.Options.RejectStartTLS {
				code = 52
			}
			if !write(c, result(id, 24, code)) {
				return
			}
			if code != 0 {
				return
			}
			t := tls.Server(raw, s.tlsConfig)
			if t.Handshake() != nil {
				return
			}
			c = t
			secure = true
		case 0:
			if len(op.Children) < 3 {
				return
			}
			dn := op.Children[1].Data.String()
			password := op.Children[2].Data.String()
			s.Binds.Add(1)
			if s.Options.StallBinds {
				continue
			}
			readerBound = secure && dn == BindDN && password == BindPassword
			user := secure && dn == UserDN && password == Password && !s.Options.Disabled
			code := int64(49)
			if readerBound || user {
				code = 0
			}
			if !write(c, result(id, 1, code)) {
				return
			}
		case 3:
			s.Searches.Add(1)
			if !readerBound || len(op.Children) < 8 {
				if !write(c, result(id, 5, 50)) {
					return
				}
				continue
			}
			name := s.Options.SearchName
			if name == "" {
				name = Username
			}
			paging := false
			for _, child := range p.Children[2:] {
				for _, control := range child.Children {
					if len(control.Children) > 0 && control.Children[0].Data.String() == ldap.ControlTypePaging {
						paging = true
					}
				}
			}
			if paging && s.Options.DirectorySync && op.Children[0].Data.String() == GroupBaseDN {
				if !write(c, groupEntry(id)) {
					return
				}
			} else if matchFilter(op.Children[6], name) || paging && s.Options.DirectorySync {
				if !write(c, s.entry(id)) {
					return
				}
				if s.Options.Duplicate && !write(c, s.entry(id)) {
					return
				}
			}
			if s.Options.Referral {
				r := result(id, 5, 10)
				if !write(c, r) {
					return
				}
			} else {
				code := int64(0)
				if s.Options.TruncatedSearch {
					code = 4
				}
				response := result(id, 5, code)
				if paging && s.Options.DirectorySync && !s.Options.MissingPaging {
					controls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
					control := ldap.NewControlPaging(500)
					if s.Options.RepeatPaging {
						control.SetCookie([]byte("repeated-cookie"))
					}
					controls.AppendChild(control.Encode())
					response.AppendChild(controls)
				}
				if !write(c, response) {
					return
				}
			}
		case 2:
			return
		default:
			return
		}
	}
}

func groupEntry(id int64) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
	op.AppendChild(str(GroupDN))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	for key, value := range map[string]string{"cn": "operators", "member": UserDN} {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		a.AppendChild(str(key))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		set.AppendChild(str(value))
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	op.AppendChild(attrs)
	p.AppendChild(op)
	return p
}
