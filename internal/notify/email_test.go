package notify

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"mime/quotedprintable"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/milliebillie/patchtacio/internal/advice"
	"github.com/milliebillie/patchtacio/internal/config"
)

// testCert makes a self-signed certificate for 127.0.0.1 and a client
// config that trusts it.
func testCert(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// smtpServer is a minimal SMTP server for one session at a time.
type smtpServer struct {
	cert      tls.Certificate
	implicit  bool // TLS from the first byte ("tls")
	starttls  bool // offer STARTTLS
	mu        sync.Mutex
	authPlain string // decoded AUTH PLAIN payload
	from      string
	rcpts     []string
	data      string
	commands  []string
}

func (s *smtpServer) start(t *testing.T) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if s.implicit {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.session(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func (s *smtpServer) session(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r, w := bufio.NewReader(conn), conn
	say := func(line string) { _, _ = io.WriteString(w, line+"\r\n") }
	secure := s.implicit
	say("220 test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		s.mu.Lock()
		s.commands = append(s.commands, line)
		s.mu.Unlock()
		verb := strings.ToUpper(strings.Fields(line + " x")[0])
		switch verb {
		case "EHLO", "HELO":
			if s.starttls && !secure {
				say("250-test")
				say("250-STARTTLS")
				say("250 AUTH PLAIN")
			} else {
				say("250-test")
				say("250 AUTH PLAIN")
			}
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{s.cert}, MinVersion: tls.VersionTLS12})
			if err := tc.HandshakeContext(context.Background()); err != nil {
				return
			}
			conn, r, w, secure = tc, bufio.NewReader(tc), tc, true
		case "AUTH":
			f := strings.Fields(line)
			if len(f) == 3 {
				dec, _ := base64.StdEncoding.DecodeString(f[2])
				s.mu.Lock()
				s.authPlain = string(dec)
				s.mu.Unlock()
			}
			say("235 ok")
		case "MAIL":
			s.mu.Lock()
			s.from = line
			s.mu.Unlock()
			say("250 ok")
		case "RCPT":
			s.mu.Lock()
			s.rcpts = append(s.rcpts, line)
			s.mu.Unlock()
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func newTestEmail(t *testing.T, s *smtpServer, security, username string, vars map[string]string) *Email {
	t.Helper()
	cert, clientTLS := testCert(t)
	s.cert = cert
	port := s.start(t)
	cfg := config.Email{Host: "127.0.0.1", Port: port, Security: security, Username: username,
		From: "Patchtacio <alerts@school.example>", To: []string{"it@school.example", "head@school.example"}}
	e := NewEmail(cfg, env(vars))
	e.tlsConfig = clientTLS
	e.timeout = 10 * time.Second
	e.Now = func() time.Time { return time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC) }
	return e
}

func TestEmailImplicitTLSWithLogin(t *testing.T) {
	s := &smtpServer{implicit: true}
	e := newTestEmail(t, s, "tls", "alerts@school.example", map[string]string{config.EnvSMTPPassword: "hunter2"})
	m := sample()
	m.Items[0].Products[0].Display = "Ünïcode Widget"
	if err := e.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authPlain != "\x00alerts@school.example\x00hunter2" {
		t.Errorf("AUTH PLAIN = %q", s.authPlain)
	}
	if !strings.Contains(s.from, "<alerts@school.example>") || len(s.rcpts) != 2 {
		t.Errorf("envelope: from %q to %v", s.from, s.rcpts)
	}
	head, body, _ := strings.Cut(s.data, "\r\n\r\n")
	for _, want := range []string{
		"Subject: =?utf-8?q?",
		"To: <it@school.example>, <head@school.example>",
		"Content-Transfer-Encoding: quoted-printable",
		"Auto-Submitted: auto-generated",
		"Date: Sat, 03 Oct 2026 09:00:00 +0000",
	} {
		if !strings.Contains(head, want) {
			t.Errorf("headers lack %q:\n%s", want, head)
		}
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(decoded), "Ünïcode Widget") || !strings.Contains(string(decoded), "patchtacio ack CVE-2026-1") {
		t.Errorf("body:\n%s", decoded)
	}
}

func TestEmailStartTLS(t *testing.T) {
	s := &smtpServer{starttls: true}
	e := newTestEmail(t, s, "starttls", "", nil)
	if err := e.SendNotice(context.Background(), advice.TestNotice()); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.Contains(s.data, "Patchtacio alerts work") {
		t.Errorf("test message not received: %q", s.data)
	}
}

// A server that does not offer STARTTLS gets nothing: no login, no message.
func TestEmailRefusesWithoutStartTLS(t *testing.T) {
	s := &smtpServer{starttls: false}
	e := newTestEmail(t, s, "starttls", "alerts@school.example", map[string]string{config.EnvSMTPPassword: "hunter2"})
	err := e.SendNotice(context.Background(), advice.TestNotice())
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Fatalf("want a STARTTLS refusal, got %v", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Error("error contains the password")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.commands {
		if v := strings.ToUpper(strings.Fields(c + " x")[0]); v == "AUTH" || v == "MAIL" || v == "DATA" {
			t.Errorf("sent %q over an unencrypted connection", c)
		}
	}
}

func TestEmailPlainToLocalhost(t *testing.T) {
	s := &smtpServer{}
	e := newTestEmail(t, s, "none", "", nil)
	if err := e.SendNotice(context.Background(), advice.TestNotice()); err != nil {
		t.Fatal(err)
	}
	e.Config.Host = "mail.example.org"
	if err := e.SendNotice(context.Background(), advice.TestNotice()); err == nil {
		t.Error("plaintext to another computer must be refused")
	}
}

func TestEmailMissingPassword(t *testing.T) {
	s := &smtpServer{implicit: true}
	e := newTestEmail(t, s, "tls", "alerts@school.example", nil)
	err := e.SendNotice(context.Background(), advice.TestNotice())
	if err == nil || !strings.Contains(err.Error(), config.EnvSMTPPassword) {
		t.Errorf("want an error naming %s, got %v", config.EnvSMTPPassword, err)
	}
}
