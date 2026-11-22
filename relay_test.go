package mail

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// relay is an SMTP server for the tests. script holds, by command, answers
// to give in place of the usual one, each once and in order; "STALL" as an
// answer leaves the client waiting.
type relay struct {
	host     string
	port     int
	roots    *x509.CertPool
	startTLS *tls.Config

	mu          sync.Mutex
	script      map[string][]string
	connections int
	active      int // sessions open now,
	peak        int // and the most there were at once
	open        []net.Conn
	commands    []string
	messages    []delivery
}

// delivery is a message the relay accepted.
type delivery struct {
	from   string
	to     []string
	data   string
	secure bool
	auth   string // "user password" when the session authenticated
}

// newRelay starts a relay on a loopback port: plain, or offering STARTTLS,
// or with implicit speaking TLS from the first byte.
func newRelay(t *testing.T, offerStartTLS, implicit bool) *relay {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test relay"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(der)
	settings := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if implicit {
		listener = tls.NewListener(listener, settings)
	}
	t.Cleanup(func() { listener.Close() })
	r := &relay{host: "127.0.0.1", port: listener.Addr().(*net.TCPAddr).Port, roots: x509.NewCertPool(), script: map[string][]string{}}
	r.roots.AddCert(certificate)
	if offerStartTLS {
		r.startTLS = settings
	}
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			r.connections++
			r.open = append(r.open, c)
			r.mu.Unlock()
			go r.serve(c, implicit)
		}
	}()
	return r
}

// config is a client configuration for this relay with fast retries.
func (r *relay) config(mode TLSMode) Config {
	return Config{Host: r.host, Port: r.port, TLS: mode, TLSConfig: &tls.Config{RootCAs: r.roots},
		RetryDelay: time.Millisecond, Timeout: 5 * time.Second}
}

// answer is the scripted answer to a command, or usual.
func (r *relay) answer(command, usual string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, command)
	if queue := r.script[command]; len(queue) > 0 {
		r.script[command] = queue[1:]
		return queue[0]
	}
	return usual
}

// hangUp closes every connection, as a relay does to idle clients.
func (r *relay) hangUp() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.open {
		c.Close()
	}
	r.open = nil
}

func (r *relay) count(command string) (n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.commands {
		if c == command {
			n++
		}
	}
	return n
}

func (r *relay) state() (connections int, messages []delivery) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connections, append([]delivery(nil), r.messages...)
}

func (r *relay) serve(c net.Conn, secure bool) {
	defer c.Close()
	r.mu.Lock()
	r.active++
	r.peak = max(r.peak, r.active)
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.active--
		r.mu.Unlock()
	}()
	text := textproto.NewConn(c)
	text.PrintfLine("220 relay ESMTP")
	var current delivery
	auth := ""
	for {
		line, err := text.ReadLine()
		if err != nil {
			return
		}
		command, argument, _ := strings.Cut(line, " ")
		command = strings.ToUpper(command)
		reply := r.answer(command, "250 ok")
		if reply == "STALL" {
			io.Copy(io.Discard, c)
			return
		}
		switch {
		case reply != "250 ok":
			text.PrintfLine("%s", reply)
		case command == "EHLO":
			text.PrintfLine("250-relay")
			if r.startTLS != nil && !secure {
				text.PrintfLine("250-STARTTLS")
			}
			text.PrintfLine("250-AUTH PLAIN")
			text.PrintfLine("250 8BITMIME")
		case command == "STARTTLS":
			text.PrintfLine("220 go ahead")
			upgraded := tls.Server(c, r.startTLS)
			if upgraded.Handshake() != nil {
				return
			}
			c, secure, text = upgraded, true, textproto.NewConn(upgraded)
		case command == "AUTH":
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(argument, "PLAIN "))
			auth = strings.ReplaceAll(strings.TrimPrefix(string(raw), "\x00"), "\x00", " ")
			text.PrintfLine("235 welcome")
		case command == "MAIL":
			current = delivery{from: between(argument), secure: secure, auth: auth}
			text.PrintfLine("250 ok")
		case command == "RCPT":
			current.to = append(current.to, between(argument))
			text.PrintfLine("250 ok")
		case command == "DATA":
			text.PrintfLine("354 send it")
			data, err := io.ReadAll(text.DotReader())
			if err != nil {
				return
			}
			// The dot reader turns CRLF into LF; the tests look at what was sent.
			current.data = strings.ReplaceAll(string(data), "\n", "\r\n")
			switch end := r.answer("END", "250 queued"); end {
			case "250 queued":
			case "STALL":
				io.Copy(io.Discard, c)
				return
			default:
				text.PrintfLine("%s", end)
				continue
			}
			r.mu.Lock()
			r.messages = append(r.messages, current)
			r.mu.Unlock()
			text.PrintfLine("250 queued")
		case command == "QUIT":
			text.PrintfLine("221 bye")
			return
		default: // RSET, NOOP
			text.PrintfLine("250 ok")
		}
	}
}

// between returns what stands in the angle brackets of a MAIL or RCPT argument.
func between(argument string) string {
	open, end := strings.IndexByte(argument, '<'), strings.IndexByte(argument, '>')
	if open < 0 || end < open {
		return argument
	}
	return argument[open+1 : end]
}
