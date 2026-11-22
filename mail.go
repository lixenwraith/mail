package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"sync"
	"time"
)

// Sender delivers a message: a Client through a relay, a Dir into files.
type Sender interface {
	Send(ctx context.Context, msg *Message) error
}

// TLSMode says how a Client protects its connection.
type TLSMode int

const (
	// StartTLS upgrades with STARTTLS and fails where the relay offers none.
	StartTLS TLSMode = iota
	// OpportunisticTLS upgrades when the relay offers STARTTLS, and goes on in
	// the clear when it does not: for a relay on a network that is trusted.
	OpportunisticTLS
	// ImplicitTLS speaks TLS from the first byte, as port 465 expects.
	ImplicitTLS
	// NoTLS never upgrades.
	NoTLS
)

func (m TLSMode) String() string {
	switch m {
	case StartTLS:
		return "starttls"
	case OpportunisticTLS:
		return "starttls when offered"
	case ImplicitTLS:
		return "implicit tls"
	case NoTLS:
		return "no tls"
	}
	return "invalid tls mode"
}

// Config describes the relay and how a Client treats it. The zero value of
// every optional field is its default.
type Config struct {
	Host string // the relay's name, which its certificate must carry
	Port int
	// Username and Password, when both are set, authenticate with AUTH
	// PLAIN, which is sent only over TLS or to localhost.
	Username string
	Password string
	// LocalName is the name given in EHLO; "localhost" when empty.
	LocalName string

	TLS TLSMode
	// TLSConfig adjusts the handshake: other roots, another ServerName. It is
	// copied; TLS 1.2 is the floor and ServerName defaults to Host.
	TLSConfig *tls.Config

	Timeout        time.Duration // of one attempt, dial to answer; 30 seconds
	MaxRetries     int           // of a failure that may pass; 3, negative for none
	RetryDelay     time.Duration // before a retry; 5 seconds
	MaxMessageSize int64         // of a rendered message; 25 MiB

	MaxConnections int // open at once; 10
	// ConnMaxIdleTime is how long a connection waits to be used again; one
	// minute, since relays hang up on idle clients. Negative for no reuse.
	ConnMaxIdleTime time.Duration
}

// Client sends messages through one relay. It is safe for concurrent use;
// Close it to drop the connections it keeps.
type Client struct {
	config Config
	tls    *tls.Config
	slots  chan struct{} // one token for each send under way

	mu     sync.Mutex
	idle   []*conn // most recently used last
	closed bool
}

// ErrClosed is returned by Send after Close.
var ErrClosed = errors.New("mail: client closed")

// NewClient validates the configuration and applies its defaults. It connects
// to nothing: the first Send does.
func NewClient(config Config) (*Client, error) {
	invalid := func(text string) (*Client, error) {
		return nil, &Error{Op: "config", Type: ErrorTypeValidation, Err: errors.New(text)}
	}
	switch {
	case config.Host == "":
		return invalid("host required")
	case config.Port < 1 || config.Port > 65535:
		return invalid("port out of range")
	case config.TLS < StartTLS || config.TLS > NoTLS:
		return invalid("unknown TLS mode")
	case (config.Username == "") != (config.Password == ""):
		return invalid("username and password go together")
	}
	if config.LocalName == "" {
		config.LocalName = "localhost"
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = 5 * time.Second
	}
	if config.MaxMessageSize <= 0 {
		config.MaxMessageSize = 25 << 20
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 10
	}
	if config.ConnMaxIdleTime == 0 {
		config.ConnMaxIdleTime = time.Minute
	}
	settings := &tls.Config{}
	if config.TLSConfig != nil {
		settings = config.TLSConfig.Clone()
	}
	if settings.ServerName == "" {
		settings.ServerName = config.Host
	}
	if settings.MinVersion < tls.VersionTLS12 {
		settings.MinVersion = tls.VersionTLS12
	}
	config.TLSConfig = nil
	return &Client{config: config, tls: settings, slots: make(chan struct{}, config.MaxConnections)}, nil
}

// String names the relay and how it is reached, without secrets.
func (c *Client) String() string {
	auth := "no authentication"
	if c.config.Username != "" {
		auth = "as " + c.config.Username
	}
	return fmt.Sprintf("smtp %s (%s, %s)", net.JoinHostPort(c.config.Host, fmt.Sprint(c.config.Port)), c.config.TLS, auth)
}

// Send delivers the message to every recipient through the relay. A failure
// that may pass (the network, a timeout, a 4xx answer) is tried again up to
// MaxRetries times; the message keeps its Message-ID across attempts. The
// error is an *Error. ctx bounds the whole of it.
func (c *Client) Send(ctx context.Context, msg *Message) error {
	r, err := msg.render(c.config.MaxMessageSize)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		err := c.attempt(ctx, r)
		var failure *Error
		if err == nil || attempt >= c.config.MaxRetries || !errors.As(err, &failure) || !failure.Temporary() || ctx.Err() != nil {
			return err
		}
		pause := time.NewTimer(c.config.RetryDelay)
		select {
		case <-pause.C:
		case <-ctx.Done():
			pause.Stop()
			return err
		}
	}
}

// attempt sends the message once, on a kept connection or a new one. Only a
// connection that carried a whole message is kept.
func (c *Client) attempt(ctx context.Context, r *rendered) error {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return failure("wait", ctx.Err())
	}
	link, err := c.connection(ctx)
	if err != nil {
		return err
	}
	// The connection's deadline bounds the attempt; a ctx that ends cuts it
	// short, and leaves a deadline behind that makes the connection useless.
	stop := context.AfterFunc(ctx, func() { link.net.SetDeadline(time.Now()) })
	err = link.deliver(r)
	cut := !stop()
	switch {
	case err != nil && ctx.Err() != nil:
		err = failure("send", ctx.Err())
		fallthrough
	case err != nil, cut:
		link.close()
	default:
		c.keep(link)
	}
	return err
}

// Close drops the kept connections; a Send after it fails with ErrClosed.
func (c *Client) Close() error {
	c.mu.Lock()
	idle := c.idle
	c.idle, c.closed = nil, true
	c.mu.Unlock()
	for _, link := range idle {
		link.quit()
	}
	return nil
}

// ErrorType sorts failures by what a caller can do about them.
type ErrorType int

const (
	ErrorTypeNetwork    ErrorType = iota // the connection failed or broke
	ErrorTypeAuth                        // the relay refused the credentials, or they could not be sent safely
	ErrorTypeValidation                  // the message or the configuration is not acceptable
	ErrorTypeSize                        // the message exceeds MaxMessageSize
	ErrorTypeTimeout                     // an attempt outran its Timeout, or the context ended
	ErrorTypeTLS                         // no TLS where it is required, or the handshake failed
	ErrorTypeRejected                    // the relay refused the sender, a recipient or the message
)

// Error is what Send and NewClient return: the step that failed, the kind of
// failure, and its cause, which for a relay's answer is a *textproto.Error.
type Error struct {
	Op   string
	Type ErrorType
	Err  error
}

func (e *Error) Error() string { return fmt.Sprintf("mail: %s: %v", e.Op, e.Err) }

func (e *Error) Unwrap() error { return e.Err }

// Temporary reports a failure that a later attempt may not meet: the network,
// a timeout, or an answer the relay marked transient (4xx).
func (e *Error) Temporary() bool {
	switch e.Type {
	case ErrorTypeNetwork, ErrorTypeTimeout:
		return true
	case ErrorTypeAuth, ErrorTypeRejected:
		var answer *textproto.Error
		return errors.As(e.Err, &answer) && answer.Code/100 == 4
	}
	return false
}

// failure sorts an error of the step op.
func failure(op string, err error) *Error {
	var timeout net.Error
	var answer *textproto.Error
	kind := ErrorTypeNetwork
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		kind = ErrorTypeTimeout
	case op == "auth":
		kind = ErrorTypeAuth
	case op == "tls":
		kind = ErrorTypeTLS
	case errors.As(err, &answer):
		kind = ErrorTypeRejected
	}
	return &Error{Op: op, Type: kind, Err: err}
}
