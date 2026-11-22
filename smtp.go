package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"strconv"
	"time"
)

// A kept connection is asked whether it still listens before it is used; a
// relay that does not answer within this is taken to have hung up.
const probeTimeout = 5 * time.Second

// conn is one SMTP session with the relay. net is the socket under it, for
// deadlines: after STARTTLS the session reads through a TLS layer of its own.
type conn struct {
	net  net.Conn
	smtp *smtp.Client
	used time.Time
}

// close ends the session without a word, as after a failure.
func (link *conn) close() { link.net.Close() }

// quit ends an idle session politely.
func (link *conn) quit() {
	link.net.SetDeadline(time.Now().Add(probeTimeout))
	if link.smtp.Quit() != nil {
		link.net.Close()
	}
}

// connection returns a session ready for a message, its deadline one Timeout
// away: the most recently kept one that still answers, else a new one.
func (c *Client) connection(ctx context.Context) (*conn, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, &Error{Op: "send", Type: ErrorTypeValidation, Err: ErrClosed}
		}
		var link *conn
		if n := len(c.idle); n > 0 {
			link, c.idle = c.idle[n-1], c.idle[:n-1]
		}
		c.mu.Unlock()
		if link == nil {
			return c.dial(ctx)
		}
		link.net.SetDeadline(time.Now().Add(probeTimeout))
		if time.Since(link.used) < c.config.ConnMaxIdleTime && link.smtp.Reset() == nil {
			link.net.SetDeadline(time.Now().Add(c.config.Timeout))
			return link, nil
		}
		link.close()
	}
}

// keep puts a session that carried a whole message aside for the next one.
func (c *Client) keep(link *conn) {
	link.used = time.Now()
	c.mu.Lock()
	reuse := !c.closed && c.config.ConnMaxIdleTime > 0
	if reuse {
		c.idle = append(c.idle, link)
	}
	c.mu.Unlock()
	if !reuse {
		link.quit()
		return
	}
	time.AfterFunc(c.config.ConnMaxIdleTime, c.reap)
}

// reap ends the sessions that waited their idle time out.
func (c *Client) reap() {
	c.mu.Lock()
	var expired []*conn
	kept := c.idle[:0]
	for _, link := range c.idle {
		if time.Since(link.used) >= c.config.ConnMaxIdleTime {
			expired = append(expired, link)
		} else {
			kept = append(kept, link)
		}
	}
	c.idle = kept
	c.mu.Unlock()
	for _, link := range expired {
		link.quit()
	}
}

// dial opens a session: connect, greet, secure, authenticate.
func (c *Client) dial(ctx context.Context) (*conn, error) {
	deadline := time.Now().Add(c.config.Timeout)
	dialer := net.Dialer{Deadline: deadline}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(c.config.Host, strconv.Itoa(c.config.Port)))
	if err != nil {
		return nil, failure("dial", err)
	}
	raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { raw.SetDeadline(time.Now()) })
	defer stop()
	link, err := c.open(raw)
	if err != nil {
		raw.Close()
		if ctx.Err() != nil {
			return nil, failure("dial", ctx.Err())
		}
		return nil, err
	}
	return link, nil
}

func (c *Client) open(raw net.Conn) (*conn, error) {
	stream := raw
	if c.config.TLS == ImplicitTLS {
		secure := tls.Client(raw, c.tls)
		if err := secure.Handshake(); err != nil {
			return nil, failure("tls", err)
		}
		stream = secure
	}
	session, err := smtp.NewClient(stream, c.config.Host)
	if err != nil {
		return nil, failure("greeting", err)
	}
	if err := session.Hello(c.config.LocalName); err != nil {
		return nil, failure("hello", err)
	}
	if c.config.TLS == StartTLS || c.config.TLS == OpportunisticTLS {
		offered, _ := session.Extension("STARTTLS")
		switch {
		case offered:
			if err := session.StartTLS(c.tls); err != nil {
				return nil, failure("tls", err)
			}
		case c.config.TLS == StartTLS:
			return nil, failure("tls", errors.New("the relay offers no STARTTLS"))
		}
	}
	if c.config.Username != "" {
		// PlainAuth itself refuses a connection that is neither TLS nor local.
		auth := smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)
		if err := session.Auth(auth); err != nil {
			return nil, failure("auth", err)
		}
	}
	return &conn{net: raw, smtp: session}, nil
}

// deliver hands the relay one message for all its recipients; a recipient
// the relay refuses fails the whole message.
func (link *conn) deliver(r *rendered) error {
	if err := link.smtp.Mail(r.from); err != nil {
		return failure("mail", err)
	}
	for _, to := range r.to {
		if err := link.smtp.Rcpt(to); err != nil {
			return failure("rcpt", err)
		}
	}
	w, err := link.smtp.Data()
	if err != nil {
		return failure("data", err)
	}
	if _, err := w.Write(r.data); err != nil {
		return failure("data", err)
	}
	if err := w.Close(); err != nil {
		return failure("data", err)
	}
	return nil
}
