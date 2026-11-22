package mail

import (
	"context"
	"errors"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var _ Sender = (*Client)(nil)

func note(to ...string) *Message {
	return &Message{From: "Sender <sender@example.org>", To: to, Subject: "A note", Text: "Hello.\n"}
}

func send(t *testing.T, c *Client, msg *Message) error {
	t.Helper()
	t.Cleanup(func() { c.Close() })
	return c.Send(t.Context(), msg)
}

func client(t *testing.T, config Config) *Client {
	t.Helper()
	c, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The envelope carries every recipient once and the bare sender address; the
// headers never name a Bcc recipient.
func TestSendHandsTheRelayTheEnvelopeAndTheMessage(t *testing.T) {
	r := newRelay(t, false, false)
	msg := note("First <one@example.org>", "two@example.org")
	msg.Cc, msg.Bcc = []string{"one@example.org", "three@example.org"}, []string{"hidden@example.org"}
	if err := send(t, client(t, r.config(NoTLS)), msg); err != nil {
		t.Fatal(err)
	}
	_, messages := r.state()
	if len(messages) != 1 {
		t.Fatalf("%d messages", len(messages))
	}
	got := messages[0]
	if got.from != "sender@example.org" ||
		strings.Join(got.to, " ") != "one@example.org two@example.org three@example.org hidden@example.org" {
		t.Errorf("envelope from %q to %q", got.from, got.to)
	}
	for _, want := range []string{"From: \"Sender\" <sender@example.org>\r\n", "To: \"First\" <one@example.org>, two@example.org\r\n", "Cc: one@example.org, three@example.org\r\n", "\r\n\r\nHello.\r\n"} {
		if !strings.Contains(got.data, want) {
			t.Errorf("message lacks %q:\n%s", want, got.data)
		}
	}
	if strings.Contains(got.data, "hidden") {
		t.Errorf("the headers name the Bcc recipient:\n%s", got.data)
	}
}

// STARTTLS is the default and its absence a failure; a certificate that does
// not verify is one too, and no later attempt would mend either.
func TestTLSIsRequiredUnlessTheConfigurationSaysOtherwise(t *testing.T) {
	plain, offering, implicit := newRelay(t, false, false), newRelay(t, true, false), newRelay(t, false, true)

	err := send(t, client(t, plain.config(StartTLS)), note("a@example.org"))
	var refused *Error
	if !errors.As(err, &refused) || refused.Type != ErrorTypeTLS || refused.Temporary() || plain.count("MAIL") != 0 {
		t.Errorf("no STARTTLS offered: %v, %d MAIL commands", err, plain.count("MAIL"))
	}
	if connections, _ := plain.state(); connections != 1 {
		t.Errorf("a missing STARTTLS was tried %d times", connections)
	}
	if err := send(t, client(t, plain.config(OpportunisticTLS)), note("a@example.org")); err != nil {
		t.Errorf("opportunistic, none offered: %v", err)
	}

	withLogin := offering.config(StartTLS)
	withLogin.Username, withLogin.Password = "user", "secret"
	if err := send(t, client(t, withLogin), note("a@example.org")); err != nil {
		t.Fatalf("STARTTLS: %v", err)
	}
	if _, messages := offering.state(); len(messages) != 1 || !messages[0].secure || messages[0].auth != "user secret" {
		t.Errorf("STARTTLS delivery = %+v", messages)
	}
	untrusting := offering.config(OpportunisticTLS)
	untrusting.TLSConfig = nil
	if err := send(t, client(t, untrusting), note("a@example.org")); !errors.As(err, &refused) || refused.Type != ErrorTypeTLS {
		t.Errorf("unknown certificate: %v", err)
	}

	if err := send(t, client(t, implicit.config(ImplicitTLS)), note("a@example.org")); err != nil {
		t.Fatalf("implicit TLS: %v", err)
	}
	if _, messages := implicit.state(); len(messages) != 1 || !messages[0].secure {
		t.Errorf("implicit TLS delivery = %+v", messages)
	}
}

func TestATransientAnswerIsRetriedAndAPermanentOneIsNot(t *testing.T) {
	r := newRelay(t, false, false)
	r.script["RCPT"] = []string{"451 4.3.0 try again later"}
	r.script["END"] = []string{"452 4.3.1 out of space"}
	if err := send(t, client(t, r.config(NoTLS)), note("a@example.org")); err != nil {
		t.Fatalf("after two transient answers: %v", err)
	}
	if connections, messages := r.state(); connections != 3 || len(messages) != 1 {
		t.Errorf("%d connections, %d messages; want 3 and 1", connections, len(messages))
	}

	r.script["RCPT"] = []string{"550 5.1.1 no such user"}
	err := send(t, client(t, r.config(NoTLS)), note("a@example.org"))
	var refused *Error
	var answer *textproto.Error
	if !errors.As(err, &refused) || refused.Type != ErrorTypeRejected || refused.Temporary() ||
		!errors.As(err, &answer) || answer.Code != 550 {
		t.Errorf("permanent answer: %v", err)
	}
	if connections, messages := r.state(); connections != 4 || len(messages) != 1 {
		t.Errorf("%d connections, %d messages after a permanent answer; want 4 and 1", connections, len(messages))
	}
}

// A connection carries message after message; one the relay has hung up on
// is replaced without costing an attempt.
func TestAConnectionIsUsedAgainUntilTheRelayHangsUp(t *testing.T) {
	r := newRelay(t, false, false)
	config := r.config(NoTLS)
	config.MaxRetries = -1
	c := client(t, config)
	for range 2 {
		if err := send(t, c, note("a@example.org")); err != nil {
			t.Fatal(err)
		}
	}
	if connections, _ := r.state(); connections != 1 {
		t.Errorf("%d connections for two messages", connections)
	}
	r.hangUp()
	if err := send(t, c, note("a@example.org")); err != nil {
		t.Fatalf("after the relay hung up: %v", err)
	}
	if connections, messages := r.state(); connections != 2 || len(messages) != 3 {
		t.Errorf("%d connections, %d messages; want 2 and 3", connections, len(messages))
	}

	config.ConnMaxIdleTime = -1
	single := client(t, config)
	for range 2 {
		if err := send(t, single, note("a@example.org")); err != nil {
			t.Fatal(err)
		}
	}
	if connections, _ := r.state(); connections != 4 {
		t.Errorf("%d connections; without reuse two messages take two more", connections)
	}
	c.Close()
	if err := c.Send(t.Context(), note("a@example.org")); !errors.Is(err, ErrClosed) {
		t.Errorf("send after Close: %v", err)
	}
}

func TestConcurrentSendsShareAtMostMaxConnections(t *testing.T) {
	r := newRelay(t, false, false)
	config := r.config(NoTLS)
	config.MaxConnections = 3
	c := client(t, config)
	defer c.Close()
	var group sync.WaitGroup
	errs := make(chan error, 20)
	for range cap(errs) {
		group.Go(func() { errs <- c.Send(t.Context(), note("a@example.org")) })
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.messages) != 20 || r.peak > 3 || r.connections > 3 {
		t.Errorf("%d messages over %d connections, %d at once; want 20 over at most 3", len(r.messages), r.connections, r.peak)
	}
}

func TestAContextThatEndsCutsTheAttemptShort(t *testing.T) {
	r := newRelay(t, false, false)
	r.script["END"] = []string{"STALL"}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	c := client(t, r.config(NoTLS))
	defer c.Close()
	err := c.Send(ctx, note("a@example.org"))
	var cut *Error
	if !errors.As(err, &cut) || cut.Type != ErrorTypeTimeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v", err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Errorf("waited %v on a relay that never answers", waited)
	}
}

func TestDirWritesWhatARelayWouldBeGiven(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "outbox")
	var sender Sender = Dir{Path: dir}
	if err := sender.Send(t.Context(), note("a@example.org")); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.eml"))
	if err != nil || len(files) != 1 {
		t.Fatalf("files = %v, %v", files, err)
	}
	data, _ := os.ReadFile(files[0])
	info, _ := os.Stat(files[0])
	if !strings.HasPrefix(string(data), "From: \"Sender\" <sender@example.org>\r\n") ||
		!strings.HasSuffix(string(data), "\r\n\r\nHello.\r\n") || info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, content:\n%s", info.Mode(), data)
	}
}
