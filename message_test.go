package mail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	netmail "net/mail"
	"strings"
	"testing"
)

// part is a leaf of a parsed message: its media type, its file name when it
// is an attachment, and its content, decoded.
type part struct {
	kind, filename, content string
}

// parse reads a rendered message back the way a mail client would.
func parse(t testing.TB, data []byte) (netmail.Header, string, []part) {
	t.Helper()
	msg, err := netmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("rendered message does not parse: %v\n%q", err, data)
	}
	kind, parts := leaves(t, msg.Header.Get("Content-Type"), msg.Header.Get("Content-Transfer-Encoding"), "", msg.Body)
	return msg.Header, kind, parts
}

func leaves(t testing.TB, contentType, encoding, disposition string, body io.Reader) (string, []part) {
	t.Helper()
	kind, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		t.Fatalf("content type %q: %v", contentType, err)
	}
	if strings.HasPrefix(kind, "multipart/") {
		var all []part
		reader := multipart.NewReader(body, params["boundary"])
		for {
			// The raw part keeps its transfer encoding for this function to undo.
			p, err := reader.NextRawPart()
			if err == io.EOF {
				return kind, all
			}
			if err != nil {
				t.Fatalf("%s: %v", kind, err)
			}
			inner, found := leaves(t, p.Header.Get("Content-Type"), p.Header.Get("Content-Transfer-Encoding"),
				p.Header.Get("Content-Disposition"), p)
			if strings.HasPrefix(inner, "multipart/") {
				all = append(all, part{kind: inner})
			}
			all = append(all, found...)
		}
	}
	switch encoding {
	case "quoted-printable":
		body = quotedprintable.NewReader(body)
	case "base64":
		body = base64.NewDecoder(base64.StdEncoding, body)
	case "7bit":
	default:
		t.Fatalf("transfer encoding %q", encoding)
	}
	content, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("%s body: %v", kind, err)
	}
	leaf := part{kind: kind, content: string(content)}
	if disposition != "" {
		_, params, err := mime.ParseMediaType(disposition)
		if err != nil {
			t.Fatalf("disposition %q: %v", disposition, err)
		}
		leaf.filename = params["filename"]
	}
	return kind, []part{leaf}
}

func TestAMessageCannotBreakOutOfItsHeaders(t *testing.T) {
	for name, change := range map[string]func(*Message){
		"line break in the sender":    func(m *Message) { m.From = "a@example.org\r\nBcc: x@example.org" },
		"line break in a recipient":   func(m *Message) { m.To = []string{"a@example.org\nBcc: x@example.org"} },
		"line break in the subject":   func(m *Message) { m.Subject = "Hello\r\nBcc: x@example.org" },
		"line break in a header":      func(m *Message) { m.Headers = map[string]string{"X-Note": "a\r\nBcc: x@example.org"} },
		"line break in a header name": func(m *Message) { m.Headers = map[string]string{"X-Note\r\nBcc": "x@example.org"} },
		"colon in a header name":      func(m *Message) { m.Headers = map[string]string{"Bcc: x@example.org\r\nX": "y"} },
		"a header of the package":     func(m *Message) { m.Headers = map[string]string{"content-type": "text/html"} },
		"a non-ASCII address":         func(m *Message) { m.To = []string{"jürgen@example.org"} },
		"no recipient":                func(m *Message) { m.To = nil },
		"no body":                     func(m *Message) { m.Text = "" },
		"a path as a file name":       func(m *Message) { m.Attachments = []Attachment{{Filename: "../x", Content: []byte("x")}} },
		"an attachment of nothing":    func(m *Message) { m.Attachments = []Attachment{{Filename: "x.txt"}} },
	} {
		msg := note("a@example.org")
		change(msg)
		_, err := msg.WriteTo(io.Discard)
		var refused *Error
		if !errors.As(err, &refused) || refused.Type != ErrorTypeValidation {
			t.Errorf("%s: error = %v, want a validation error", name, err)
		}
	}
}

// ASCII text in lines SMTP carries goes out untouched, so a link in it stays
// whole; anything else is quoted-printable. Headers decode to what was set.
func TestTextTravelsAsItIsUnlessItNeedsEncoding(t *testing.T) {
	link := "https://example.org/reset?token=" + strings.Repeat("x", 120)
	msg := note("a@example.org")
	msg.Text = "Open this link:\n\n  " + link + "\n"
	var plain bytes.Buffer
	if _, err := msg.WriteTo(&plain); err != nil {
		t.Fatal(err)
	}
	header, kind, parts := parse(t, plain.Bytes())
	if header.Get("Content-Transfer-Encoding") != "7bit" || kind != "text/plain" ||
		!strings.Contains(plain.String(), "\r\n  "+link+"\r\n") {
		t.Errorf("plain text was changed:\n%s", plain.String())
	}
	if parts[0].content != "Open this link:\r\n\r\n  "+link+"\r\n" {
		t.Errorf("content = %q", parts[0].content)
	}

	subject := "Grüße aus Zürich: " + strings.Repeat("ein sehr langer Betreff ", 8)
	msg = &Message{
		From: `"Jürgen Müller" <sender@example.org>`, To: []string{"a@example.org"}, Subject: subject,
		Text:    "Zeile mit ä\r\n" + strings.Repeat("long ", 300) + "\n",
		Headers: map[string]string{"x-note": "naïve", "Auto-Submitted": "auto-generated"},
	}
	var encoded bytes.Buffer
	if _, err := msg.WriteTo(&encoded); err != nil {
		t.Fatal(err)
	}
	header, _, parts = parse(t, encoded.Bytes())
	decoder := new(mime.WordDecoder)
	gotSubject, _ := decoder.DecodeHeader(header.Get("Subject"))
	gotNote, _ := decoder.DecodeHeader(header.Get("X-Note"))
	from, err := header.AddressList("From")
	if strings.Join(strings.Fields(gotSubject), " ") != strings.Join(strings.Fields(subject), " ") || gotNote != "naïve" ||
		err != nil || from[0].Name != "Jürgen Müller" || header.Get("Auto-Submitted") != "auto-generated" {
		t.Errorf("subject %q, note %q, from %v (%v)", gotSubject, gotNote, from, err)
	}
	if header.Get("Content-Transfer-Encoding") != "quoted-printable" ||
		parts[0].content != "Zeile mit ä\r\n"+strings.Repeat("long ", 300)+"\r\n" {
		t.Errorf("encoded text reads back as %q", parts[0].content)
	}
	// A field's name and one encoded word, which cannot be broken, share a line.
	for _, line := range strings.Split(encoded.String(), "\r\n") {
		if len(line) > len("Subject: ")+75 {
			t.Errorf("a line of %d bytes: %q", len(line), line)
		}
	}
}

func TestBodiesAndAttachmentsNestAsMailClientsExpect(t *testing.T) {
	binary := bytes.Repeat([]byte{0, 1, 2, 250, 251, '\r', '\n'}, 100)
	msg := note("a@example.org")
	msg.HTML = "<p>Hello.</p>"
	msg.Attachments = []Attachment{
		{Filename: "notes.txt", Content: []byte("plain notes\n")},
		{Filename: "Übersicht.bin", Reader: bytes.NewReader(binary)},
	}
	var b bytes.Buffer
	if _, err := msg.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	_, kind, parts := parse(t, b.Bytes())
	want := []part{
		{kind: "multipart/alternative"},
		{kind: "text/plain", content: "Hello.\r\n"},
		{kind: "text/html", content: "<p>Hello.</p>\r\n"},
		{kind: "text/plain", filename: "notes.txt", content: "plain notes\n"},
		{kind: "application/octet-stream", filename: "Übersicht.bin", content: string(binary)},
	}
	if kind != "multipart/mixed" || len(parts) != len(want) {
		t.Fatalf("%s with %d parts: %+v", kind, len(parts), parts)
	}
	for i := range want {
		if parts[i] != want[i] {
			t.Errorf("part %d = {%s %q %d bytes}, want {%s %q %d bytes}", i, parts[i].kind, parts[i].filename,
				len(parts[i].content), want[i].kind, want[i].filename, len(want[i].content))
		}
	}
}

func TestAMessageOverTheLimitIsRefusedBeforeAnyConnection(t *testing.T) {
	r := newRelay(t, false, false)
	config := r.config(NoTLS)
	config.MaxMessageSize = 2000
	for name, attachment := range map[string]Attachment{
		"bytes":  {Filename: "big.bin", Content: make([]byte, 3000)},
		"stream": {Filename: "big.bin", Reader: bytes.NewReader(make([]byte, 3000))},
	} {
		msg := note("a@example.org")
		msg.Attachments = []Attachment{attachment}
		err := send(t, client(t, config), msg)
		var refused *Error
		if !errors.As(err, &refused) || refused.Type != ErrorTypeSize {
			t.Errorf("%s: error = %v, want a size error", name, err)
		}
	}
	if connections, _ := r.state(); connections != 0 {
		t.Errorf("%d connections for messages that were never sent", connections)
	}
}

// FuzzMessage holds the renderer to a mail parser: whatever the subject, the
// sender's name and the text, a message that renders reads back as written,
// in CRLF lines that SMTP carries.
func FuzzMessage(f *testing.F) {
	f.Add("A note", "Sender", "Hello.\n")
	f.Add("Grüße "+strings.Repeat("ä", 90), "J. \"Q\" Müller", "a\r\nb\rc\n.\n..\n"+strings.Repeat("x", 1200))
	f.Add("=?utf-8?q?x?=  two  spaces", "", "\x00\x7f =\t\n")
	f.Fuzz(func(t *testing.T, subject, name, text string) {
		msg := &Message{
			From: (&netmail.Address{Name: name, Address: "sender@example.org"}).String(),
			To:   []string{"a@example.org"}, Subject: subject, Text: text,
		}
		var b bytes.Buffer
		if _, err := msg.WriteTo(&b); err != nil {
			var refused *Error
			if !errors.As(err, &refused) || refused.Type != ErrorTypeValidation {
				t.Fatalf("error %v is not a validation error", err)
			}
			return
		}
		data := b.String()
		if strings.Contains(strings.ReplaceAll(data, "\r\n", ""), "\r") || strings.Contains(strings.ReplaceAll(data, "\r\n", ""), "\n") {
			t.Fatalf("a bare CR or LF in %q", data)
		}
		for _, line := range strings.Split(data, "\r\n") {
			if len(line) > maxLine {
				t.Fatalf("a line of %d bytes", len(line))
			}
		}
		header, _, parts := parse(t, b.Bytes())
		got, err := new(mime.WordDecoder).DecodeHeader(header.Get("Subject"))
		if err != nil || strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(subject), " ") {
			t.Fatalf("subject %q reads back as %q (%v)", subject, got, err)
		}
		if from, err := header.AddressList("From"); err != nil || len(from) != 1 || from[0].Address != "sender@example.org" {
			t.Fatalf("from reads back as %v (%v)", from, err)
		}
		want := strings.ReplaceAll(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text), "\n", "\r\n")
		if !strings.HasSuffix(want, "\r\n") {
			want += "\r\n"
		}
		if len(parts) != 1 || parts[0].content != want {
			t.Fatalf("text %q reads back as %q", text, parts[0].content)
		}
	})
}
