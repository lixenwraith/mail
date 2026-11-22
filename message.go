package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	netmail "net/mail"
	"net/textproto"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxLine is the longest line SMTP carries, without its CRLF (RFC 5322 2.1.1).
const maxLine = 998

// Message is one email. From and at least one recipient are required, and
// Text or HTML; with both, a reader's client picks between them.
type Message struct {
	From    string // "Name <address>" or a bare address
	To      []string
	Cc      []string
	Bcc     []string // in the envelope only, never in the headers
	ReplyTo string
	Subject string

	Text string
	HTML string

	// Headers are further fields, such as Auto-Submitted. The fields the
	// package writes itself (From, Date, Content-Type, ...) are refused here.
	Headers     map[string]string
	Attachments []Attachment
}

// Attachment is a file sent with a message, from Content or, when that is
// nil, from Reader, which is read once. ContentType defaults to the type of
// the filename's extension, else application/octet-stream.
type Attachment struct {
	Filename    string
	Content     []byte
	Reader      io.Reader
	ContentType string
}

// rendered is a message ready for the wire.
type rendered struct {
	from string   // envelope sender
	to   []string // envelope recipients, each once
	data []byte
}

// WriteTo writes the message as it would be sent, headers and body with CRLF
// line ends. Each call makes a new Message-ID and Date.
func (m *Message) WriteTo(w io.Writer) (int64, error) {
	r, err := m.render(0)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(r.data)
	return int64(n), err
}

// ownHeaders are the fields render writes; a message may not set them.
var ownHeaders = map[string]bool{
	"From": true, "To": true, "Cc": true, "Bcc": true, "Reply-To": true, "Subject": true, "Date": true,
	"Message-Id": true, "Mime-Version": true, "Content-Type": true, "Content-Transfer-Encoding": true,
}

// render validates the message and builds its bytes; limit, when positive,
// bounds them.
func (m *Message) render(limit int64) (*rendered, error) {
	invalid := func(format string, args ...any) (*rendered, error) {
		return nil, &Error{Op: "message", Type: ErrorTypeValidation, Err: fmt.Errorf(format, args...)}
	}
	from, err := parseAddress(m.From)
	if err != nil {
		return invalid("from: %w", err)
	}
	out := &rendered{from: from.Address}
	var b bytes.Buffer
	writeHeader(&b, "From", from.String())
	seen := make(map[string]bool)
	for _, list := range []struct {
		name      string
		addresses []string
	}{{"To", m.To}, {"Cc", m.Cc}, {"Bcc", m.Bcc}} {
		var shown []string
		for _, text := range list.addresses {
			address, err := parseAddress(text)
			if err != nil {
				return invalid("%s: %w", strings.ToLower(list.name), err)
			}
			shown = append(shown, address.String())
			if !seen[address.Address] {
				seen[address.Address] = true
				out.to = append(out.to, address.Address)
			}
		}
		if len(shown) > 0 && list.name != "Bcc" {
			writeHeader(&b, list.name, strings.Join(shown, ", "))
		}
	}
	if len(out.to) == 0 {
		return invalid("no recipient")
	}
	if m.ReplyTo != "" {
		reply, err := parseAddress(m.ReplyTo)
		if err != nil {
			return invalid("reply-to: %w", err)
		}
		writeHeader(&b, "Reply-To", reply.String())
	}
	if !printable(m.Subject) {
		return invalid("subject holds a control character")
	}
	writeHeader(&b, "Subject", encodeWords(m.Subject))
	writeHeader(&b, "Date", time.Now().Format(time.RFC1123Z))
	var nonce [16]byte
	rand.Read(nonce[:])
	domain := from.Address[strings.LastIndexByte(from.Address, '@')+1:]
	writeHeader(&b, "Message-ID", "<"+hex.EncodeToString(nonce[:])+"@"+domain+">")
	writeHeader(&b, "MIME-Version", "1.0")

	names := make([]string, 0, len(m.Headers))
	for name := range m.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		field := textproto.CanonicalMIMEHeaderKey(name)
		switch {
		case name == "" || strings.Trim(name, headerNameChars) != "":
			return invalid("header name %q", name)
		case ownHeaders[field]:
			return invalid("header %s is written by the package", field)
		case !printable(m.Headers[name]):
			return invalid("header %s holds a control character", field)
		}
		writeHeader(&b, field, encodeWords(m.Headers[name]))
	}

	if m.Text == "" && m.HTML == "" {
		return invalid("no text or html body")
	}
	body, err := m.body(limit)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"Content-Type", "Content-Transfer-Encoding"} {
		if value := body.header.Get(name); value != "" {
			writeHeader(&b, name, value)
		}
	}
	b.WriteString("\r\n")
	b.Write(body.content)
	for _, line := range bytes.Split(b.Bytes(), []byte("\r\n")) {
		if len(line) > maxLine {
			return invalid("a header line longer than %d bytes", maxLine)
		}
	}
	if limit > 0 && int64(b.Len()) > limit {
		return nil, &Error{Op: "message", Type: ErrorTypeSize,
			Err: fmt.Errorf("%d bytes exceed the limit of %d", b.Len(), limit)}
	}
	out.data = b.Bytes()
	return out, nil
}

const headerNameChars = "!\"#$%&'()*+,-./0123456789;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

// parseAddress reads one address. Non-ASCII addresses need SMTPUTF8 and IDNA,
// which the package does not speak; a display name may be any text.
func parseAddress(text string) (*netmail.Address, error) {
	address, err := netmail.ParseAddress(text)
	if err != nil {
		return nil, fmt.Errorf("address %q: %w", text, err)
	}
	for _, c := range []byte(address.Address) {
		if c <= ' ' || c >= 0x7f {
			return nil, fmt.Errorf("address %q is not plain ASCII", text)
		}
	}
	return address, nil
}

// printable refuses what could end a header line or hide in it.
func printable(value string) bool {
	for _, r := range value {
		if r < ' ' && r != '\t' || r == 0x7f {
			return false
		}
	}
	return true
}

// encodeWords writes text for a header: as it is when it is ASCII, else as
// RFC 2047 encoded words. ASCII that holds "=?" is encoded too, or a reader
// would take it for an encoded word and show something else.
func encodeWords(value string) string {
	if encoded := mime.QEncoding.Encode("utf-8", value); encoded != value || !strings.Contains(value, "=?") {
		return encoded
	}
	var words []string
	for len(value) > 0 {
		n := min(len(value), 45)
		words = append(words, "=?utf-8?b?"+base64.StdEncoding.EncodeToString([]byte(value[:n]))+"?=")
		value = value[n:]
	}
	return strings.Join(words, " ")
}

// writeHeader writes a field, folded at spaces to lines of 78 where it can be.
// The standard library folds long encoded words itself; that is undone first,
// or a second fold would leave an empty line, which ends the headers.
func writeHeader(b *bytes.Buffer, name, value string) {
	value = strings.ReplaceAll(value, "\r\n ", " ")
	line := len(name) + 1
	b.WriteString(name)
	b.WriteByte(':')
	for _, word := range strings.Split(value, " ") {
		if line+1+len(word) > 78 && line > len(name)+1 {
			b.WriteString("\r\n")
			line = 0
		}
		b.WriteByte(' ')
		b.WriteString(word)
		line += 1 + len(word)
	}
	b.WriteString("\r\n")
}

// entity is a body or a part of one: its content headers and encoded bytes.
type entity struct {
	header  textproto.MIMEHeader
	content []byte
}

// body builds the message body: the text, the HTML, or both as alternatives,
// and around that the attachments, when there are any.
func (m *Message) body(limit int64) (entity, error) {
	var texts []entity
	if m.Text != "" {
		texts = append(texts, textEntity("text/plain; charset=utf-8", m.Text))
	}
	if m.HTML != "" {
		texts = append(texts, textEntity("text/html; charset=utf-8", m.HTML))
	}
	body := texts[0]
	if len(texts) == 2 {
		body = multipartEntity("multipart/alternative", texts)
	}
	if len(m.Attachments) == 0 {
		return body, nil
	}
	parts := []entity{body}
	budget := limit
	for i, attachment := range m.Attachments {
		part, err := attachmentEntity(attachment, budget)
		if err != nil {
			var size *Error
			if errors.As(err, &size) {
				return entity{}, err
			}
			return entity{}, &Error{Op: "message", Type: ErrorTypeValidation, Err: fmt.Errorf("attachment %d: %w", i+1, err)}
		}
		if limit > 0 {
			budget = max(budget-int64(len(part.content)), 1)
		}
		parts = append(parts, part)
	}
	return multipartEntity("multipart/mixed", parts), nil
}

// textEntity sends text as it is when it is ASCII in lines SMTP carries, and
// quoted-printable otherwise, so no relay needs 8BITMIME. Line ends become CRLF.
func textEntity(contentType, text string) entity {
	text = strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text)
	plain := true
	for _, line := range strings.Split(text, "\n") {
		plain = plain && len(line) <= maxLine
	}
	for i := 0; plain && i < len(text); i++ {
		plain = text[i] < 0x7f && (text[i] >= ' ' || text[i] == '\n' || text[i] == '\t')
	}
	header := textproto.MIMEHeader{"Content-Type": {contentType}}
	var b bytes.Buffer
	if plain {
		header.Set("Content-Transfer-Encoding", "7bit")
		b.WriteString(strings.ReplaceAll(text, "\n", "\r\n"))
	} else {
		header.Set("Content-Transfer-Encoding", "quoted-printable")
		w := quotedprintable.NewWriter(&b)
		io.WriteString(w, text)
		w.Close()
	}
	if !bytes.HasSuffix(b.Bytes(), []byte("\r\n")) {
		b.WriteString("\r\n")
	}
	return entity{header: header, content: b.Bytes()}
}

func multipartEntity(kind string, parts []entity) entity {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for _, part := range parts {
		p, _ := w.CreatePart(part.header) // a bytes.Buffer does not fail
		p.Write(part.content)
	}
	w.Close()
	return entity{
		header:  textproto.MIMEHeader{"Content-Type": {mime.FormatMediaType(kind, map[string]string{"boundary": w.Boundary()})}},
		content: b.Bytes(),
	}
}

// attachmentEntity encodes a file as base64 in lines of 76. limit, when
// positive, bounds what is read of it.
func attachmentEntity(a Attachment, limit int64) (entity, error) {
	if a.Filename == "" || a.Filename != filepath.Base(a.Filename) || !printable(a.Filename) {
		return entity{}, fmt.Errorf("filename %q is not a plain file name", a.Filename)
	}
	content := a.Content
	if content == nil {
		if a.Reader == nil {
			return entity{}, errors.New("no content")
		}
		reader := a.Reader
		if limit > 0 {
			reader = io.LimitReader(reader, limit+1)
		}
		var err error
		if content, err = io.ReadAll(reader); err != nil {
			return entity{}, fmt.Errorf("read %s: %w", a.Filename, err)
		}
	}
	if limit > 0 && int64(len(content)) > limit {
		return entity{}, &Error{Op: "message", Type: ErrorTypeSize,
			Err: fmt.Errorf("attachment %s exceeds the message limit", a.Filename)}
	}
	contentType := a.ContentType
	if contentType == "" {
		contentType = mime.TypeByExtension(filepath.Ext(a.Filename))
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	kind, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return entity{}, fmt.Errorf("content type %q: %w", contentType, err)
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(content)))
	base64.StdEncoding.Encode(encoded, content)
	var b bytes.Buffer
	for len(encoded) > 0 {
		n := min(len(encoded), 76)
		b.Write(encoded[:n])
		b.WriteString("\r\n")
		encoded = encoded[n:]
	}
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename})
	if disposition == "" {
		return entity{}, fmt.Errorf("filename %q cannot be written to a header", a.Filename)
	}
	return entity{
		header: textproto.MIMEHeader{
			"Content-Type":              {mime.FormatMediaType(kind, params)},
			"Content-Transfer-Encoding": {"base64"},
			"Content-Disposition":       {disposition},
		},
		content: b.Bytes(),
	}, nil
}
