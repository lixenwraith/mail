# mail

A small SMTP client for Go 1.27+, built on the standard library alone: send
plain or HTML email with attachments through a relay, with TLS on by default,
retries of what can pass, and connections kept for reuse.

```go
client, err := mail.NewClient(mail.Config{
    Host: "smtp.example.org", Port: 587, Username: "app", Password: "secret",
})
if err != nil {
    return err
}
defer client.Close()

err = client.Send(ctx, &mail.Message{
    From:    "App <app@example.org>",
    To:      []string{"someone@example.net"},
    Subject: "Your report",
    Text:    "The report is attached.\n",
    Attachments: []mail.Attachment{{Filename: "report.csv", Content: csv}},
})
```

A `Client` is safe for concurrent use. `mail.Sender` is the interface it
shares with `mail.Dir`, so code that sends takes either.

## Configuration

Every optional field's zero value is its default.

- `Host`, `Port`: the relay. `Host` is also the name its certificate must
  carry.
- `Username`, `Password`: AUTH PLAIN when both are set. The credentials are
  sent only over TLS, or to localhost.
- `LocalName`: the name given in EHLO; `localhost` when empty.
- `TLS`:
  - `mail.StartTLS` (default): upgrade with STARTTLS, fail where the relay
    offers none
  - `mail.OpportunisticTLS`: upgrade when offered, else go on in the clear;
    for a relay on a trusted network
  - `mail.ImplicitTLS`: TLS from the first byte, as on port 465
  - `mail.NoTLS`: never
- `TLSConfig`: other roots or another `ServerName`, for a relay with a private
  CA or one reached by address. TLS 1.2 is the floor.
- `Timeout`: one attempt, from the dial to the relay's answer; 30 seconds.
- `MaxRetries`, `RetryDelay`: 3 retries, 5 seconds apart; a negative
  `MaxRetries` for none.
- `MaxMessageSize`: of the rendered message; 25 MiB.
- `MaxConnections`: sends under way at once; 10. Further sends wait.
- `ConnMaxIdleTime`: how long a connection waits for the next message; one
  minute. Negative for a connection per message.

## Sending

- A message goes to all its recipients or to none: a recipient the relay
  refuses fails the send.
- Retried: a failed or broken connection, a timeout, and an answer the relay
  marks transient (4xx). Not retried: a permanent answer (5xx), a failed TLS
  handshake or a missing STARTTLS, refused credentials, an invalid message.
- A retry sends the same bytes, Message-ID included. A connection that breaks
  after the message was handed over can still deliver it twice; the
  Message-ID lets the receiving side tell.
- The context bounds the whole send, retries and waiting included; when it
  ends, the attempt under way is cut short.
- A kept connection is asked whether it still listens before it is used, and
  replaced when it does not; that costs no attempt.

## Messages

- `From` and at least one of `To`, `Cc`, `Bcc`; `Text`, `HTML`, or both, which
  are sent as alternatives. `Bcc` recipients are in the envelope only.
- Addresses are parsed and must be ASCII; display names, the subject and
  header values may be any text and are encoded as RFC 2047 words.
- A line break or control character in an address, the subject, a header or a
  file name is refused, never passed on: nothing a caller forwards can add a
  header or a recipient.
- `Headers` adds fields such as `Auto-Submitted`. The fields the package
  writes (`From`, `To`, `Cc`, `Reply-To`, `Subject`, `Date`, `Message-ID`,
  `MIME-Version`, `Content-Type`, `Content-Transfer-Encoding`) are refused
  there.
- ASCII text in lines of at most 998 bytes is sent as it is, so a link in it
  stays whole; other text is quoted-printable. No relay needs 8BITMIME.
- An attachment comes from `Content` or, when that is nil, from `Reader`, read
  once before the first attempt. Its type defaults to that of the file name's
  extension.
- `Message.WriteTo` gives the bytes a relay would get.

## Without a relay

`mail.Dir{Path: dir}` writes each message to `<dir>/<time>-<random>.eml`,
mode 0600, for development and tests.

## Errors

`Send` and `NewClient` return a `*mail.Error`: `Op` is the step, `Type` the
kind, `Err` the cause (a `*textproto.Error` for a relay's answer).
`Temporary()` says whether a later attempt may pass.

- `ErrorTypeValidation`: the message or the configuration
- `ErrorTypeSize`: over `MaxMessageSize`
- `ErrorTypeNetwork`: the connection failed or broke
- `ErrorTypeTimeout`: an attempt outran `Timeout`, or the context ended
- `ErrorTypeTLS`: no TLS where it is required, or a failed handshake
- `ErrorTypeAuth`: credentials refused, or not safe to send
- `ErrorTypeRejected`: the relay refused the sender, a recipient or the message

## Not included

DKIM signing (the relay's work), AUTH mechanisms other than PLAIN, non-ASCII
addresses (SMTPUTF8, IDNA), inline images, and receiving mail.
