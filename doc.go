// Package mail sends email with the standard library alone. A Client delivers
// through an SMTP relay: it keeps connections for reuse, retries what a later
// attempt can fix, and upgrades to TLS unless told otherwise. A Message renders
// itself as RFC 5322 text, and Dir writes messages to files where a test or a
// development setup wants no relay.
//
// The package signs nothing (DKIM is the relay's work), speaks AUTH PLAIN only,
// and takes ASCII addresses only. See the README for the defaults and limits.
package mail
