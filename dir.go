package mail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Dir writes each message to a file in Path instead of sending it, for
// development and tests. A file holds exactly what a relay would be given.
type Dir struct {
	Path string
}

func (d Dir) String() string { return "directory " + d.Path }

// Send writes the message as <unix-nanos>-<random>.eml, readable by its
// owner alone, and creates Path when it is missing.
func (d Dir) Send(_ context.Context, msg *Message) error {
	r, err := msg.render(0)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return &Error{Op: "write", Type: ErrorTypeNetwork, Err: err}
	}
	var nonce [4]byte
	rand.Read(nonce[:])
	name := fmt.Sprintf("%d-%s.eml", time.Now().UnixNano(), hex.EncodeToString(nonce[:]))
	if err := os.WriteFile(filepath.Join(d.Path, name), r.data, 0o600); err != nil {
		return &Error{Op: "write", Type: ErrorTypeNetwork, Err: err}
	}
	return nil
}
