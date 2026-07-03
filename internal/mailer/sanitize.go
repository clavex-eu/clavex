package mailer

import (
	"fmt"
	"net/mail"
	"strings"
)

// SanitizeHeader removes CR and LF from an arbitrary header value (subject,
// display name, ...) to prevent SMTP header / email injection (CWE-93). An
// attacker who controls a recipient address, subject, or display name could
// otherwise inject extra headers or a forged body by embedding "\r\n"
// sequences. Use for any value interpolated into a message header line.
func SanitizeHeader(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return v
}

// SanitizeAddress validates an email address and returns its canonical
// addr-spec form (no display name). It rejects any value containing a newline
// or that is not a syntactically valid RFC 5322 address, which blocks header
// injection through the To/From fields.
func SanitizeAddress(addr string) (string, error) {
	if strings.ContainsAny(addr, "\r\n") {
		return "", fmt.Errorf("invalid email address: contains newline")
	}
	a, err := mail.ParseAddress(addr)
	if err != nil {
		return "", fmt.Errorf("invalid email address %q: %w", addr, err)
	}
	return a.Address, nil
}
