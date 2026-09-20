package emaildelivery

import "github.com/leodip/goiabada/core/errs"

// SMTPEncryption is how the SMTP connection is secured. It is here because EmailSender is the only
// thing in the tree that acts on it -- settings carries the value as a plain string column, so
// models does not name this type at all -- and out of core because the admin console sends no mail
// (#385).
type SMTPEncryption int

const (
	SMTPEncryptionNone SMTPEncryption = iota
	SMTPEncryptionSSLTLS
	SMTPEncryptionSTARTTLS
)

// String returns the wire value, or "" for an SMTPEncryption outside the declared range, rather
// than panicking on the slice index. Not reachable from any int conversion today -- the column is
// read through SMTPEncryptionFromString, which refuses anything it does not recognize -- but the
// guard goes on the type so the next caller cannot step on it (#385).
func (se SMTPEncryption) String() string {
	if se < SMTPEncryptionNone || se > SMTPEncryptionSTARTTLS {
		return ""
	}
	return []string{"none", "ssltls", "starttls"}[se]
}

func SMTPEncryptionFromString(s string) (SMTPEncryption, error) {
	// Treat empty string as "none" for backward compatibility
	if s == "" {
		return SMTPEncryptionNone, nil
	}
	switch s {
	case SMTPEncryptionNone.String():
		return SMTPEncryptionNone, nil
	case SMTPEncryptionSSLTLS.String():
		return SMTPEncryptionSSLTLS, nil
	case SMTPEncryptionSTARTTLS.String():
		return SMTPEncryptionSTARTTLS, nil
	}
	return SMTPEncryptionNone, errs.New("invalid SMTP encryption " + s)
}
