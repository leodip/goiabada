package communication

import (
	"net/smtp"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// loginAuth implements the AUTH LOGIN mechanism, which the standard library does not carry:
// net/smtp ships PLAIN and CRAM-MD5 only. LOGIN is not specified by any RFC (it is the expired
// draft-murchison-sasl-login), but it is the only password mechanism smtp.office365.com advertises
// after STARTTLS, so a client without it cannot reach that relay at all (#274).
//
// The exchange is two base64 challenges, conventionally "Username:" and "Password:", answered with
// the bare values. net/smtp hands Next the challenge already decoded and encodes the reply, so
// neither direction is base64 here.
//
// LOGIN sends the password in the clear inside the SASL exchange, exactly as PLAIN does. There is
// no TLS check in this type on purpose: SendEmail gates both mechanisms on the connection being
// TLS or the host being loopback before it issues any AUTH command, so the refusal names the
// encryption setting the operator has to change rather than net/smtp's "unencrypted connection"
// (#274).
type loginAuth struct {
	username string
	password string
	// answered counts the challenges already replied to, so a server whose prompts are not the
	// conventional words is still answered in order.
	answered int
}

func (a *loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}

	prompt := strings.ToLower(strings.TrimSpace(string(fromServer)))
	switch {
	case strings.HasPrefix(prompt, "username"):
		a.answered++
		return []byte(a.username), nil
	case strings.HasPrefix(prompt, "password"):
		a.answered++
		return []byte(a.password), nil
	}

	// The prompt is not one of the conventional words. Answer by position, which is what the
	// mechanism actually defines: the username first, the password second.
	switch a.answered {
	case 0:
		a.answered++
		return []byte(a.username), nil
	case 1:
		a.answered++
		return []byte(a.password), nil
	}
	return nil, errs.New("unexpected server challenge")
}
