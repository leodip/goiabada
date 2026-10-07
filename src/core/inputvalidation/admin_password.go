package inputvalidation

import (
	"unicode/utf8"

	"github.com/leodip/goiabada/core/errs"
)

const (
	// adminPasswordMinCharacters is NIST SP 800-63B-4 §3.1.1.2's minimum for a password used as a
	// single-factor authenticator, which the first administrator's is until OTP is enrolled: the
	// admin console's client defaults to level2_optional. Characters, not bytes, as the account
	// password rule counts its own minimum (#409).
	adminPasswordMinCharacters = 15
	// adminPasswordMaxBytes is bcrypt's bound, in its unit: the auth server's passwordhash refuses
	// anything longer rather than truncate it.
	adminPasswordMaxBytes = 72
	// publishedAdminPassword is the password this project's samples, guides and configuration once
	// supplied, so anyone can try it on any deployment.
	publishedAdminPassword = "changeme"
)

// CheckAdminPassword answers why password may not be the first administrator's, or nil when it
// may. The first start seeds that administrator, holding authserver:manage, with a password no
// other validator sees, and the setup wizard writes the configuration that start reads, so the
// rule is defined once here, where both can reach it, and the two cannot disagree on which
// passwords seed (#500). The reason names no
// variable or flag: each caller knows which one the password came from and says so.
func CheckAdminPassword(password string) error {
	if password == "" {
		return errs.Errorf("it is empty, and the first administrator needs a password of at least %d characters",
			adminPasswordMinCharacters)
	}
	// Ahead of the length rule, which would refuse it too, so whoever copied it from an old guide
	// or sample is told why it is refused rather than only that it is short.
	if password == publishedAdminPassword {
		return errs.Errorf("it is %s, a password this project published in its samples and guides, so anyone could sign in with it: "+
			"choose another of at least %d characters", publishedAdminPassword, adminPasswordMinCharacters)
	}
	if len(password) > adminPasswordMaxBytes {
		return errs.Errorf("it is %d bytes long, and bcrypt accepts at most %d bytes: "+
			"shorten it, counting two to four bytes for each non-ASCII character",
			len(password), adminPasswordMaxBytes)
	}
	if n := utf8.RuneCountInString(password); n < adminPasswordMinCharacters {
		return errs.Errorf("it is %d characters long, and must be at least %d characters", n, adminPasswordMinCharacters)
	}
	return nil
}
