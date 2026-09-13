package handlers

import (
	"testing"

	"github.com/leodip/goiabada/core/testutil"
)

// TestHandlers_NoDeadInterfaces fails the admin console unit tier when any interface declared under
// internal/handlers has no reference anywhere in this module, production or test.
// testutil.AssertNoDeadInterfaces carries the rule and the reasoning for each shape it refuses.
//
// This is the package the rule was written for. interfaces.go declared fourteen interfaces and nine
// of them had no consumer at all: ProfileValidator, EmailValidator, EmailSender, AddressValidator,
// PhoneValidator, UserCreator, OtpSecretGenerator, PasswordValidator and TCPConnectionTester. Four
// of this package's kernel imports existed only to spell their method signatures, two temporary
// exception rows in ARCHITECTURE.md existed only to permit those imports, and internal/tcputils was
// still in the tree because the ninth of them named it (#333).
//
// Nothing caught it, and nothing else would have. golangci-lint's unused says nothing about an
// exported declaration; the two settings that might have were run over the unmodified tree, where
// all nine were still present, and between them reported none of the nine. A dead interface is
// inert rather than broken, which is exactly why it needs a lint: it compiles, it holds its
// imports open, and it reads to the next person as a seam somebody is using.
//
// The scope is this module, not the source root. An interface under internal/ is unreferenceable
// from outside the module that declares it, and the auth server's half of this guard sits beside
// its own interfaces.go for the same reason.
func TestHandlers_NoDeadInterfaces(t *testing.T) {
	testutil.AssertNoDeadInterfaces(t, "adminconsole/internal/handlers")
}
