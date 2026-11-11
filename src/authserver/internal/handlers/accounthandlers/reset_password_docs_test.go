package accounthandlers

// A password reset started from a client's sign-in page, as Password recovery describes it, held
// to the console's labels (#812).
//
// The page is where an administrator learns what a user who forgot their password goes through:
// the link on the sign-in page, the way back to it from the forgot password page, and that a reset
// finished in the same browser carries the sign-in on into the application. A label the page names
// that the auth server no longer shows sends the reader looking for a link that isn't there.
//
// It reads the page and the English catalog, and nothing else.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/core/guard"
	"github.com/leodip/goiabada/core/i18n"
)

const passwordRecoveryPage = "site/src/content/docs/concepts/password-recovery.mdx"

// The section names the sign-in page's link and the forgot password page's way back by the text the
// pages show, and says a reset in the same browser carries the sign-in on, in the client's brand.
func TestResetPasswordDocs_AResetFromASignInCarriesItOn(t *testing.T) {
	ctx := context.Background()
	guard.AssertSectionSays(t, filepath.Dir(guard.SourceRoot(t)), passwordRecoveryPage,
		"## Resetting from a client's sign-in page",
		[]string{
			"**" + i18n.T(ctx, "auth.pwd.forgot_password") + "**",
			"**" + i18n.T(ctx, "forgot_password.back_to_sign_in") + "**",
			"same browser",
			"signs them in and sends them on to the client",
			"[two-factor authentication](/guides/require-two-factor-authentication/)",
			"[brand](/concepts/clients/#brand)",
		}, nil)
}
