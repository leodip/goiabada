package authflow

import (
	"context"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
)

// The sign-in setup's recovery-codes step (#257 decision 14). An authenticator set up during a
// sign-in comes with a set of recovery codes, and the user sees them on one page after the accepted
// setup code, before the sign-in goes on: OTPSubmission saves the ceremony in level2_recovery_codes
// holding the set, RecoveryCodesPrompt shows it once, and ContinueAfterRecoveryCodes moves the
// ceremony on to authentication_completed.
//
// The set rides on the ceremony, in the sealed browser-session row, only until that page first
// renders: the prompt takes it off in the save before the page is drawn, so a reload, a second tab
// or a failure after the save shows it no more. The step is its own state rather than the setup
// POST's answer, so the POST answers 303 as every sign-in POST does (RFC 9700 section 4.12), and a
// reload of the page draws it again without a "resubmit the form?" prompt.

// recoveryCodesStep is the route of the page that shows the set.
const recoveryCodesStep = "/auth/recovery-codes"

// holdRecoveryCodes leaves the set on the ceremony for the page that shows it, and moves the
// ceremony to that page's state. The caller has recorded the code that set up the authenticator.
func holdRecoveryCodes(authContext *ceremony.AuthContext, codes []string) {
	authContext.RecoveryCodes = append([]string(nil), codes...)
	authContext.AuthState = ceremony.AuthStateLevel2RecoveryCodes
}

// RecoveryCodesPrompt is GET /auth/recovery-codes in level2_recovery_codes: it takes the set of
// recovery codes off the ceremony for the page to show once. The route table builds one.
type RecoveryCodesPrompt struct {
	database ceremonyClientDisplayDatabase
}

// NewRecoveryCodesPrompt builds the operation over the database it reads the client block from.
func NewRecoveryCodesPrompt(database ceremonyClientDisplayDatabase) *RecoveryCodesPrompt {
	return &RecoveryCodesPrompt{database: database}
}

// RecoveryCodesPromptResult is what RecoveryCodesPrompt.Run prepared.
type RecoveryCodesPromptResult struct {
	Display *ClientDisplayInfo
	// RecoveryCodes is the set to show, as drawn, and nil when the ceremony held none: the set was
	// already shown, and the page says so.
	RecoveryCodes []string

	// SaveErr is the failure of the save that took the set off the ceremony:
	// ceremony.ErrCeremonyReplaced when the browser session no longer holds the ceremony. The
	// handler renders the page only when it is nil, so a set is never shown without that save
	// having landed.
	SaveErr error
}

// Run prepares the page. In order:
//
//  1. Loads the client block (loadClientDisplay); a failure is returned as an error, and the set
//     stays on the ceremony for the next render.
//  2. A ceremony holding no set: the page that says the codes were already shown. Nothing is saved.
//  3. Otherwise takes the set off the ceremony and saves it, still in level2_recovery_codes, so the
//     page's Continue still works; the set is returned for the page.
func (p *RecoveryCodesPrompt) Run(ctx context.Context, browser stepSaver,
	authContext *ceremony.AuthContext) (RecoveryCodesPromptResult, error) {

	display, err := loadClientDisplay(ctx, p.database, authContext)
	if err != nil {
		return RecoveryCodesPromptResult{}, err
	}

	if len(authContext.RecoveryCodes) == 0 {
		return RecoveryCodesPromptResult{Display: display}, nil
	}

	codes := authContext.RecoveryCodes
	authContext.RecoveryCodes = nil
	return RecoveryCodesPromptResult{
		Display:       display,
		RecoveryCodes: codes,
		SaveErr:       browser.SaveAuthContext(authContext),
	}, nil
}

// RecoveryCodesContinuation is what ContinueAfterRecoveryCodes did: the step it saved the ceremony
// towards, and how that save went.
type RecoveryCodesContinuation struct {
	// NextStep is the route the ceremony was saved to go to, /auth/completed.
	NextStep string
	// SaveErr is the save's failure, ceremony.ErrCeremonyReplaced when the browser session no longer
	// holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error
}

// ContinueAfterRecoveryCodes is POST /auth/recovery-codes, the page's Continue: it moves the
// ceremony to authentication_completed, holding no set, whether or not the page was ever drawn, and
// saves it, and the handler sends the browser to /auth/completed.
func ContinueAfterRecoveryCodes(browser stepSaver, authContext *ceremony.AuthContext) RecoveryCodesContinuation {
	authContext.RecoveryCodes = nil
	authContext.AuthState = ceremony.AuthStateAuthenticationCompleted
	return RecoveryCodesContinuation{
		NextStep: "/auth/completed",
		SaveErr:  browser.SaveAuthContext(authContext),
	}
}
