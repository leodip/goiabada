package authflow

import "github.com/leodip/goiabada/authserver/internal/ceremony"

// Level1SelectionResult is what SelectLevel1Method did: the step it saved the ceremony towards, and
// how that save went.
type Level1SelectionResult struct {
	// NextStep is the route the ceremony was saved to go to, /auth/pwd.
	NextStep string
	// SaveErr is the save's failure, ceremony.ErrCeremonyReplaced when the browser session no longer
	// holds the ceremony. The handler redirects to NextStep only when it is nil.
	SaveErr error
}

// SelectLevel1Method is GET /auth/level1, the choice of level 1 method for a ceremony in
// requires_level_1. The password is the only level 1 method, so it moves the ceremony to
// level1_password and saves it, and the handler sends the browser to /auth/pwd.
func SelectLevel1Method(browser stepSaver, authContext *ceremony.AuthContext) Level1SelectionResult {
	authContext.AuthState = ceremony.AuthStateLevel1Password
	return Level1SelectionResult{
		NextStep: "/auth/pwd",
		SaveErr:  browser.SaveAuthContext(authContext),
	}
}
