package accounthandlers

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/authserver/internal/authflow"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// signInBrowser is the per-request adapter authflow.PasswordProof writes the browser session
// through: the response writer and the request of the one request it was built for, passed unchanged
// to every call. Built for each request and never stored, as the ceremony handlers' adapter is.
type signInBrowser struct {
	w          http.ResponseWriter
	r          *http.Request
	ceremonies signInCeremonies
}

// RegenerateSession is ceremony.Store.RegenerateSession on this request.
func (b *signInBrowser) RegenerateSession(ceremonyId string, userId int64) error {
	return b.ceremonies.RegenerateSession(b.w, b.r, ceremonyId, userId)
}

// SaveAuthContext is ceremony.Store.SaveAuthContext on this request.
func (b *signInBrowser) SaveAuthContext(authContext *ceremony.AuthContext) error {
	return b.ceremonies.SaveAuthContext(b.w, b.r, authContext)
}

// carryOnSignIn signs a user who has just registered, or activated their account, into the sign-in
// that started the registration, and sends the browser on to its next step (#622 decision 9).
// ceremonyId is the sign-in the password page's Create an account link named, from the page's URL
// (registrationCeremonyId), or empty for a registration reached from anywhere else. user is the
// account just created, with the password the user just chose.
//
// It carries the sign-in on only while the browser holds it at the password step, the step whose
// page has the link: the password proven is recorded on it as the password page records one
// (authflow.PasswordProof), the browser session's identifier rotated and the sign-in saved past the
// password, and the browser redirected to the sign-in's next step, which leads on through two-factor
// when the app asks for it, the acceptance step and consent. It reports true when it answered.
//
// It reports false, having answered nothing, everywhere else: no sign-in named, one the browser does
// not hold (another browser, or a sign-in that ended or expired), one past the password step, and one
// the browser lost before the rotation or the save landed. The account exists by then, so a failure
// here is no reason to answer that the registration failed: the caller answers its own page, which
// tells the user what to do next.
func carryOnSignIn(w http.ResponseWriter, r *http.Request, ceremonies signInCeremonies,
	proof *authflow.PasswordProof, baseURL string, ceremonyId string, user *record.User) bool {

	if ceremonyId == "" {
		return false
	}
	authContext, err := ceremonies.HeldAuthContext(r, ceremonyId)
	if errors.Is(err, ceremony.ErrNoAuthContext) || errors.Is(err, ceremony.ErrCeremonyNotHeld) {
		return false
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "unable to read the sign-in a registration came from", "error", err)
		return false
	}
	if !authContext.InState(ceremony.AuthStateLevel1Password) {
		return false
	}

	result := proof.Record(r.Context(), &signInBrowser{w: w, r: r, ceremonies: ceremonies}, authContext, user)
	if errors.Is(result.SaveErr, ceremony.ErrCeremonyReplaced) {
		slog.WarnContext(r.Context(), "the browser session no longer holds the sign-in a registration came from")
		return false
	}
	if result.SaveErr != nil {
		slog.ErrorContext(r.Context(), "unable to carry on the sign-in a registration came from", "error", result.SaveErr)
		return false
	}

	// 303, as every redirect answering a POST of the sign-in is: the browser follows with a GET and
	// sends the form's body, the password among it, nowhere (RFC 9700 section 4.12).
	next := baseURL + result.NextStep + "?" + url.Values{ceremony.QueryParameter: {authContext.CeremonyId}}.Encode()
	http.Redirect(w, r, next, http.StatusSeeOther)
	return true
}
