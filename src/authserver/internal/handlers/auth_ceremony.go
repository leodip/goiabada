package handlers

import (
	"crypto/subtle"
	"net/http"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/i18n"
	core_middleware "github.com/leodip/goiabada/core/middleware"
	"github.com/leodip/goiabada/core/oauth"
)

// ceremonyIdField is the hidden form field naming the authorization ceremony, and its name is
// duplicated in the auth-flow templates because a template cannot read a Go constant. A rename
// in one place alone renders a form whose every submission is refused, which the integration
// cases catch: they read the field out of the rendered page rather than building the form.
const ceremonyIdField = "ceremonyId"

// ceremonyIdLength matches continuationIdLength, and for the same reason its comment gives:
// over the 65-character alphabet GenerateSecurityRandomString draws from, this is far more
// entropy than the value needs. Nobody outside the session ever sees it and it authorizes
// nothing on its own.
const ceremonyIdLength = 32

// ceremonyMatches reports whether a submitted form belongs to the ceremony the session
// currently holds.
//
// An empty stored id is refused rather than matched against an empty submission. Only an auth
// context written by a binary from before #79 can carry one, and treating "" as equal to ""
// would make such a context accept a form naming no ceremony at all, which is every forged
// form. The cost is that a user mid-flow across a deploy is refused once and starts the
// authorization again.
//
// Constant time, like forgotPasswordCodeMatches and the client secret comparison in
// validators.ValidateTokenRequest. Not because this value is guessed at, but because a plain
// comparison stopping at the first differing byte is the kind of thing that is cheap to avoid
// and expensive to notice later.
func ceremonyMatches(contextCeremonyId string, submitted string) bool {
	if contextCeremonyId == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(contextCeremonyId), []byte(submitted)) == 1
}

// rejectCeremonyMismatch answers a submission that names a ceremony the session no longer
// holds: audit it, then render the error page at 400.
//
// The auth context is deliberately NOT touched. The ceremony that is current is the one the
// user is actually working on, in another tab, and clearing or advancing it here would let a
// forgotten tab cancel a live authorization with nothing left to recover from. The stale form
// is simply dead. The client is not told either, for the same reason: the client that would
// receive an error is the current one, whose authorization the user still wants (#79
// decision 5).
//
// Mirrors rejectResetPassword: audit, then render, at http.StatusBadRequest because a
// submission was genuinely refused.
func rejectCeremonyMismatch(httpHelper HttpHelper, auditLogger AuditLogger, w http.ResponseWriter,
	r *http.Request, authContext *oauth.AuthContext) {

	const maxAuditedValueLength = 100

	// Truncated for the same reason auditFailedResetPasswordCode truncates it:
	// MiddlewareRealIP resolves the IP from a forwarded header in a proxied deployment, so
	// this is a sink for a value that originates outside the process.
	clientIP := core_middleware.GetClientIPFromRequest(r)
	if len(clientIP) > maxAuditedValueLength {
		clientIP = clientIP[:maxAuditedValueLength]
	}

	details := map[string]interface{}{
		"clientId":  authContext.ClientId,
		"authState": authContext.AuthState,
		"ipAddress": clientIP,
	}
	// Absent rather than zero when the ceremony has not identified anyone yet, which is every
	// submission of the password form. A payload naming user 0 asserts a row that does not exist.
	if authContext.UserId != 0 {
		details["userId"] = authContext.UserId
	}
	auditLogger.Log(constants.AuditAuthCeremonyMismatch, details)

	bind := map[string]interface{}{
		"title":       i18n.T(r.Context(), "auth_error.ceremony_mismatch.title"),
		"error":       i18n.T(r.Context(), "auth_error.ceremony_mismatch.message"),
		"_httpStatus": http.StatusBadRequest,
	}

	if err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/auth_error.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}
