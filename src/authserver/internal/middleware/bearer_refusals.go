package middleware

import (
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/core/errs"
)

// bearerRefusals is how one bearer-guarded surface answers a refusal. The guards decide what is
// refused and the status class; the surface decides the body, because the two surfaces promise
// different ones. The admin and account APIs answer their documented {error_code,
// error_description} envelope; /userinfo answers the RFC 6749 section 5.2 shape its handler uses,
// since OIDC Core 1.0 section 5.3.3 sends its errors through RFC 6750, which fixes only the
// challenge. Which of the two a guard set writes is fixed when routes.go builds it, never read off
// the request path (#435).
//
// Every refusal but the 500 carries a challenge naming the realm: a 401 both the Bearer and the DPoP
// challenge, Bearer first, and a 400 or 403 the challenge of the scheme the request used (RFC 9449
// section 7.2, #42 decision 10). They share one WWW-Authenticate field line, as RFC 9449's figures
// write them, so a client reading the header's first line reads both.
type bearerRefusals interface {
	// missing answers a request carrying no bearer credential: 401 with both challenges naming the
	// realm alone, per RFC 6750 section 3.1 and RFC 9449 section 7.2.
	missing(w http.ResponseWriter, r *http.Request)
	// invalidRequest answers a malformed bearer request, a token sent by two methods or an
	// access_token parameter sent twice: 400 invalid_request, per RFC 6750 section 3.1, the error in
	// the challenge of each scheme used.
	invalidRequest(w http.ResponseWriter, r *http.Request, description string, used schemes)
	// invalidToken answers a presented token that is refused, whatever the reason: 401
	// invalid_token, per RFC 6750 section 3.1, the error in the challenge of the scheme used.
	invalidToken(w http.ResponseWriter, r *http.Request, description string, used schemes)
	// invalidDPoPProof answers a token presented with the DPoP scheme whose proof is missing,
	// repeated, fails a check or was used before: 401 invalid_dpop_proof, per RFC 9449 section 7.1,
	// the error in the DPoP challenge.
	invalidDPoPProof(w http.ResponseWriter, r *http.Request)
	// forbidden answers a valid token that does not reach the route: 403 insufficient_scope. apiCode
	// is the API envelope's error_code, which says why; the challenge's error is RFC 6750's one
	// code for any 403, in the challenge of the scheme used.
	forbidden(w http.ResponseWriter, r *http.Request, apiCode, description string, used schemes)
	// insufficientUserAuthentication answers a valid token whose sign-in is too old or too weak for
	// the route: 401 insufficient_user_authentication with the acr_values and max_age the client
	// signs the user in again with, per RFC 9470 section 3, in the challenge of the scheme used.
	insufficientUserAuthentication(w http.ResponseWriter, r *http.Request, description, acrValues string, maxAge time.Duration,
		used schemes)
	// internalError answers a fault the guard could not decide past: 500, logged once. sid is the
	// session identifier the guard was checking, or empty before it has one; it is the one value the
	// guards log beside an error.
	internalError(w http.ResponseWriter, r *http.Request, err error, sid string)
}

// invalidDPoPProofDescription is what a DPoP request whose proof is refused is told, whatever the
// reason, which the Warn record says instead, as the token endpoint tells it.
const invalidDPoPProofDescription = "The DPoP proof is invalid."

// apiBearerRefusals answers in the admin and account API's envelope, through the same writer every
// API handler uses.
//
// i18n surface: B — machine. Bearer-token failures on /api/v1/* do not localize: each description
// is also the challenge's, which RFC 6750 section 3 holds to ASCII. TestBearerRefusals_EnglishOnly
// holds every sentence to bearerEnglishRefusals and the body to the challenge's string.
type apiBearerRefusals struct{}

func (apiBearerRefusals) missing(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("WWW-Authenticate", unauthorizedChallenges(0, "", ""))
	apiresponse.WriteError(w, "Access token required.", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
}

func (apiBearerRefusals) invalidRequest(w http.ResponseWriter, _ *http.Request, description string, used schemes) {
	w.Header().Set("WWW-Authenticate", usedChallenges(used, "invalid_request", description))
	apiresponse.WriteError(w, description, "INVALID_REQUEST", http.StatusBadRequest)
}

func (apiBearerRefusals) invalidToken(w http.ResponseWriter, _ *http.Request, description string, used schemes) {
	w.Header().Set("WWW-Authenticate", unauthorizedChallenges(used, "invalid_token", description))
	apiresponse.WriteError(w, description, "INVALID_TOKEN", http.StatusUnauthorized)
}

func (apiBearerRefusals) invalidDPoPProof(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("WWW-Authenticate", unauthorizedChallenges(schemeDPoP, "invalid_dpop_proof", invalidDPoPProofDescription))
	apiresponse.WriteError(w, invalidDPoPProofDescription, "INVALID_DPOP_PROOF", http.StatusUnauthorized)
}

func (apiBearerRefusals) forbidden(w http.ResponseWriter, _ *http.Request, apiCode, description string, used schemes) {
	w.Header().Set("WWW-Authenticate", usedChallenges(used, "insufficient_scope", description))
	apiresponse.WriteError(w, description, apiCode, http.StatusForbidden)
}

func (apiBearerRefusals) insufficientUserAuthentication(w http.ResponseWriter, _ *http.Request, description, acrValues string,
	maxAge time.Duration, used schemes) {
	w.Header().Set("WWW-Authenticate", stepUpChallenges(used, description, acrValues, maxAge))
	apiresponse.WriteError(w, description, "INSUFFICIENT_USER_AUTHENTICATION", http.StatusUnauthorized)
}

func (apiBearerRefusals) internalError(w http.ResponseWriter, r *http.Request, err error, sid string) {
	if sid == "" {
		apiresponse.WriteInternalServerError(w, r, err)
		return
	}
	apiresponse.WriteInternalServerError(w, r, err, "sid", sid)
}

// jsonErrorWriter is the one thing the /userinfo refusals and LimitROPC need of the auth server's
// JSON writer: the RFC 6749 error writer the userinfo and token handlers answer through.
// render.Renderer satisfies it.
type jsonErrorWriter interface {
	JSONError(w http.ResponseWriter, r *http.Request, err error)
}

// userinfoBearerRefusals answers /userinfo's refusals as {error, error_description}, mirroring the
// challenge, through the JSON writer the handler itself uses, so a refusal from a guard and one
// from the handler read the same on the wire.
type userinfoBearerRefusals struct {
	jsonWriter jsonErrorWriter
}

// missing writes the challenges and no body. RFC 6750 section 3.1: a request lacking any
// authentication information SHOULD NOT be told an error code or other error information, and
// on this surface the body would be nothing but that.
func (userinfoBearerRefusals) missing(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("WWW-Authenticate", unauthorizedChallenges(0, "", ""))
	w.WriteHeader(http.StatusUnauthorized)
}

func (u userinfoBearerRefusals) invalidRequest(w http.ResponseWriter, r *http.Request, description string, used schemes) {
	u.refuse(w, r, "invalid_request", description, http.StatusBadRequest, usedChallenges(used, "invalid_request", description))
}

func (u userinfoBearerRefusals) invalidToken(w http.ResponseWriter, r *http.Request, description string, used schemes) {
	u.refuse(w, r, "invalid_token", description, http.StatusUnauthorized, unauthorizedChallenges(used, "invalid_token", description))
}

func (u userinfoBearerRefusals) invalidDPoPProof(w http.ResponseWriter, r *http.Request) {
	u.refuse(w, r, "invalid_dpop_proof", invalidDPoPProofDescription, http.StatusUnauthorized,
		unauthorizedChallenges(schemeDPoP, "invalid_dpop_proof", invalidDPoPProofDescription))
}

func (u userinfoBearerRefusals) forbidden(w http.ResponseWriter, r *http.Request, _ string, description string, used schemes) {
	u.refuse(w, r, "insufficient_scope", description, http.StatusForbidden, usedChallenges(used, "insufficient_scope", description))
}

func (u userinfoBearerRefusals) insufficientUserAuthentication(w http.ResponseWriter, r *http.Request, description,
	acrValues string, maxAge time.Duration, used schemes) {
	u.refuse(w, r, "insufficient_user_authentication", description, http.StatusUnauthorized,
		stepUpChallenges(used, description, acrValues, maxAge))
}

// internalError answers server_error at 500 through the writer, which logs the one record.
// JSONError's record carries the error and nothing else, so the session identifier rides in the
// error's text instead, where that one record still shows it; answering through any other writer
// would log twice or answer the API's envelope here.
func (u userinfoBearerRefusals) internalError(w http.ResponseWriter, r *http.Request, err error, sid string) {
	if sid != "" {
		err = errs.Wrapf(err, "sid %s", sid)
	}
	u.jsonWriter.JSONError(w, r, err)
}

func (u userinfoBearerRefusals) refuse(w http.ResponseWriter, r *http.Request, errorCode, description string, status int, challenge string) {
	u.jsonWriter.JSONError(w, r, protocolvalidation.NewErrorDetailWithHTTPStatusAndWWWAuthenticate(
		errorCode, description, status, challenge))
}
