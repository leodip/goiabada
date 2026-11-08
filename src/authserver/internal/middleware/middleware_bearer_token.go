package middleware

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/dpop"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// tokenParser is the one thing this middleware needs of the auth server's token parser:
// turning the presented string into a validated token. signingkeys.TokenParser satisfies
// it. Declared as the shape used rather than the whole parser, which is what the
// neighbouring ports in this package already do (#385).
type tokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, withExpirationCheck bool) (*oauth.JwtToken, error)
}

// BearerToken is the bearer guard set for one surface: the parse guard, the scope guards,
// the user-bound guard and the session guard, answering every refusal through that surface's
// writer. routes.go builds one for the admin and account APIs and one for /userinfo, so which body a
// refusal carries is fixed at construction and never inferred from the request (#435).
type BearerToken struct {
	tokenParser tokenParser
	refusals    bearerRefusals
	proofs      ResourceProofs
}

// ResourceProofs is how the guards check the DPoP proof beside a token presented with the DPoP
// scheme (RFC 9449 section 7.1): the checker for the public base URL, the replay store that makes
// each proof single-use, and the server's clock, against which a proof's iat is judged here, since
// the resources take no nonce (#42 decisions 7 to 10).
type ResourceProofs struct {
	Checker *dpop.Checker
	Replays dpopProofRecorder
	// Now is the server's clock, time.Now when nil.
	Now func() time.Time
}

// dpopProofRecorder is the replay store: it records a proof's replay key until expiresAt, and
// reports false when the key was recorded before, by this instance or another sharing the database;
// and it releases a record, which unspends its proof.
type dpopProofRecorder interface {
	RecordDPoPProof(ctx context.Context, tx *sql.Tx, proofHash string, expiresAt time.Time) (bool, error)
	ReleaseDPoPProof(ctx context.Context, tx *sql.Tx, proofHash string) error
}

// NewBearerTokenForAPI builds the guard set for /api/v1/*, whose refusals answer the
// admin and account API's {error_code, error_description} envelope.
func NewBearerTokenForAPI(tokenParser tokenParser, proofs ResourceProofs) *BearerToken {
	return &BearerToken{tokenParser: tokenParser, refusals: apiBearerRefusals{}, proofs: proofs}
}

// NewBearerTokenForUserInfo builds the guard set for /userinfo, whose refusals answer
// {error, error_description} through jsonWriter, the writer the userinfo handler answers through.
func NewBearerTokenForUserInfo(tokenParser tokenParser, jsonWriter jsonErrorWriter, proofs ResourceProofs) *BearerToken {
	return &BearerToken{tokenParser: tokenParser, refusals: userinfoBearerRefusals{jsonWriter: jsonWriter}, proofs: proofs}
}

// bearerScheme is the auth-scheme RFC 6750 section 2.1 defines. It is compared case-insensitively:
// that section's `credentials = "Bearer" 1*SP b64token` is ABNF, whose quoted strings are case
// insensitive (RFC 5234 section 2.3), and RFC 9110 section 11.1 calls the auth-scheme a
// "case-insensitive token". Before #435 only "Bearer " matched, so a client sending "bearer" was
// refused as if it had sent nothing, where section 2.1 says resource servers MUST support the method.
const bearerScheme = "Bearer"

// dpopScheme is the auth-scheme RFC 9449 section 7.1 defines, `"DPoP" 1*SP token68`, compared
// case-insensitively as bearerScheme is. Only the Authorization header carries it: the RFC defines no
// form-body method for a DPoP-bound token.
const dpopScheme = "DPoP"

// The sentences a token presented with the wrong scheme for its binding is told, and a proof by
// another key than the token's. A presenter holding the token can read its cnf, so saying which
// tells it nothing it does not hold.
const (
	boundAsBearerDescription = "The access token is bound to a DPoP key and must be sent with the DPoP scheme."
	unboundAsDPoPDescription = "The access token is not bound to a DPoP key and must be sent with the Bearer scheme."
	keyBindingDescription    = "The DPoP proof is not signed with the key the access token is bound to."
)

// invalidTokenDescription is what a presented token that is refused is told, whatever the reason.
// One sentence for every reason, since the reasons are the signature, the expiry, the token's kind
// and its audience, and naming which would tell a presenter which of those it got right.
const invalidTokenDescription = "The access token is invalid."

// formMediaType is the media type RFC 6750 section 2.2's body method requires, lowercase, which is
// how mime.ParseMediaType returns every spelling of it.
const formMediaType = "application/x-www-form-urlencoded"

// JwtAuthorizationHeaderToContext is the one place that decides whether a bearer credential was
// presented, and it decides it for every guard behind it. Three methods carry one: RFC 6750 section
// 2.1's Authorization header with the Bearer scheme; RFC 9449 section 7.1's Authorization header
// with the DPoP scheme, beside a DPoP proof; and, for a POST with a form-encoded body, RFC 6750
// section 2.2's access_token body parameter, which OIDC Core 1.0 section 5.3.1 lets the UserInfo
// endpoint accept and which is a Bearer method. A token in the URL query is section 2.3's method,
// which this server does not support, so it is no credential at all.
//
// What each request is answered, and why (#435, #42 decision 10). Every 401 carries a Bearer and a
// DPoP challenge, Bearer first, the error in the challenge of the scheme used; a 400 carries the
// challenge of each scheme used.
//
//   - A form body that does not parse answers 400 invalid_request, before either method is
//     looked at. Section 3.1 names a request that "is otherwise malformed" invalid_request, and a
//     body that cannot be read cannot say whether it carries a second token: url.ParseQuery keeps
//     the pairs it could read, so admitting the header beside it admitted a request that sent the
//     token by two methods, and admitting a readable access_token beside it acted on half a body.
//     The token endpoint answers the same body the same way, a body cut at the request-body limit
//     included (#426).
//   - An Authorization header sent more than once answers 400 invalid_request. Its value is one
//     credentials production, not a list (RFC 9110 section 11.6.2), so section 5.3 forbids a
//     second field line, and section 3.1 names a request that "is otherwise malformed"
//     invalid_request. Before #435 the first line silently won, so a Bearer token behind a Basic
//     line read as no credential at all, and a second token behind a Bearer line was never seen.
//   - An access_token body parameter sent more than once answers 400 invalid_request, which
//     section 3.1 defines for a request that "repeats the same parameter". Before #435 the first
//     copy silently won.
//   - Both methods at once answers 400 invalid_request. RFC 6750 section 2: "Clients MUST NOT use
//     more than one method to transmit the token in each request", and section 3.1 names that
//     request invalid_request. Before #435 the header silently won. A DPoP header line beside a
//     body token used both schemes, and RFC 9449 section 7.2 figure 19 puts the error in both
//     challenges.
//   - A presented token that is empty, fails validation, or is not an access token for this server
//     (isAccessTokenForAuthServer, #401) answers 401 invalid_token here and now. Every route group
//     mounting this guard requires a token, so none is handed a refused one as though it were
//     optional, and a refused token no longer reads as a missing one.
//   - A token bound to a DPoP key, one carrying cnf.jkt, presented by a Bearer method answers 401
//     invalid_token: RFC 9449 section 7.2 MUST reject a DPoP-bound token received as a bearer
//     token. A token bound to no key presented with the DPoP scheme answers the same, since a client
//     that sent a proof was always issued a bound token, and admitting it would let the client
//     believe a stolen token useless when it is not (#42 decision 10). A stray DPoP header beside a
//     bearer token bound to no key is ignored.
//   - A bound token with the DPoP scheme needs its proof (dpopProof), and answers 401
//     invalid_dpop_proof when the proof is missing, repeated or fails a check, and 401 invalid_token
//     when a valid proof is signed by another key than the token's (RFC 9449 section 7.1 figure 16).
//     An accepted proof goes on the context for the guards behind, which then challenge in the DPoP
//     scheme, and for RecordDPoPProof, which spends it once they have all passed.
//   - A token the parser could not check, because the signing keys could not be read or decoded,
//     answers the surface's 500. The fault says nothing about the token, and 401 invalid_token
//     would tell the client a token that may be good is bad (#680). So does a proof checker that
//     cannot judge the proof.
//   - No credential, which includes another scheme such as Basic, passes through with nothing in the
//     context; the scope guard behind it answers the challenges with no error.
//
// A validated token is stored with reqctx.WithBearerToken, which every guard behind this reads.
func (m *BearerToken) JwtAuthorizationHeaderToContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authorizations := r.Header.Values("Authorization")
			headerScheme, headerToken, inHeader := credentialsFromHeader(r.Header.Get("Authorization"))
			bodyToken, inBody, repeated, err := bearerTokenFromForm(r)
			used := schemesPresented(authorizations, inBody)

			if err != nil {
				slog.WarnContext(r.Context(), "rejecting bearer request: the request body could not be parsed", "error", err)
				m.refusals.invalidRequest(w, r, "The request body could not be parsed.", used)
				return
			}
			if len(authorizations) > 1 {
				slog.WarnContext(r.Context(), "rejecting bearer request: the authorization header was repeated")
				m.refusals.invalidRequest(w, r, "The Authorization header must be sent once.", used)
				return
			}
			if repeated {
				slog.WarnContext(r.Context(), "rejecting bearer request: the access_token parameter was repeated")
				m.refusals.invalidRequest(w, r, "The access_token parameter must be sent once.", used)
				return
			}
			if inHeader && inBody {
				slog.WarnContext(r.Context(), "rejecting bearer request: the token was sent in the header and in the body")
				m.refusals.invalidRequest(w, r, "The access token must be sent by one method only.", used)
				return
			}
			if !inHeader && !inBody {
				next.ServeHTTP(w, r)
				return
			}

			scheme, tokenStr := schemeBearer, bodyToken
			if inHeader {
				scheme, tokenStr = headerScheme, headerToken
			}
			if tokenStr == "" {
				slog.WarnContext(r.Context(), "rejecting bearer token: the token is empty")
				m.refusals.invalidToken(w, r, invalidTokenDescription, scheme)
				return
			}
			token, err := m.tokenParser.DecodeAndValidateTokenString(r.Context(), tokenStr, true)
			if err != nil && !errors.Is(err, signingkeys.ErrTokenRefused) {
				m.refusals.internalError(w, r, errs.Wrap(err, "unable to check the bearer token"), "")
				return
			}
			if err != nil {
				slog.WarnContext(r.Context(), "rejecting bearer token: the token did not validate", "error", err)
				m.refusals.invalidToken(w, r, invalidTokenDescription, scheme)
				return
			}
			if !isAccessTokenForAuthServer(r.Context(), token) {
				m.refusals.invalidToken(w, r, invalidTokenDescription, scheme)
				return
			}

			ctx := reqctx.WithBearerToken(r.Context(), *token)
			boundTo := issuance.AccessTokenThumbprint(*token)
			switch {
			case scheme == schemeBearer && boundTo != "":
				slog.WarnContext(r.Context(), "rejecting bearer token: a DPoP-bound token was sent with the Bearer scheme",
					"client_id", token.StringClaim("client_id"))
				m.refusals.invalidToken(w, r, boundAsBearerDescription, scheme)
				return
			case scheme == schemeDPoP && boundTo == "":
				slog.WarnContext(r.Context(), "rejecting bearer token: a token bound to no DPoP key was sent with the DPoP scheme",
					"client_id", token.StringClaim("client_id"))
				m.refusals.invalidToken(w, r, unboundAsDPoPDescription, scheme)
				return
			case scheme == schemeDPoP:
				proof, ok := m.dpopProof(w, r, token, tokenStr, boundTo)
				if !ok {
					return
				}
				ctx = reqctx.WithDPoPProof(ctx, proof)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// dpopProof checks the proof beside a token presented with the DPoP scheme as RFC 9449 section 7.1
// asks of a resource: every check of section 4.3 (#42 decisions 4 to 6), the ath of tokenStr, and
// the iat within a minute either side of the server's clock, since the resources take no nonce
// (decision 8); then that the proof's key is the one the token is bound to, whose thumbprint
// boundTo is. A proof it refuses has been answered, and it reports false.
func (m *BearerToken) dpopProof(w http.ResponseWriter, r *http.Request, token *oauth.JwtToken, tokenStr, boundTo string) (*dpop.Proof, bool) {
	if m.proofs.Checker == nil {
		m.refusals.internalError(w, r, errs.New("no DPoP proof checker is configured for this surface"), "")
		return nil, false
	}
	proof, err := m.proofs.Checker.Check(dpop.Request{
		Proofs:      r.Header.Values("DPoP"),
		Method:      r.Method,
		Path:        dpop.RequestPath(r.RequestURI, r.URL.EscapedPath()),
		AccessToken: tokenStr,
		Now:         m.proofs.now(),
	})
	if errors.Is(err, dpop.ErrInvalidProof) {
		// The reason as a message, as the token endpoint logs it: a client's mistake, with no stack.
		slog.WarnContext(r.Context(), "dpop proof refused at a resource",
			"reason", err.Error(), "client_id", token.StringClaim("client_id"))
		m.refusals.invalidDPoPProof(w, r)
		return nil, false
	}
	if err != nil {
		m.refusals.internalError(w, r, errs.Wrap(err, "unable to check the DPoP proof"), "")
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(proof.Thumbprint), []byte(boundTo)) != 1 {
		slog.WarnContext(r.Context(), "rejecting bearer token: the DPoP proof's key is not the one the token is bound to",
			"client_id", token.StringClaim("client_id"))
		m.refusals.invalidToken(w, r, keyBindingDescription, schemeDPoP)
		return nil, false
	}
	return proof, true
}

// RecordDPoPProof spends the DPoP proof the parse guard accepted, recording it in the replay store
// until its iat plus a minute, the last moment the resources could accept it again (#42 decisions 8
// and 9, RFC 9449 section 11.1), and dpop.ReplayRecordGrace beyond, for the instances whose clocks
// run behind the one that sweeps. It is the last guard on every route, behind the bearer guards and
// the route's rate limiters, so only a request every other guard admitted spends its proof, just
// before its handler serves it. The iat is judged again first, at the clock of this moment: a proof
// whose window ended while the guards ahead ran is refused as an invalid proof, as it would be were
// it sent now, and so can never be recorded as new after a sweep removed its record. A proof recorded before,
// by this instance or another sharing the database, is a replay, answered 401 invalid_dpop_proof
// with a Warn record. A store that cannot answer is the surface's 500: the request never goes
// ahead unchecked. A request whose token was not presented with the DPoP scheme passes through.
//
// The handler still has checks of its own: the request body, the session's and the credentials'
// (a current password, an OTP code), whether what it names exists. A request one of them refuses
// has not succeeded, so it leaves its proof unspent too (decision 9): when the handler answers a
// 4xx, the record this call stored is released before that status is written, so the client can
// never see the refusal while its proof is still recorded, and can send the proof again with the
// request corrected. The proof is recorded before the handler runs rather than at each handler's
// own last check, so that it is single-use whatever the handler does: two requests sending it at
// once never both reach a handler, and the second, refused as a replay, released nothing. A 5xx,
// and a success, keep the record, since what the handler did before them may have taken effect. A
// release that fails is an Error record, and the proof stays spent, which refuses nothing a fresh
// proof would not be admitted for.
func (m *BearerToken) RecordDPoPProof() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proof, ok := reqctx.DPoPProofFrom(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if m.proofs.Replays == nil {
				m.refusals.internalError(w, r, errs.New("no DPoP replay store is configured for this surface"), "")
				return
			}
			if m.proofs.now().After(proof.IssuedAtWindowEnds()) {
				jwtToken, _ := reqctx.BearerTokenFrom(r.Context())
				slog.WarnContext(r.Context(), "dpop proof refused at a resource",
					"reason", dpop.ErrInvalidProof.Error()+": its iat window ended before it was recorded",
					"client_id", jwtToken.StringClaim("client_id"))
				m.refusals.invalidDPoPProof(w, r)
				return
			}
			recorded, err := m.proofs.Replays.RecordDPoPProof(r.Context(), nil, proof.ReplayKey(), proof.IssuedAtWindowEnds().Add(dpop.ReplayRecordGrace))
			if err != nil {
				m.refusals.internalError(w, r, errs.Wrap(err, "unable to record the DPoP proof in the replay store"), "")
				return
			}
			if !recorded {
				jwtToken, _ := reqctx.BearerTokenFrom(r.Context())
				slog.WarnContext(r.Context(), "dpop proof refused at a resource",
					"reason", dpop.ErrInvalidProof.Error()+": it has been used before",
					"client_id", jwtToken.StringClaim("client_id"))
				m.refusals.invalidDPoPProof(w, r)
				return
			}
			next.ServeHTTP(&dpopRefusalReleaser{ResponseWriter: w, release: func() {
				if err := m.proofs.Replays.ReleaseDPoPProof(r.Context(), nil, proof.ReplayKey()); err != nil {
					slog.ErrorContext(r.Context(), "unable to release the dpop proof of a refused request", "error", err)
				}
			}}, r)
		})
	}
}

// dpopRefusalReleaser is the writer RecordDPoPProof hands the handler: the first final status it
// writes, explicitly or by a first Write, decides once whether the proof's record is released, and a
// 4xx releases it before the status is passed on.
type dpopRefusalReleaser struct {
	http.ResponseWriter
	release func()
	decided bool
}

func (w *dpopRefusalReleaser) WriteHeader(code int) {
	// A 1xx is informational, sent ahead of the final status, which can still be anything.
	if !w.decided && code >= http.StatusOK {
		w.decided = true
		if code >= http.StatusBadRequest && code < http.StatusInternalServerError {
			w.release()
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *dpopRefusalReleaser) Write(b []byte) (int, error) {
	// A Write before any WriteHeader writes 200.
	w.decided = true
	return w.ResponseWriter.Write(b)
}

// Unwrap answers the writer beneath, for http.ResponseController.
func (w *dpopRefusalReleaser) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (p ResourceProofs) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// credentialsFromHeader reads the Authorization header's credentials when its scheme is Bearer
// (RFC 6750 section 2.1, `"Bearer" 1*SP b64token`) or DPoP (RFC 9449 section 7.1, `"DPoP" 1*SP
// token68`), and reports whether the header presents a token at all. The scheme alone, or followed
// by spaces only, presents an empty one, which the caller refuses as invalid rather than treating
// as absent. Any other scheme, and a header that is absent, present nothing.
func credentialsFromHeader(authorization string) (schemes, string, bool) {
	scheme, rest, _ := strings.Cut(authorization, " ")
	switch {
	case strings.EqualFold(scheme, bearerScheme):
		return schemeBearer, strings.TrimLeft(rest, " "), true
	case strings.EqualFold(scheme, dpopScheme):
		return schemeDPoP, strings.TrimLeft(rest, " "), true
	}
	return 0, "", false
}

// schemesPresented is every scheme the request presents a token with: each Authorization field
// line's, and Bearer for a token in the form body. It decides which challenges carry a malformed
// request's error, so a request that used both is told in both (RFC 9449 section 7.2).
func schemesPresented(authorizations []string, inBody bool) schemes {
	var used schemes
	for _, authorization := range authorizations {
		scheme, _, _ := credentialsFromHeader(authorization)
		used |= scheme
	}
	if inBody {
		used |= schemeBearer
	}
	return used
}

// bearerTokenFromForm reads RFC 6750 section 2.2's access_token body parameter, which applies to a
// POST whose body is application/x-www-form-urlencoded, and reports whether the parameter was
// present, empty included, and whether it was sent more than once. The body alone is read, never
// the query: r.PostForm, not r.Form, since a token in the URL is section 2.3's method, which this
// server does not support. A body that does not parse is returned as the error and nothing else,
// never as the pairs ParseForm managed to read.
//
// Whether the body is a form is decided on the media type alone, normalized exactly as
// mime.ParseMediaType normalizes it before net/http's ParseForm compares it: lowercased with
// strings.ToLower, then trimmed. A media type is case-insensitive (RFC 9110 section 8.3.1), and a
// case-sensitive prefix match read APPLICATION/X-WWW-FORM-URLENCODED as no form while ParseForm read
// its body, so a second token sent there beside the header was never seen and the header was
// admitted (#435). strings.EqualFold is not the same rule: strings.ToLower folds a dotted capital I
// to i and EqualFold does not, and ParseForm reads that body too. The parameters are left to
// ParseForm, so a form whose parameters do not parse is refused as a body that does not parse rather
// than passed over: ParseForm returns that error, having read the body or not.
func bearerTokenFromForm(r *http.Request) (token string, present bool, repeated bool, err error) {
	mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if r.Method != http.MethodPost || strings.TrimSpace(strings.ToLower(mediaType)) != formMediaType {
		return "", false, false, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", false, false, err
	}
	values := r.PostForm["access_token"]
	if len(values) == 0 {
		return "", false, false, nil
	}
	return values[0], true, len(values) > 1, nil
}

// isAccessTokenForAuthServer admits a validly signed token as a bearer credential only when it
// is an access token issued for this server's own resource. The signature proves this server
// issued it, not which kind of token it is: refresh tokens and ID tokens are signed with the same
// key, and before this check a refresh token whose scope carried a route's permission passed
// that route's scope check (#401).
//
// typ must be "Bearer", which every access token carries, user or client; refresh tokens carry
// "Refresh" or "Offline" and ID tokens no typ at all. aud must contain authserver: RFC 7519
// section 4.1.3 requires a principal to reject a JWT whose aud does not identify it, and issuance
// names authserver in aud for every authserver:* scope and every claim scope, so every token a
// bearer-guarded route serves already does. GetAudience is the parser's own StringOrURI reading:
// a single string, or an array of strings, which arrives from a parsed token as []interface{}.
//
// A refused token is answered exactly as a token that does not parse, which is what #401 asks for:
// 401 invalid_token since #435, where both used to read as a missing token.
func isAccessTokenForAuthServer(ctx context.Context, token *oauth.JwtToken) bool {
	if typ := token.StringClaim("typ"); typ != issuance.TokenTypeBearer.String() {
		slog.WarnContext(ctx, "rejecting bearer token: not an access token", "typ", typ)
		return false
	}
	audiences, err := token.Claims.GetAudience()
	if err != nil {
		slog.WarnContext(ctx, "rejecting bearer token: aud is malformed", "error", err)
		return false
	}
	if !slices.Contains(audiences, builtin.AuthServerResourceIdentifier) {
		slog.WarnContext(ctx, "rejecting bearer token: aud does not name this server's resource")
		return false
	}
	return true
}
