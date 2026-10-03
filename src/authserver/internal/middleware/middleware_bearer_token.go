package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
)

// tokenParser is the one thing this middleware needs of the auth server's token parser:
// turning the presented string into a validated token. signingkeys.TokenParser satisfies
// it. Declared as the shape used rather than the whole parser, which is what the
// neighbouring ports in this package already do (#385).
type tokenParser interface {
	DecodeAndValidateTokenString(ctx context.Context, token string, withExpirationCheck bool) (*oauth.JwtToken, error)
}

// MiddlewareBearerToken is the bearer guard set for one surface: the parse guard, the scope guards,
// the user-bound guard and the session guard, answering every refusal through that surface's
// writer. routes.go builds one for the admin and account APIs and one for /userinfo, so which body a
// refusal carries is fixed at construction and never inferred from the request (#435).
type MiddlewareBearerToken struct {
	tokenParser tokenParser
	refusals    bearerRefusals
}

// NewMiddlewareBearerTokenForAPI builds the guard set for /api/v1/*, whose refusals answer the
// admin and account API's {error_code, error_description} envelope.
func NewMiddlewareBearerTokenForAPI(tokenParser tokenParser) *MiddlewareBearerToken {
	return &MiddlewareBearerToken{tokenParser: tokenParser, refusals: apiBearerRefusals{}}
}

// NewMiddlewareBearerTokenForUserInfo builds the guard set for /userinfo, whose refusals answer
// {error, error_description} through jsonWriter, the writer the userinfo handler answers through.
func NewMiddlewareBearerTokenForUserInfo(tokenParser tokenParser, jsonWriter jsonErrorWriter) *MiddlewareBearerToken {
	return &MiddlewareBearerToken{tokenParser: tokenParser, refusals: userinfoBearerRefusals{jsonWriter: jsonWriter}}
}

// bearerScheme is the auth-scheme RFC 6750 section 2.1 defines. It is compared case-insensitively:
// that section's `credentials = "Bearer" 1*SP b64token` is ABNF, whose quoted strings are case
// insensitive (RFC 5234 section 2.3), and RFC 9110 section 11.1 calls the auth-scheme a
// "case-insensitive token". Before #435 only "Bearer " matched, so a client sending "bearer" was
// refused as if it had sent nothing, where section 2.1 says resource servers MUST support the method.
const bearerScheme = "Bearer"

// invalidTokenDescription is what a presented token that is refused is told, whatever the reason.
// One sentence for every reason, since the reasons are the signature, the expiry, the token's kind
// and its audience, and naming which would tell a presenter which of those it got right.
const invalidTokenDescription = "The access token is invalid."

// formMediaType is the media type RFC 6750 section 2.2's body method requires, lowercase, which is
// how mime.ParseMediaType returns every spelling of it.
const formMediaType = "application/x-www-form-urlencoded"

// JwtAuthorizationHeaderToContext is the one place that decides whether a bearer credential was
// presented, and it decides it for every guard behind it. Two methods carry one, RFC 6750 section
// 2.1's Authorization header and, for a POST with a form-encoded body, section 2.2's access_token
// body parameter, which OIDC Core 1.0 section 5.3.1 lets the UserInfo endpoint accept. A token in
// the URL query is section 2.3's method, which this server does not support, so it is no
// credential at all.
//
// What each request is answered, and why (#435):
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
//     request invalid_request. Before #435 the header silently won.
//   - A presented token that is empty, fails validation, or is not an access token for this server
//     (isAccessTokenForAuthServer, #401) answers 401 invalid_token here and now. Every route group
//     mounting this guard requires a token, so none is handed a refused one as though it were
//     optional, and a refused token no longer reads as a missing one.
//   - No credential, which includes another scheme such as Basic, passes through with nothing in the
//     context; the scope guard behind it answers the realm-only challenge.
//
// A validated token is stored with reqctx.WithBearerToken, which every guard behind this reads.
func (m *MiddlewareBearerToken) JwtAuthorizationHeaderToContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headerToken, inHeader := bearerTokenFromHeader(r.Header.Get("Authorization"))
			bodyToken, inBody, repeated, err := bearerTokenFromForm(r)

			if err != nil {
				slog.WarnContext(r.Context(), "rejecting bearer request: the request body could not be parsed", "error", err)
				m.refusals.invalidRequest(w, r, "The request body could not be parsed.")
				return
			}
			if len(r.Header.Values("Authorization")) > 1 {
				slog.WarnContext(r.Context(), "rejecting bearer request: the authorization header was repeated")
				m.refusals.invalidRequest(w, r, "The Authorization header must be sent once.")
				return
			}
			if repeated {
				slog.WarnContext(r.Context(), "rejecting bearer request: the access_token parameter was repeated")
				m.refusals.invalidRequest(w, r, "The access_token parameter must be sent once.")
				return
			}
			if inHeader && inBody {
				slog.WarnContext(r.Context(), "rejecting bearer request: the token was sent in the header and in the body")
				m.refusals.invalidRequest(w, r, "The access token must be sent by one method only.")
				return
			}
			if !inHeader && !inBody {
				next.ServeHTTP(w, r)
				return
			}

			tokenStr := headerToken
			if inBody {
				tokenStr = bodyToken
			}
			if tokenStr == "" {
				slog.WarnContext(r.Context(), "rejecting bearer token: the token is empty")
				m.refusals.invalidToken(w, r, invalidTokenDescription)
				return
			}
			token, err := m.tokenParser.DecodeAndValidateTokenString(r.Context(), tokenStr, true)
			if err != nil {
				slog.WarnContext(r.Context(), "rejecting bearer token: the token did not validate", "error", err)
				m.refusals.invalidToken(w, r, invalidTokenDescription)
				return
			}
			if !isAccessTokenForAuthServer(r.Context(), token) {
				m.refusals.invalidToken(w, r, invalidTokenDescription)
				return
			}

			next.ServeHTTP(w, r.WithContext(reqctx.WithBearerToken(r.Context(), *token)))
		})
	}
}

// bearerTokenFromHeader reads RFC 6750 section 2.1's credentials, `"Bearer" 1*SP b64token`, and
// reports whether the header presents a Bearer credential at all. The scheme alone, or followed by
// spaces only, presents an empty one, which the caller refuses as invalid rather than treating as
// absent. Any other scheme, and a header that is absent, present nothing.
func bearerTokenFromHeader(authorization string) (string, bool) {
	scheme, rest, _ := strings.Cut(authorization, " ")
	if !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	return strings.TrimLeft(rest, " "), true
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
	if typ := token.GetStringClaim("typ"); typ != issuance.TokenTypeBearer.String() {
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
