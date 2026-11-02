package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/leodip/goiabada/authserver/internal/clientauth"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/introspectionmetrics"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/liveness"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// introspectDatabase is what the introspection endpoint reads: the calling client, the state the two
// liveness checks read, and the caller's introspection resources.
type introspectDatabase interface {
	liveness.Database
	liveness.RefreshDatabase
	GetClientIntrospectionResourcesByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.ClientIntrospectionResource, error)
	GetResourcesByIds(ctx context.Context, tx *sql.Tx, resourceIds []int64) ([]record.Resource, error)
}

// introspectRequestParameters are every form parameter the introspection endpoint reads, and so every
// one whose copies must agree (RFC 6749 section 3.2). token_type_hint is not among them: it is never
// read (decision 13), so a repeated one is ignored with it.
var introspectRequestParameters = []string{"token", "client_id", "client_secret"}

// introspection is an answer of the endpoint, RFC 7662 section 2.2's members. An inactive token is
// answered with active alone, which says nothing of why; an active one with the members its kind
// carries, each read from the token.
type introspection struct {
	Active    bool        `json:"active"`
	Scope     string      `json:"scope,omitempty"`
	ClientId  string      `json:"client_id,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  interface{} `json:"aud,omitempty"`
	Issuer    string      `json:"iss,omitempty"`
	ExpiresAt int64       `json:"exp,omitempty"`
	IssuedAt  int64       `json:"iat,omitempty"`
	NotBefore int64       `json:"nbf,omitempty"`
	Jti       string      `json:"jti,omitempty"`
	TokenType string      `json:"token_type,omitempty"`
}

// HandleIntrospectPost is the token introspection endpoint, RFC 7662 (#676 decisions 5, 7, 9 and 13).
// An API, calling as a confidential client, asks whether a token is active.
//
// An access token is active when the one access-token check the auth server's own endpoints apply
// finds it live, and its aud names a resource on the caller's introspection resources (decision 5),
// so a client may see only the tokens of the APIs an administrator listed for it. A refresh token is
// active only to the client it was issued to, when the refresh grant's own check finds it live
// (decision 7) and its issuing flow is enabled; introspecting it spends nothing, and a rotated one
// answered here is no replay. Every
// other token, and every token the caller may not see, is answered {"active": false} and nothing
// else (RFC 7662 section 2.2).
//
// The client is authenticated before anything else, as at the token endpoint, and a public client is
// refused, since a caller MUST authenticate (RFC 7662 section 4). The token parser refuses a
// malformed or non-RS256 token before it reads a key, and checks any other against the current key
// and, when that signature fails, each stored one. token_type_hint is never read: the token
// says what it is, an access token by its at+jwt header and a refresh token by its typ claim.
//
// A fault reading the database or the signing keys is 500, never {"active": false}, which would
// report a fault as a dead token. Every answer carries Cache-Control: no-store, so no cache keeps one
// past the token's expiry (RFC 7662 section 4). Introspection changes nothing, so it writes no audit
// event (decision 11).
func HandleIntrospectPost(
	jsonWriter JSONWriter,
	database introspectDatabase,
	tokenParser TokenParser,
	dataCipher *encryption.DataCipher,
	introspectionMetrics *introspectionmetrics.Recorder,
) http.HandlerFunc {
	endpoint := introspectionEndpoint{
		jsonWriter:  jsonWriter,
		database:    database,
		tokenParser: tokenParser,
		clients:     clientauth.NewAuthenticator(database, dataCipher),
		metrics:     introspectionMetrics,
	}
	return endpoint.serve
}

// introspectionEndpoint is the introspection endpoint's dependencies, so each step of a request is a
// method.
type introspectionEndpoint struct {
	jsonWriter  JSONWriter
	database    introspectDatabase
	tokenParser TokenParser
	clients     *clientauth.Authenticator
	metrics     *introspectionmetrics.Recorder
}

func (e introspectionEndpoint) serve(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// A body that cannot be parsed is the client's malformed request, as at the token endpoint.
	if err := r.ParseForm(); err != nil {
		e.refuse(w, r, protocolvalidation.UnparseableRequest())
		return
	}
	if err := protocolvalidation.ValidateNoRepeatedParameters(r.PostForm, introspectRequestParameters); err != nil {
		e.refuse(w, r, err)
		return
	}
	clientIdentifier, clientSecret, err := extractClientCredentials(r)
	if err != nil {
		// Basic credentials that cannot be read or name no client are an invalid_client naming no
		// client, logged as every one is.
		atIntrospectionEndpoint.logClientAuthenticationRefusal(r, "", err)
		e.refuse(w, r, err)
		return
	}

	client, err := e.clients.AuthenticateConfidential(ctx, clientIdentifier, clientSecret)
	if err != nil {
		var refusal *oauth.ErrorDetail
		if !errors.As(err, &refusal) {
			e.fault(w, r, err)
			return
		}
		atIntrospectionEndpoint.logClientAuthenticationRefusal(r, clientIdentifier, err)
		e.refuse(w, r, err)
		return
	}

	presented := r.PostForm.Get("token")
	if presented == "" {
		e.refuse(w, r, oauth.NewErrorDetailWithHTTPStatus("invalid_request",
			"Missing required token parameter.", http.StatusBadRequest))
		return
	}

	settings, ok := reqctx.SettingsFrom(ctx)
	if !ok {
		e.fault(w, r, reqctx.ErrNoSettings)
		return
	}

	token, err := e.tokenParser.DecodeAndValidateTokenString(ctx, presented, true)
	if err != nil {
		// A token the parser refused, unsigned by any key, malformed or expired, is inactive. A
		// token it could not check because the keys could not be read says nothing about the token
		// (#680).
		if errors.Is(err, signingkeys.ErrTokenRefused) {
			e.inactive(w, r)
			return
		}
		e.fault(w, r, errs.Wrap(err, "unable to check the token to introspect"))
		return
	}

	now := time.Now().UTC()
	verdict, err := liveness.AccessToken(ctx, e.database, *token, settings, now)
	if err != nil {
		e.fault(w, r, err)
		return
	}
	if verdict.Refusal != liveness.NotAnAccessTokenHeader {
		e.introspectAccessToken(w, r, client, *token, verdict)
		return
	}

	switch token.StringClaim("typ") {
	case issuance.TokenTypeRefresh.String(), issuance.TokenTypeOffline.String():
		e.introspectRefreshToken(w, r, client, *token, settings, now)
	default:
		// An ID token, or an access token issued before #676, which carries the header typ JWT
		// (decision 4): neither is active.
		e.inactive(w, r)
	}
}

// introspectAccessToken answers an access token the access-token check has judged: active when it is
// live and its aud names a resource on the caller's list.
func (e introspectionEndpoint) introspectAccessToken(w http.ResponseWriter, r *http.Request, client *record.Client,
	token oauth.JwtToken, verdict liveness.Verdict) {

	if !verdict.Live() {
		e.inactive(w, r)
		return
	}
	listed, err := e.listsAnAudience(r.Context(), client, token)
	if err != nil {
		e.fault(w, r, err)
		return
	}
	if !listed {
		e.inactive(w, r)
		return
	}

	// The token's own members, not narrowed to the caller's resources (decision 13): the API holds
	// the token and can read every claim in it anyway.
	e.active(w, r, introspection{
		Active:    true,
		Scope:     token.StringClaim("scope"),
		ClientId:  token.StringClaim("client_id"),
		Subject:   token.StringClaim("sub"),
		Audience:  token.Claims["aud"],
		Issuer:    token.StringClaim("iss"),
		ExpiresAt: numericDateClaim(token, "exp"),
		IssuedAt:  numericDateClaim(token, "iat"),
		NotBefore: numericDateClaim(token, "nbf"),
		Jti:       token.StringClaim("jti"),
		TokenType: "Bearer",
	})
}

// listsAnAudience reports whether the token's aud names a resource on the client's introspection
// resources (decision 5). A resource identifier is compared exactly, as aud's StringOrURI values are
// (RFC 7519 section 4.1.3).
func (e introspectionEndpoint) listsAnAudience(ctx context.Context, client *record.Client, token oauth.JwtToken) (bool, error) {
	links, err := e.database.GetClientIntrospectionResourcesByClientId(ctx, nil, client.Id)
	if err != nil {
		return false, errs.Wrap(err, "failed to load the caller's introspection resources")
	}
	if len(links) == 0 {
		return false, nil
	}
	resourceIds := make([]int64, 0, len(links))
	for _, link := range links {
		resourceIds = append(resourceIds, link.ResourceId)
	}
	resources, err := e.database.GetResourcesByIds(ctx, nil, resourceIds)
	if err != nil {
		return false, errs.Wrap(err, "failed to load the caller's introspection resources")
	}

	audiences := tokenAudiences(token)
	for _, resource := range resources {
		if slices.Contains(audiences, resource.ResourceIdentifier) {
			return true, nil
		}
	}
	return false, nil
}

// introspectRefreshToken answers a refresh token: active only to the client it was issued to, and
// only when the refresh grant's own check finds it live (decision 7) and the flow that issued it is
// still enabled for the client, which the grant also requires (#250). Active says the token is
// live, not that a refresh would succeed: the grant re-checks consent, permissions and the client's
// scope allowances against the scope a refresh asks for, when it is made. Another client's token is
// inactive before anything about its grant is read, so the answer tells a caller nothing of a grant
// it does not own. The check reads no client: the caller is the token's own, which client
// authentication found to exist and be enabled.
func (e introspectionEndpoint) introspectRefreshToken(w http.ResponseWriter, r *http.Request, client *record.Client,
	token oauth.JwtToken, settings *record.Settings, now time.Time) {

	ctx := r.Context()
	stored, err := liveness.FindRefreshToken(ctx, e.database, token)
	if err != nil {
		e.fault(w, r, err)
		return
	}
	if stored == nil || stored.ClientId != client.Id {
		e.inactive(w, r)
		return
	}
	refusal, err := liveness.RefreshToken(ctx, e.database, stored, token, settings, now)
	if err != nil {
		e.fault(w, r, err)
		return
	}
	if refusal != liveness.RefreshLive {
		e.inactive(w, r)
		return
	}
	if !client.IsRefreshIssuingFlowEnabled(stored.IsROPC, settings.ResourceOwnerPasswordCredentialsEnabled) {
		e.inactive(w, r)
		return
	}

	// No token_type, since RFC 6749 section 5.1's types name access tokens, and no aud, since a
	// refresh token is for no resource. Its exp is already the earlier of its expiry and its maximum
	// lifetime: issuance writes it so.
	e.active(w, r, introspection{
		Active:    true,
		Scope:     token.StringClaim("scope"),
		ClientId:  client.ClientIdentifier,
		Subject:   token.StringClaim("sub"),
		Issuer:    token.StringClaim("iss"),
		ExpiresAt: numericDateClaim(token, "exp"),
		IssuedAt:  numericDateClaim(token, "iat"),
		Jti:       token.StringClaim("jti"),
	})
}

// tokenAudiences reads aud, a single string or an array of them (RFC 7519 section 4.1.3).
func tokenAudiences(token oauth.JwtToken) []string {
	switch aud := token.Claims["aud"].(type) {
	case string:
		return []string{aud}
	case []interface{}:
		audiences := make([]string, 0, len(aud))
		for _, value := range aud {
			if s, ok := value.(string); ok {
				audiences = append(audiences, s)
			}
		}
		return audiences
	}
	return nil
}

// numericDateClaim reads a NumericDate claim as seconds, or 0, which the answer omits, when the token
// carries none.
func numericDateClaim(token oauth.JwtToken, name string) int64 {
	seconds, _ := token.Claims[name].(float64)
	return int64(seconds)
}

// active answers an active token with its members.
func (e introspectionEndpoint) active(w http.ResponseWriter, r *http.Request, answer introspection) {
	e.metrics.Count(introspectionmetrics.Active)
	e.answer(w, r, answer)
}

// inactive answers {"active": false}, saying nothing of why (RFC 7662 section 2.2).
func (e introspectionEndpoint) inactive(w http.ResponseWriter, r *http.Request) {
	e.metrics.Count(introspectionmetrics.Inactive)
	e.answer(w, r, introspection{})
}

// HandleIntrospectOtherMethods answers every method at /auth/introspect but POST, which
// HandleIntrospectPost answers: 405 with Allow: POST and an empty body, as the router answers a path
// registered for other methods, so no token reaches a URL (RFC 7662 section 4 MAY disallow GET). It
// is registered for the endpoint rather than left to the router because every introspection answer
// carries Cache-Control: no-store, the refusal included (#676 decision 13). It counts nothing: no
// token reached the endpoint.
func HandleIntrospectOtherMethods() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", http.MethodPost)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// answer writes an introspection, which no cache may keep (RFC 7662 section 4), with the pair RFC
// 6749 section 5.1 writes on a response carrying token information.
func (e introspectionEndpoint) answer(w http.ResponseWriter, r *http.Request, answer introspection) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	e.jsonWriter.EncodeJSON(w, r, answer)
}

// refuse answers a request the client got wrong with err, RFC 6749 section 5.2's error response, not
// stored, as the JSON writer writes every error.
func (e introspectionEndpoint) refuse(w http.ResponseWriter, r *http.Request, err error) {
	e.metrics.Count(introspectionmetrics.Refused)
	e.jsonWriter.JSONError(w, r, err)
}

// fault answers a request the server could not decide.
func (e introspectionEndpoint) fault(w http.ResponseWriter, r *http.Request, err error) {
	answerIntrospectionFault(w, r, e.jsonWriter, e.metrics, err)
}

// answerIntrospectionFault answers a fault at the introspection endpoint, the handler's own or one met
// before it: counted as error and answered 500 server_error, which the JSON writer logs once at Error
// with the request id, never {"active": false} (decision 13).
func answerIntrospectionFault(w http.ResponseWriter, r *http.Request, jsonWriter JSONWriter,
	introspectionMetrics *introspectionmetrics.Recorder, err error) {

	introspectionMetrics.Count(introspectionmetrics.Error)
	jsonWriter.JSONError(w, r, err)
}

// IntrospectionFaultWriter is the introspection endpoint's error writer for the faults met before its
// handler runs, the settings or the session failing to load or a panic, on the branch the endpoint
// alone is registered on: each is answered and counted as the handler answers its own.
type IntrospectionFaultWriter struct {
	jsonWriter JSONWriter
	metrics    *introspectionmetrics.Recorder
}

// IntrospectionFaults returns the introspection branch's fault writer, answering through jsonWriter.
func IntrospectionFaults(jsonWriter JSONWriter, introspectionMetrics *introspectionmetrics.Recorder) IntrospectionFaultWriter {
	return IntrospectionFaultWriter{jsonWriter: jsonWriter, metrics: introspectionMetrics}
}

// JSONError answers err as a fault of the introspection endpoint.
func (w IntrospectionFaultWriter) JSONError(rw http.ResponseWriter, r *http.Request, err error) {
	answerIntrospectionFault(rw, r, w.jsonWriter, w.metrics, err)
}
