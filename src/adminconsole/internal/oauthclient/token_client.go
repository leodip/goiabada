package oauthclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

// NewAuthServerHTTPClient builds the one client for every call this process makes to the
// auth server's OAuth endpoints: the JWKS fetch and the token grants. Bare &http.Client{}
// literals left every one of them with no bound on the wait for response headers or the
// body, so a peer that accepted the connection and never answered held the handler open
// indefinitely.
//
// For one of them this is the only bound there is. The token grants build their own
// deadline, but the JWKS fetch deliberately keeps the request's own context -- it is an
// idempotent read -- and a browser context carries no deadline. So the timeout here is what
// bounds it (#338).
func NewAuthServerHTTPClient() *http.Client {
	return &http.Client{Timeout: TokenExchangeTimeout}
}

// TokenEndpointURL is the auth server's token endpoint under baseURL. The base URL comes from
// configuration, and an operator writing it with a trailing slash is a matter of when rather
// than whether.
func TokenEndpointURL(baseURL string) string {
	return strings.TrimSuffix(baseURL, "/") + "/auth/token"
}

// TokenClient is the admin console's client of the auth server's token endpoint. It is built
// once, with the token URL, the client identifier, the secret and the HTTP client, so no
// caller names any of them per request, and it answers every refusal of the endpoint as one
// *TokenEndpointError (#441).
type TokenClient struct {
	tokenURL     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// NewTokenClient builds the token client. A nil HTTP client gets NewAuthServerHTTPClient's,
// so the deadline holds however the composition root wires this; the composition root passes
// its own so every call to the auth server shares one configured client (#338).
func NewTokenClient(tokenURL, clientID, clientSecret string, httpClient *http.Client) *TokenClient {
	if httpClient == nil {
		httpClient = NewAuthServerHTTPClient()
	}
	return &TokenClient{
		tokenURL:     tokenURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   httpClient,
	}
}

// TokenEndpointError is the token endpoint answering anything but 200: the status, and the
// answer's error and error_description (RFC 6749 section 5.2), each conformed to Appendix A's
// error_description characters and bounded at 512 bytes, empty when the answer did not carry
// it as a string. The body itself is never kept: what this error says is logged, and the body
// is up to MaxTokenResponseBytes of the peer's text (#441 decision 3).
type TokenEndpointError struct {
	StatusCode       int
	ErrorCode        string
	ErrorDescription string
}

func (e *TokenEndpointError) Error() string {
	message := fmt.Sprintf("the auth server's token endpoint answered %d", e.StatusCode)
	switch {
	case e.ErrorCode != "" && e.ErrorDescription != "":
		return message + " (" + e.ErrorCode + ": " + e.ErrorDescription + ")"
	case e.ErrorCode != "":
		return message + " (" + e.ErrorCode + ")"
	case e.ErrorDescription != "":
		return message + " (" + e.ErrorDescription + ")"
	}
	return message
}

// newTokenEndpointError reads the RFC 6749 error object out of a refusal's body. A body that
// is not one -- a proxy's page, a member that is not a string -- leaves both fields empty, and
// the refusal is the status alone.
func newTokenEndpointError(statusCode int, body []byte) error {
	var answer struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		answer.Error, answer.ErrorDescription = "", ""
	}
	return errs.WithStack(&TokenEndpointError{
		StatusCode:       statusCode,
		ErrorCode:        oauth.ConformErrorDescription(answer.Error),
		ErrorDescription: oauth.ConformErrorDescription(answer.ErrorDescription),
	})
}

// ExchangeCode redeems an authorization code: the sign-in's grant. It is transport only; the
// caller checks the answer through the parser.
//
// The browser may be gone; the auth server is not. authorization_code is single use, so the
// server has already burned the code by the time it answers, and abandoning the read loses the
// only copy of what it issued. So the request runs on ctx detached from its cancellation:
// WithoutCancel keeps the caller's values, so request_id still reaches every record, where
// context.Background() would drop it, and TokenExchangeTimeout is what bounds the call instead.
// The detachment covers this call and stops there: what the caller does with the answer runs on
// its own context (#338).
func (c *TokenClient) ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (*oauth.TokenResponse, error) {
	// Debug: one record on every administrator sign-in. Per-request tracing is not Info, which is
	// for lifecycle and configuration, and the one reader who needs it is debugging the exchange
	// against an address they suspect (#320).
	slog.DebugContext(ctx, "exchanging the code for tokens", "token_url", c.tokenURL)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code_verifier", codeVerifier)

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), TokenExchangeTimeout)
	defer cancel()

	return c.post(ctx, form)
}

// Refresh sends the refresh grant for refreshToken: the JWT middleware's, when the stored access
// token is due. It is transport only; the caller checks the answer through the parser and writes
// the session (#441 decision 2).
//
// refresh_token is single use: the auth server revokes the old token as part of issuing the new
// one, so abandoning the read loses the only copy of what it issued, and the administrator would
// hold a revoked token and be signed out on their next page load. So the request runs on ctx
// detached from its cancellation, under TokenExchangeTimeout, as ExchangeCode's does.
func (c *TokenClient) Refresh(ctx context.Context, refreshToken string) (*oauth.TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), TokenExchangeTimeout)
	defer cancel()

	tokenResponse, err := c.post(ctx, form)
	if err != nil {
		return nil, err
	}

	// RFC 6749 section 6: "The authorization server MAY issue a new refresh token, in which case
	// the client MUST discard the old refresh token". One that issues none leaves the old one the
	// client's, and returning the answer as it came would have the caller store it away as empty
	// and sign the administrator out at the next refresh. golang.org/x/oauth2 keeps it the same
	// way (#427).
	if tokenResponse.RefreshToken == "" {
		tokenResponse.RefreshToken = refreshToken
	}
	return tokenResponse, nil
}

// ClientCredentials sends the client_credentials grant for scope: the bearer SessionTokenSource
// caches for the browser-session endpoint. It is transport only, like the other two grants; the
// cache decides what to do with the answer.
//
// Unlike them it keeps the caller's cancellation. client_credentials spends nothing: the auth
// server issues a token and burns no grant, so a caller that goes away abandons nothing a later
// request cannot ask for again, and the session lookup behind it ends with the page load that
// asked for it. TokenExchangeTimeout still bounds it, since a browser context carries no
// deadline (#441 decision 2).
//
// A refusal is the shared *TokenEndpointError, named with the client it was refused for and, for
// the two codes that mean the client is not provisioned for this grant, what to fix (#441
// decision 3).
func (c *TokenClient) ClientCredentials(ctx context.Context, scope string) (*oauth.TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("scope", scope)

	ctx, cancel := context.WithTimeout(ctx, TokenExchangeTimeout)
	defer cancel()

	tokenResponse, err := c.post(ctx, form)
	if err != nil {
		var refusal *TokenEndpointError
		if errors.As(err, &refusal) {
			return nil, errs.Errorf("%w%s", err, c.clientCredentialsRemedy(refusal.ErrorCode, scope))
		}
		return nil, err
	}
	return tokenResponse, nil
}

// clientCredentialsRemedy is what a client-credentials refusal adds to the shared message: the
// client that was refused and, where the refusal says the client is not provisioned for this,
// the two things it needs.
//
// The reason it is worth more than a status code: a deployment this fails on cannot be repaired
// through the admin console, because obtaining this token is what every admin console page
// needs, so an administrator locked out by it has no page to fix it from. The route back in is
// direct SQL, which is not discoverable from "answered 400" (#266).
//
// How a deployment reaches it, now that the client this authenticates as is the constant the
// seeder writes rather than configuration (#285): both things migration 000035 provisions on
// that client are editable from the admin console afterwards. An administrator can turn the
// client credentials flow off on `admin-console-client`, or take the browser-sessions
// permission away from it, and the next token request is refused. The two codes below are the
// two ways the endpoint says which one happened: unauthorized_client when client credentials
// is off, invalid_scope when the permission is gone.
//
// The remedy sentence is attached to exactly those two codes rather than to every refusal,
// because a server_error or a gateway's 502 is not a provisioning fault and telling an operator
// to grant a permission would send them to the wrong place. The code it is keyed on is the
// conformed one, so a code the peer dressed up with a forbidden character does not earn it.
func (c *TokenClient) clientCredentialsRemedy(code, scope string) string {
	// %q rather than %s: the identifier is a constructor parameter, so it is only a compile time
	// constant by convention, and a stray control character in it must not forge a line in the
	// log this lands in.
	remedy := fmt.Sprintf(" for client_id %q", c.clientID)
	if code == "unauthorized_client" || code == "invalid_scope" {
		remedy += fmt.Sprintf(", which needs the client credentials flow enabled and the"+
			" %s permission granted", scope)
	}
	return remedy
}

// post sends one grant's form to the token endpoint and decodes the answer.
func (c *TokenClient) post(ctx context.Context, form url.Values) (*oauth.TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errs.Wrap(err, "error creating request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Wrap(err, "error sending request")
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded: the peer is the auth server, but a peer that answers with an endless body
	// would otherwise be read into memory until the process dies. An answer over the ceiling
	// is refused rather than cut, so it reaches the caller as boundedread.ErrResponseTooLarge
	// rather than as a parse failure indistinguishable from a malformed body (#386 decision 4).
	body, err := boundedread.Read(resp.Body, MaxTokenResponseBytes)
	if err != nil {
		return nil, errs.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, newTokenEndpointError(resp.StatusCode, body)
	}

	var tokenResponse oauth.TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, errs.Wrap(err, "error parsing response")
	}
	return &tokenResponse, nil
}
