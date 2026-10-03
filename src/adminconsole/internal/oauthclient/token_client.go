package oauthclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/core/boundedread"
	"github.com/leodip/goiabada/core/customerrors"
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
		ErrorCode:        customerrors.ConformErrorDescription(answer.Error),
		ErrorDescription: customerrors.ConformErrorDescription(answer.ErrorDescription),
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

// post sends one grant's form to the token endpoint and decodes the answer.
func (c *TokenClient) post(ctx context.Context, form url.Values) (*oauth.TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, errs.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, errs.Errorf("error sending request: %v", err)
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
		return nil, errs.Errorf("error parsing response: %v", err)
	}
	return &tokenResponse, nil
}
