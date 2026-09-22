package oauthclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/boundedread"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
)

type TokenExchanger struct {
	httpClient *http.Client
}

// NewTokenExchanger creates the client half of the authorization-code exchange. A nil
// client gets one carrying TokenExchangeTimeout, so the deadline holds however the
// composition root wires this; the caller passes its own so all three calls the admin
// console makes to the auth server share one configured client (#338).
func NewTokenExchanger(httpClient *http.Client) *TokenExchanger {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: TokenExchangeTimeout}
	}
	return &TokenExchanger{httpClient: httpClient}
}

func (te *TokenExchanger) ExchangeCodeForTokens(
	ctx context.Context,
	code, redirectURI, clientId, clientSecret, codeVerifier, tokenEndpoint string,
) (*oauth.TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientId)
	data.Set("client_secret", clientSecret) // Add client secret to form data
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, errs.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := te.httpClient.Do(req)
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
		// %w rather than %v, which is what the line said before: the message is byte for
		// byte the same and the sentinel stays reachable through errors.Is.
		return nil, errs.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errs.Errorf("error response from server: %s", body)
	}

	var tokenResponse oauth.TokenResponse
	err = json.Unmarshal(body, &tokenResponse)
	if err != nil {
		return nil, errs.Errorf("error parsing response: %v", err)
	}

	return &tokenResponse, nil
}
