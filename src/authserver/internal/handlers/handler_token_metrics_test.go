package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
)

// The token metrics (#400 decision 5): every token response the endpoint writes is counted under
// its grant, and every refusal under the grant asked for and the RFC 6749 section 5.2 code it was
// answered with. Read the way a scraper reads them, from the registry's exposition.

// testTokenMetrics is a recorder over a registry nothing reads, for a test that does not look at
// the counts.
func testTokenMetrics() *tokenmetrics.Recorder {
	return tokenmetrics.Register(metrics.NewRegistry())
}

// tokenSamples answers the sample lines of the two token families in registry's exposition.
func tokenSamples(t *testing.T, registry *metrics.Registry) []string {
	t.Helper()

	rec := httptest.NewRecorder()
	registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var samples []string
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "goiabada_token") {
			samples = append(samples, line)
		}
	}
	return samples
}

func TestHandleTokenPost_CountsEachTokenResponseUnderItsGrant(t *testing.T) {
	tokenResponse := &oauth.TokenResponse{AccessToken: "access_token", TokenType: "Bearer", ExpiresIn: 3600}

	tests := []struct {
		grant string
		arm   func(e *tokenEndpoint)
		form  string
	}{
		{"authorization_code", func(e *tokenEndpoint) {
			code := &record.Code{Id: 1}
			e.validates(&protocolvalidation.AuthorizationCodeGrant{Code: code})
			e.issuer.On("IssueAuthorizationCodeGrant", mock.Anything, mock.Anything, code).Return(tokenResponse, nil).Once()
		}, "grant_type=authorization_code&code=c&redirect_uri=http://example.com&client_id=test_client"},
		{"client_credentials", func(e *tokenEndpoint) {
			client := &record.Client{Id: 1}
			e.validates(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "r:p"})
			e.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, client, "r:p").Return(tokenResponse, nil).Once()
		}, "grant_type=client_credentials&client_id=test_client&client_secret=s&scope=r:p"},
		{"password", func(e *tokenEndpoint) {
			e.validates(&protocolvalidation.PasswordGrant{Client: &record.Client{Id: 1}, User: &record.User{Id: 42}, Scope: "openid"})
			e.issuer.On("IssuePasswordGrant", mock.Anything, mock.Anything, mock.Anything).Return(tokenResponse, nil).Once()
		}, "grant_type=password&client_id=test_client&username=u&password=p&scope=openid"},
		{"refresh_token", func(e *tokenEndpoint) {
			e.validates(codeRefreshGrant(false))
			e.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
				Return(tokenResponse, &issuance.RefreshOutcome{}, nil).Once()
		}, "grant_type=refresh_token&refresh_token=r"},
	}
	for _, test := range tests {
		t.Run(test.grant, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			test.arm(endpoint)
			endpoint.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return()
			endpoint.jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything, tokenResponse).Return().Once()

			endpoint.post(t, test.form)

			endpoint.assertExpectations(t)
			assert.Equal(t, []string{`goiabada_tokens_issued_total{grant_type="` + test.grant + `"} 1`},
				tokenSamples(t, endpoint.registry), "one token response, and no refusal")
		})
	}
}

func TestHandleTokenPost_CountsEachRefusalUnderItsGrantAndErrorCode(t *testing.T) {
	refusal := func(code string, status int) error {
		return oauth.NewErrorDetailWithHTTPStatus(code, "refused", status)
	}

	tests := []struct {
		name string
		arm  func(e *tokenEndpoint)
		form string
		want string
	}{
		{
			name: "the validator's refusal, with its own code",
			arm: func(e *tokenEndpoint) {
				e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, refusal("invalid_client", http.StatusUnauthorized)).Once()
			},
			form: "grant_type=client_credentials&client_id=test_client&client_secret=wrong",
			want: `goiabada_token_requests_refused_total{grant_type="client_credentials",error="invalid_client"} 1`,
		},
		{
			name: "a grant_type the endpoint does not redeem is other, whatever it was",
			arm: func(e *tokenEndpoint) {
				e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, refusal("unsupported_grant_type", http.StatusBadRequest)).Once()
			},
			form: "grant_type=implicit&client_id=test_client",
			want: `goiabada_token_requests_refused_total{grant_type="other",error="unsupported_grant_type"} 1`,
		},
		{
			name: "a code outside RFC 6749 section 5.2 is other",
			arm: func(e *tokenEndpoint) {
				e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, refusal("invalid_target", http.StatusBadRequest)).Once()
			},
			form: "grant_type=password&client_id=test_client&username=u&password=p",
			want: `goiabada_token_requests_refused_total{grant_type="password",error="other"} 1`,
		},
		{
			name: "an issuer fault is the server_error it is answered as",
			arm: func(e *tokenEndpoint) {
				e.validates(&protocolvalidation.PasswordGrant{Client: &record.Client{Id: 1}, User: &record.User{Id: 42}, Scope: "openid"})
				e.issuer.On("IssuePasswordGrant", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errs.New("signing key unavailable")).Once()
			},
			form: "grant_type=password&client_id=test_client&username=u&password=p&scope=openid",
			want: `goiabada_token_requests_refused_total{grant_type="password",error="server_error"} 1`,
		},
		{
			name: "a refusal the responder writes, a replayed refresh token",
			arm: func(e *tokenEndpoint) {
				e.validates(codeRefreshGrant(true))
				e.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
					Return(nil, nil, &issuance.RefreshTokenReplayedError{}).Once()
			},
			form: "grant_type=refresh_token&refresh_token=r",
			want: `goiabada_token_requests_refused_total{grant_type="refresh_token",error="invalid_grant"} 1`,
		},
		{
			name: "a code whose claim was lost",
			arm: func(e *tokenEndpoint) {
				code := &record.Code{Id: 1}
				e.validates(&protocolvalidation.AuthorizationCodeGrant{Code: code})
				e.issuer.On("IssueAuthorizationCodeGrant", mock.Anything, mock.Anything, code).
					Return(nil, issuance.ErrCodeNotClaimed).Once()
			},
			form: "grant_type=authorization_code&code=c&redirect_uri=http://example.com&client_id=test_client",
			want: `goiabada_token_requests_refused_total{grant_type="authorization_code",error="invalid_grant"} 1`,
		},
		{
			name: "a body refused before it reached the validator, under the grant it named",
			arm:  func(e *tokenEndpoint) {},
			form: "grant_type=client_credentials&client_id=a&client_id=b",
			want: `goiabada_token_requests_refused_total{grant_type="client_credentials",error="invalid_request"} 1`,
		},
		{
			name: "a body that does not parse, under the grant named before the fault",
			arm:  func(e *tokenEndpoint) {},
			form: "grant_type=refresh_token&refresh_token=%zz",
			want: `goiabada_token_requests_refused_total{grant_type="refresh_token",error="invalid_request"} 1`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			test.arm(endpoint)
			endpoint.auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
			endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			endpoint.post(t, test.form)

			endpoint.assertExpectations(t)
			assert.Equal(t, []string{test.want}, tokenSamples(t, endpoint.registry), "one refusal, and no token")
		})
	}
}

// The grant_type is the request's, and only its mapping into the declared set reaches the label:
// a value the endpoint does not redeem is recorded as other and never appears itself.
func TestHandleTokenPost_ARequestedGrantTypeNeverReachesALabel(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	endpoint.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, oauth.NewErrorDetailWithHTTPStatus("unsupported_grant_type", "refused", http.StatusBadRequest)).Once()
	endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

	endpoint.post(t, "grant_type=urn:example:marker-grant&client_id=test_client")

	samples := tokenSamples(t, endpoint.registry)
	assert.Equal(t, []string{`goiabada_token_requests_refused_total{grant_type="other",error="unsupported_grant_type"} 1`}, samples)
	assert.NotContains(t, strings.Join(samples, "\n"), "marker")
}
