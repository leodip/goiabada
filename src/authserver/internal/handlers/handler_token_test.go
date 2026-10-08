package handlers

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/tokenmetrics"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/metrics"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleTokenPost(t *testing.T) {
	// A form that cannot be parsed is the client's malformed request, answered 400 invalid_request
	// per RFC 6749 section 5.2, and never the 500 it once was: whatever broke the parse, the
	// server is not at fault (#426). The body cut at the request-body limit is the case the
	// limit introduced; the other two answered 500 before it.
	t.Run("ParseForm gives error", func(t *testing.T) {
		const form = "grant_type=client_credentials&client_id=a-client&client_secret=a-secret"

		tests := []struct {
			name string
			body func(w http.ResponseWriter) io.Reader
		}{
			{"no body at all", func(http.ResponseWriter) io.Reader { return nil }},
			{"a broken percent-encoding", func(http.ResponseWriter) io.Reader { return strings.NewReader("grant_type=%zz") }},
			{"a body cut one byte short by the request-body limit", func(w http.ResponseWriter) io.Reader {
				return http.MaxBytesReader(w, io.NopCloser(strings.NewReader(form)), int64(len(form)-1))
			}},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				jsonWriter := handlersmocks.NewJSONWriter(t)
				database := datamocks.NewDatabase(t)
				handler := HandleTokenPost(jsonWriter, database,
					handlersmocks.NewTokenIssuer(t), handlersmocks.NewTokenValidator(t),
					handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())

				rr := httptest.NewRecorder()
				req, _ := http.NewRequest("POST", "/token", test.body(rr))
				req = withSettings(req, &record.Settings{})
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
					detail, ok := err.(*oauth.ErrorDetail)
					return ok && detail.Code() == "invalid_request" &&
						detail.HTTPStatus() == http.StatusBadRequest &&
						detail.Description() == "The request body could not be parsed."
				})).Return().Once()

				handler.ServeHTTP(rr, req)

				jsonWriter.AssertExpectations(t)
				database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
			})
		}

		// The accept side of the limit: the same form under a limit equal to its length is read
		// whole, and every field of it reaches the validator.
		t.Run("the same body at exactly the limit", func(t *testing.T) {
			refused := oauth.NewErrorDetailWithHTTPStatus("invalid_client", "Client authentication failed.", http.StatusUnauthorized)
			tokenValidator := handlersmocks.NewTokenValidator(t)
			tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.MatchedBy(func(input *protocolvalidation.ValidateTokenRequestInput) bool {
				return input.GrantType == "client_credentials" && input.ClientId == "a-client" && input.ClientSecret == "a-secret"
			})).Return(nil, refused).Once()
			jsonWriter := handlersmocks.NewJSONWriter(t)

			handler := HandleTokenPost(jsonWriter, datamocks.NewDatabase(t),
				handlersmocks.NewTokenIssuer(t), tokenValidator, handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())

			rr := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/token",
				http.MaxBytesReader(rr, io.NopCloser(strings.NewReader(form)), int64(len(form))))
			req = withSettings(req, &record.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*oauth.ErrorDetail)
				return ok && detail.Code() == "invalid_client"
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
			tokenValidator.AssertExpectations(t)
		})

		// With the ROPC limiter on, its own ParseForm meets the cut body first and passes the
		// request through, and net/http leaves an empty form behind for the handler's. The real
		// validator answers that empty form, which names no client.
		t.Run("a body cut before the handler, as the ROPC limiter leaves it", func(t *testing.T) {
			jsonWriter := handlersmocks.NewJSONWriter(t)
			database := datamocks.NewDatabase(t)
			handler := HandleTokenPost(jsonWriter, database,
				handlersmocks.NewTokenIssuer(t), protocolvalidation.NewTokenValidator(database, nil, nil, testDataCipher),
				handlersmocks.NewAuditLogger(t), noCredentialFailures{}, testTokenMetrics())

			rr := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/token",
				http.MaxBytesReader(rr, io.NopCloser(strings.NewReader(form)), int64(len(form)-1)))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{Id: 1}))
			require.Error(t, req.ParseForm(), "the limiter's parse fails")

			jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*oauth.ErrorDetail)
				return ok && detail.Code() == "invalid_request" &&
					detail.HTTPStatus() == http.StatusBadRequest &&
					detail.Description() == "Missing required client_id parameter."
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
		})
	})

	// RFC 6749 section 2.3: a client MUST NOT use more than one authentication method in a request.
	// Refused as parsed, before any client is looked up; which pairs count as two is
	// TestExtractClientCredentials'.
	t.Run("two client authentication methods are refused before the validator", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			detail, ok := err.(*oauth.ErrorDetail)
			return ok && detail.Code() == "invalid_request" &&
				detail.HTTPStatus() == http.StatusBadRequest &&
				strings.Contains(detail.Description(), "multiple authentication methods provided")
		})).Return().Once()

		req, _ := http.NewRequest("POST", "/token",
			strings.NewReader("grant_type=client_credentials&client_id=test_client&client_secret=body-secret"))
		req = withSettings(req, endpoint.settings)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("test_client", "basic-secret")
		endpoint.handler.ServeHTTP(httptest.NewRecorder(), req)

		// The strict validator double registered nothing, so reaching it would have failed here.
		endpoint.assertExpectations(t)
	})

	t.Run("ValidateTokenRequest gives error", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)
		tokenIssuer := handlersmocks.NewTokenIssuer(t)
		tokenValidator := handlersmocks.NewTokenValidator(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		validationError := oauth.NewErrorDetailWithHTTPStatus("invalid_request", "Validation error", http.StatusBadRequest)

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(nil, validationError)

		jsonWriter.On("JSONError", rr, req, validationError).Return()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
	})

	t.Run("Authorization_code: an issuer failure is answered as it arrived", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		code := &record.Code{Id: 1}
		endpoint.validates(&protocolvalidation.AuthorizationCodeGrant{Code: code})

		failure := oauth.NewErrorDetailWithHTTPStatus("server_error", "Failed to generate token", http.StatusInternalServerError)
		endpoint.issuer.On("IssueAuthorizationCodeGrant", mock.Anything, mock.Anything, code).Return(nil, failure).Once()
		endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, failure).Return().Once()

		endpoint.post(t, "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client")

		endpoint.assertExpectations(t)
		endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Authorization_code successful flow", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		code := &record.Code{Id: 1}
		requestSettings := &record.Settings{Issuer: "https://issuer.example"}
		endpoint.settings = requestSettings
		endpoint.validates(&protocolvalidation.AuthorizationCodeGrant{Code: code})

		tokenResponse := &oauth.TokenResponse{AccessToken: "access_token", TokenType: "Bearer", ExpiresIn: 3600}
		// The issuer is handed the request's own settings and the validated code itself.
		endpoint.issuer.On("IssueAuthorizationCodeGrant", mock.Anything, theseSettings(requestSettings), code).
			Return(tokenResponse, nil).Once()
		endpoint.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedAuthorizationCodeResponse, map[string]interface{}{
			"code_id": code.Id,
		}).Return().Once()
		endpoint.jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything, tokenResponse).Return().Once()

		rr := endpoint.post(t, "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client")

		endpoint.assertExpectations(t)
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Client_credentials successful flow", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		requestSettings := &record.Settings{Issuer: "https://issuer.example"}
		endpoint.settings = requestSettings
		client := &record.Client{Id: 1, ClientIdentifier: "test_client"}
		endpoint.validates(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "test_scope"})

		tokenResponse := &oauth.TokenResponse{AccessToken: "access_token", TokenType: "Bearer", ExpiresIn: 3600}
		endpoint.issuer.On("IssueClientCredentialsGrant", mock.Anything, theseSettings(requestSettings), client, "test_scope").
			Return(tokenResponse, nil).Once()
		endpoint.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedClientCredentialsResponse, map[string]interface{}{
			"client_id": client.Id,
			"scope":     "test_scope",
		}).Return().Once()
		endpoint.jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything, tokenResponse).Return().Once()

		rr := endpoint.post(t, "grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=test_scope")

		endpoint.assertExpectations(t)
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Client_credentials: an issuer failure is answered, and nothing is audited", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		client := &record.Client{Id: 1, ClientIdentifier: "test_client"}
		endpoint.validates(&protocolvalidation.ClientCredentialsGrant{Client: client, Scope: "test_scope"})

		failure := errs.New("signing key unavailable")
		endpoint.issuer.On("IssueClientCredentialsGrant", mock.Anything, mock.Anything, client, "test_scope").
			Return(nil, failure).Once()
		endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, failure).Return().Once()

		endpoint.post(t, "grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=test_scope")

		endpoint.assertExpectations(t)
		endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Password: an issuer failure is answered, and nothing is audited", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		grant := &protocolvalidation.PasswordGrant{
			Client: &record.Client{Id: 1, ClientIdentifier: "test_client"},
			User:   &record.User{Id: 42},
			Scope:  "openid",
		}
		endpoint.validates(grant)

		failure := errs.New("signing key unavailable")
		endpoint.issuer.On("IssuePasswordGrant", mock.Anything, mock.Anything, mock.Anything).Return(nil, failure).Once()
		endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, failure).Return().Once()

		endpoint.post(t, "grant_type=password&client_id=test_client&username=u&password=p&scope=openid")

		endpoint.assertExpectations(t)
		endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Password successful flow", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		grant := &protocolvalidation.PasswordGrant{
			Client: &record.Client{Id: 1, ClientIdentifier: "test_client"},
			User:   &record.User{Id: 42},
			Scope:  "openid",
		}
		endpoint.validates(grant)

		tokenResponse := &oauth.TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600}
		endpoint.issuer.On("IssuePasswordGrant", mock.Anything, mock.Anything, &issuance.ROPCGrantInput{
			Client: grant.Client, User: grant.User, Scope: grant.Scope,
		}).Return(tokenResponse, nil).Once()
		endpoint.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedROPCResponse, map[string]interface{}{
			"user_id":   int64(42),
			"client_id": int64(1),
		}).Return().Once()
		endpoint.jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything, tokenResponse).Return().Once()

		rr := endpoint.post(t, "grant_type=password&client_id=test_client&username=u&password=p&scope=openid")

		endpoint.assertExpectations(t)
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Refresh_token: an issuer fault is answered as it arrived", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		grant := codeRefreshGrant(false)
		endpoint.validates(grant)

		failure := oauth.NewErrorDetailWithHTTPStatus("server_error", "Failed to generate token", http.StatusInternalServerError)
		endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil, failure).Once()
		endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, failure).Return().Once()

		endpoint.post(t, "grant_type=refresh_token&refresh_token=test_refresh_token")

		endpoint.assertExpectations(t)
		endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Refresh_token: the issuer is handed the whole validated grant", func(t *testing.T) {
		for _, isROPC := range []bool{false, true} {
			endpoint := newTokenEndpoint(t)
			requestSettings := &record.Settings{Issuer: "https://issuer.example"}
			endpoint.settings = requestSettings
			grant := codeRefreshGrant(false)
			if isROPC {
				grant = ropcRefreshGrant(false)
			}
			grant.ScopeRequested = "openid"
			endpoint.validates(grant)

			endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, theseSettings(requestSettings), &issuance.RefreshTokenGrantInput{
				Client:         grant.Client,
				RefreshToken:   grant.RefreshToken,
				ScopeRequested: "openid",
				IsROPC:         isROPC,
			}).Return(nil, nil, issuance.ErrRefreshTokenNotClaimed).Once()
			endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			endpoint.post(t, "grant_type=refresh_token&refresh_token=test_refresh_token&scope=openid")

			endpoint.assertExpectations(t)
		}
	})

	t.Run("Refresh_token with a bumped session audits the bump before the issuance", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		grant := codeRefreshGrant(false)
		endpoint.validates(grant)

		tokenResponse := &oauth.TokenResponse{AccessToken: "new_access_token", RefreshToken: "new_refresh_token", TokenType: "Bearer", ExpiresIn: 3600}
		endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
			Return(tokenResponse, &issuance.RefreshOutcome{BumpedSession: &record.UserSession{Id: 1, UserId: 456}}, nil).Once()

		var order []string
		endpoint.auditLogger.On("Log", mock.Anything, audit.EventBumpedUserSession, map[string]interface{}{
			"user_id":   int64(456),
			"client_id": grant.RefreshToken.Code.ClientId,
		}).Run(func(mock.Arguments) { order = append(order, audit.EventBumpedUserSession) }).Return().Once()
		endpoint.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedRefreshTokenResponse, map[string]interface{}{
			"code_id":           grant.RefreshToken.Code.Id,
			"refresh_token_jti": grant.RefreshToken.RefreshTokenJti,
			"flow":              "auth_code",
		}).Run(func(mock.Arguments) { order = append(order, audit.EventTokenIssuedRefreshTokenResponse) }).Return().Once()
		endpoint.jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything, tokenResponse).Return().Once()

		rr := endpoint.post(t, "grant_type=refresh_token&refresh_token=test_refresh_token")

		endpoint.assertExpectations(t)
		assert.Equal(t, []string{audit.EventBumpedUserSession, audit.EventTokenIssuedRefreshTokenResponse}, order)
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Refresh_token success path without session", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		grant := codeRefreshGrant(false)
		endpoint.validates(grant)

		tokenResponse := &oauth.TokenResponse{AccessToken: "new_access_token", RefreshToken: "new_refresh_token", TokenType: "Bearer", ExpiresIn: 3600}
		endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
			Return(tokenResponse, &issuance.RefreshOutcome{}, nil).Once()
		// The strict double refuses any other Log call, the bump's included.
		endpoint.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedRefreshTokenResponse, map[string]interface{}{
			"code_id":           grant.RefreshToken.Code.Id,
			"refresh_token_jti": grant.RefreshToken.RefreshTokenJti,
			"flow":              "auth_code",
		}).Return().Once()
		endpoint.jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything, tokenResponse).Return().Once()

		rr := endpoint.post(t, "grant_type=refresh_token&refresh_token=test_refresh_token")

		endpoint.assertExpectations(t)
		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Refresh_token, a password grant's token: audited with the user and client on its row", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		grant := ropcRefreshGrant(false)
		endpoint.validates(grant)

		tokenResponse := &oauth.TokenResponse{AccessToken: "new_access_token", RefreshToken: "new_refresh_token", TokenType: "Bearer", ExpiresIn: 3600}
		endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
			Return(tokenResponse, &issuance.RefreshOutcome{}, nil).Once()
		endpoint.auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedRefreshTokenResponse, map[string]interface{}{
			"user_id":           grant.RefreshToken.UserId.Int64,
			"client_id":         grant.RefreshToken.ClientId.Int64,
			"refresh_token_jti": grant.RefreshToken.RefreshTokenJti,
			"flow":              "ropc",
		}).Return().Once()
		endpoint.jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything, tokenResponse).Return().Once()

		endpoint.post(t, "grant_type=refresh_token&refresh_token=test_refresh_token")

		endpoint.assertExpectations(t)
	})

	t.Run("Refresh_token replayed with nothing left to contain: refused, not audited", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		endpoint.validates(codeRefreshGrant(true))

		// Containment ran and found nothing live, the idempotent no-op an already-swept family
		// produces. A zero count means no audit event (#128).
		endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
			Return(nil, nil, &issuance.RefreshTokenReplayedError{FamilyRevokedCount: 0}).Once()
		endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			detail, ok := err.(*oauth.ErrorDetail)
			return ok && detail.Code() == "invalid_grant" &&
				detail.Description() == "This refresh token has been revoked." &&
				detail.HTTPStatus() == http.StatusBadRequest
		})).Return().Once()

		endpoint.post(t, "grant_type=refresh_token&refresh_token=test_refresh_token")

		endpoint.assertExpectations(t)
		endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	// The validator refuses every grant_type the grant table does not accept, so no request
	// reaches this arm; it is what the endpoint answers if a validator ever returned a grant with
	// no responder. A server fault, never a token.
	t.Run("a grant the endpoint has no responder for is a server fault", func(t *testing.T) {
		endpoint := newTokenEndpoint(t)
		endpoint.validates(unansweredGrant{})

		endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			var detail *oauth.ErrorDetail
			return !errors.As(err, &detail) && strings.Contains(err.Error(), "does not answer")
		})).Return().Once()

		endpoint.post(t, "grant_type=device_code&client_id=test_client")

		endpoint.assertExpectations(t)
		endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})
}

// unansweredGrant is a validated grant the token endpoint has no responder for.
type unansweredGrant struct{}

func (unansweredGrant) GrantType() oidc.GrantType { return "device_code" }

// tokenEndpoint is one HandleTokenPost wired to fresh strict doubles, for a case that drives one
// request through it. The validator answers whatever validates names.
type tokenEndpoint struct {
	jsonWriter  *handlersmocks.JSONWriter
	database    *datamocks.Database
	issuer      *handlersmocks.TokenIssuer
	validator   *handlersmocks.TokenValidator
	auditLogger *handlersmocks.AuditLogger
	settings    *record.Settings
	handler     http.HandlerFunc
	// registry is the one the handler's token metrics are registered on, read by tokenSamples.
	registry *metrics.Registry
}

func newTokenEndpoint(t *testing.T) *tokenEndpoint {
	t.Helper()
	endpoint := &tokenEndpoint{
		jsonWriter:  handlersmocks.NewJSONWriter(t),
		database:    datamocks.NewDatabase(t),
		issuer:      handlersmocks.NewTokenIssuer(t),
		validator:   handlersmocks.NewTokenValidator(t),
		auditLogger: handlersmocks.NewAuditLogger(t),
		settings:    &record.Settings{},
		registry:    metrics.NewRegistry(),
	}
	endpoint.handler = HandleTokenPost(endpoint.jsonWriter, endpoint.database, endpoint.issuer,
		endpoint.validator, endpoint.auditLogger, noCredentialFailures{}, tokenmetrics.Register(endpoint.registry))
	return endpoint
}

// validates makes the validator accept every request as grant.
func (e *tokenEndpoint) validates(grant protocolvalidation.TokenGrant) {
	e.validator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
		mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(grant, nil).Once()
}

// post submits form to the endpoint with the endpoint's settings on the request.
func (e *tokenEndpoint) post(t *testing.T, form string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := http.NewRequest("POST", "/token", strings.NewReader(form))
	require.NoError(t, err)
	req = withSettings(req, e.settings)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, req)
	return rr
}

func (e *tokenEndpoint) assertExpectations(t *testing.T) {
	t.Helper()
	e.jsonWriter.AssertExpectations(t)
	e.validator.AssertExpectations(t)
	e.issuer.AssertExpectations(t)
	e.auditLogger.AssertExpectations(t)
	e.database.AssertExpectations(t)
}

// codeRefreshGrant is a validated refresh of a token an authorization code minted; revoked is what
// the validator read.
func codeRefreshGrant(revoked bool) *protocolvalidation.RefreshTokenGrant {
	return &protocolvalidation.RefreshTokenGrant{
		Client: &record.Client{Id: 123, ClientIdentifier: "test_client", AuthorizationCodeEnabled: true},
		RefreshToken: &record.RefreshToken{
			Id:                   1,
			Revoked:              revoked,
			RefreshTokenJti:      "jti-presented",
			FirstRefreshTokenJti: "jti-family",
			SessionIdentifier:    "sid-1",
			CodeId:               sql.NullInt64{Int64: 789, Valid: true},
			Code:                 record.Code{Id: 789, ClientId: 123, UserId: 456},
		},
	}
}

// ropcRefreshGrant is a validated refresh of a token the password grant minted, whose user and
// client are on the token row.
func ropcRefreshGrant(revoked bool) *protocolvalidation.RefreshTokenGrant {
	return &protocolvalidation.RefreshTokenGrant{
		Client: &record.Client{Id: 123, ClientIdentifier: "test_client"},
		RefreshToken: &record.RefreshToken{
			Id:                   1,
			Revoked:              revoked,
			RefreshTokenJti:      "jti-presented",
			FirstRefreshTokenJti: "jti-family",
			UserId:               sql.NullInt64{Int64: 456, Valid: true},
			ClientId:             sql.NullInt64{Int64: 123, Valid: true},
		},
		IsROPC: true,
	}
}

func TestParseBasicAuth(t *testing.T) {
	t.Run("Empty header returns false", func(t *testing.T) {
		clientId, clientSecret, ok := parseBasicAuth("")
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Non-Basic scheme returns false", func(t *testing.T) {
		clientId, clientSecret, ok := parseBasicAuth("Bearer some-token")
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Invalid base64 returns false", func(t *testing.T) {
		clientId, clientSecret, ok := parseBasicAuth("Basic not-valid-base64!")
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Missing colon separator returns false", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("nocolon"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Valid credentials are parsed correctly", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("my-client-id:my-secret"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "my-client-id", clientId)
		assert.Equal(t, "my-secret", clientSecret)
	})

	t.Run("Password with colons is parsed correctly", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:pass:with:colons"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "client", clientId)
		assert.Equal(t, "pass:with:colons", clientSecret)
	})

	t.Run("Empty password is valid", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "client", clientId)
		assert.Equal(t, "", clientSecret)
	})

	t.Run("Empty client_id with password is valid", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(":secret"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "", clientId)
		assert.Equal(t, "secret", clientSecret)
	})

	t.Run("Special characters in credentials", func(t *testing.T) {
		// Test with special chars that might cause issues
		encoded := base64.StdEncoding.EncodeToString([]byte("client+id@example.com:p@ss=word&special!"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "client+id@example.com", clientId)
		assert.Equal(t, "p@ss=word&special!", clientSecret)
	})

	t.Run("Unicode characters in credentials", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("клиент:密码"))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, "клиент", clientId)
		assert.Equal(t, "密码", clientSecret)
	})

	t.Run("Lowercase basic prefix is rejected", func(t *testing.T) {
		// RFC 7617 says the scheme is case-insensitive, but we're strict here
		// This documents the current behavior
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		clientId, clientSecret, ok := parseBasicAuth("basic " + encoded)
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Extra whitespace after Basic is handled", func(t *testing.T) {
		// Extra space should cause base64 decode to fail or produce wrong result
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		clientId, clientSecret, ok := parseBasicAuth("Basic  " + encoded) // two spaces
		// The extra space becomes part of the base64 string, likely causing decode failure
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Missing space after Basic is rejected", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		clientId, clientSecret, ok := parseBasicAuth("Basic" + encoded) // no space
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Very long credentials", func(t *testing.T) {
		longClientId := strings.Repeat("a", 1000)
		longSecret := strings.Repeat("b", 1000)
		encoded := base64.StdEncoding.EncodeToString([]byte(longClientId + ":" + longSecret))
		clientId, clientSecret, ok := parseBasicAuth("Basic " + encoded)
		assert.True(t, ok)
		assert.Equal(t, longClientId, clientId)
		assert.Equal(t, longSecret, clientSecret)
	})
}

func TestExtractClientCredentials(t *testing.T) {
	t.Run("Basic auth only - credentials extracted from header", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		req, _ := http.NewRequest("POST", "/token", strings.NewReader("grant_type=client_credentials"))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
	})

	t.Run("POST body only - credentials extracted from form", func(t *testing.T) {
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
	})

	t.Run("Both methods provided - returns error", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.Error(t, err)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)

		errDetail, ok := err.(*oauth.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", errDetail.Code())
		assert.Contains(t, errDetail.Description(), "multiple authentication methods")
	})

	t.Run("No credentials provided - returns empty values", func(t *testing.T) {
		formData := "grant_type=authorization_code&code=test"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Basic auth with client_id in POST but no client_secret - allowed", func(t *testing.T) {
		// This is allowed because only client_secret in POST triggers the conflict
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
	})

	t.Run("Invalid Basic auth header falls back to POST body", func(t *testing.T) {
		// Malformed Basic auth should be ignored, not cause an error
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic invalid-base64!")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
	})

	t.Run("Bearer token header does not interfere with POST body", func(t *testing.T) {
		// A Bearer token should not be treated as Basic auth
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer some-access-token")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
	})

	t.Run("Empty client_secret in POST body is not considered authentication", func(t *testing.T) {
		// Empty string for client_secret should not trigger the "multiple methods" error
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client&client_secret="
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
	})

	t.Run("Public client - only client_id in POST, no secret", func(t *testing.T) {
		formData := "grant_type=authorization_code&client_id=public-client&code=auth-code"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "public-client", clientId)
		assert.Equal(t, "", clientSecret)
	})
}

// TestHandleTokenPost_AuthCodeReuse_RevokeFailureReturns500 verifies the
// failure path of the RFC 6749 §4.1.2 revocation flow: when the validator
// signals auth-code reuse but the transactional revoke fails, the handler
// MUST return 500 (not invalid_grant) so the client never sees a response
// that looks like a clean denial while linked tokens may still be live.
// It must also skip the audit log, which fires only after a successful commit.
func TestHandleTokenPost_AuthCodeReuse_RevokeFailureReturns500(t *testing.T) {
	jsonWriter := handlersmocks.NewJSONWriter(t)
	database := datamocks.NewDatabase(t)
	tokenIssuer := handlersmocks.NewTokenIssuer(t)
	tokenValidator := handlersmocks.NewTokenValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())

	formData := "grant_type=authorization_code&code=replayed&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &record.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	reusedCode := &record.Code{
		Id:                42,
		ClientId:          7,
		UserId:            13,
		SessionIdentifier: "sid-reused",
	}
	reuseErr := &protocolvalidation.AuthCodeReusedError{
		Detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Code is invalid.", http.StatusBadRequest),
		Code:   reusedCode,
	}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(nil, reuseErr)

	stub := datamocks.ExpectRunInTransaction(database, revokeTx)

	// The session row is taken first, ahead of the grants that hang off it (#139). Stubbed as
	// succeeding so this case still fails where it means to, at the token read below. Both reads
	// name revokeTx rather than nil, which is what says they happened inside the transaction:
	// until #422 this case expected (*sql.Tx)(nil), which a call made outside one also matches.
	database.On("AcquireUserSessionRow", mock.Anything, revokeTx, "sid-reused").
		Return(true, nil).Once()

	dbErr := errors.New("connection refused")
	database.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, "sid-reused").
		Return(nil, dbErr).Once()

	jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "connection refused")
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	assert.ErrorIs(t, stub.BodyErr, dbErr, "the body hands its error to the helper, which rolls back")

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	// Audit log must NOT fire when revocation fails: it is reserved for the
	// post-commit success path where revokedJtis are real.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	// invalid_grant response must NOT be sent: the client gets 500 instead.
	// The one JSONError call is the 500 matched above; a second would be the invalid_grant.
	jsonWriter.AssertNumberOfCalls(t, "JSONError", 1)
}

// TestHandleTokenPost_AuthCodeReuse_BeginTransactionFailureReturns500 covers
// the earliest failure point: BeginTransaction itself errors. The handler
// must still surface a 500 and skip both the audit log and the invalid_grant.
func TestHandleTokenPost_AuthCodeReuse_BeginTransactionFailureReturns500(t *testing.T) {
	jsonWriter := handlersmocks.NewJSONWriter(t)
	database := datamocks.NewDatabase(t)
	tokenIssuer := handlersmocks.NewTokenIssuer(t)
	tokenValidator := handlersmocks.NewTokenValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())

	formData := "grant_type=authorization_code&code=replayed&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &record.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	reuseErr := &protocolvalidation.AuthCodeReusedError{
		Detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Code is invalid.", http.StatusBadRequest),
		Code: &record.Code{
			Id:                7,
			SessionIdentifier: "sid-reused",
		},
	}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(nil, reuseErr)

	beginErr := errors.New("tx begin failed")
	datamocks.ExpectRunInTransactionRefused(database, beginErr)

	jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "tx begin failed")
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	jsonWriter.AssertNumberOfCalls(t, "JSONError", 1)
}

// TestHandleTokenPost_AuthCodeReuse_AuditsAfterTheCommit pins where the reuse audit row falls: after
// revocation.RevokeOnAuthCodeReuseTx has committed, and before the invalid_grant answer. The order
// is not cosmetic. AuditLogger.Log writes on a nil transaction, and on SQLite the whole process
// shares the one connection the reuse transaction holds, so an audit written inside it would wait
// on itself; and a row written before a commit that then failed would list JTIs never revoked.
func TestHandleTokenPost_AuthCodeReuse_AuditsAfterTheCommit(t *testing.T) {
	jsonWriter := handlersmocks.NewJSONWriter(t)
	database := datamocks.NewDatabase(t)
	tokenValidator := handlersmocks.NewTokenValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, database,
		handlersmocks.NewTokenIssuer(t), tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())

	formData := "grant_type=authorization_code&code=replayed&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &record.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	reuseErr := &protocolvalidation.AuthCodeReusedError{
		Detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Code is invalid.", http.StatusBadRequest),
		Code:   &record.Code{Id: 42, ClientId: 7, UserId: 13, SessionIdentifier: "sid-reused"},
	}
	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(nil, reuseErr)

	var order []string
	note := func(what string) func(mock.Arguments) {
		return func(mock.Arguments) { order = append(order, what) }
	}
	token := &record.RefreshToken{Id: 1, RefreshTokenJti: "rt-1"}
	datamocks.ExpectRunInTransaction(database, revokeTx, func(edge string) { order = append(order, edge) })
	database.On("AcquireUserSessionRow", mock.Anything, revokeTx, "sid-reused").Return(true, nil).Once()
	database.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, "sid-reused").
		Return([]*record.RefreshToken{token}, nil).Once()
	database.On("UpdateRefreshToken", mock.Anything, revokeTx, token).Run(note("revoke")).Return(nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, revokeTx, "sid-reused").
		Return(&record.UserSession{Id: 9, SessionIdentifier: "sid-reused"}, nil).Once()
	database.On("DeleteUserSession", mock.Anything, revokeTx, int64(9)).Return(nil).Once()

	var audited map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.EventAuthCodeReuseDetected, mock.Anything).
		Run(func(args mock.Arguments) {
			order = append(order, "audit")
			audited, _ = args.Get(2).(map[string]interface{})
		}).Return().Once()
	jsonWriter.On("JSONError", rr, req, reuseErr.Detail).Run(note("answer")).Return().Once()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, []string{"begin", "revoke", "commit", "audit", "answer"}, order,
		"the audit row must wait for the commit, and the client's answer for the audit row")
	assert.Equal(t, []string{"rt-1"}, audited["revoked_refresh_token_jtis"],
		"the row lists what the committed transaction revoked")
	database.AssertExpectations(t)
}

// TestHandleTokenPost_AuthCode_ConcurrentDoubleSpendLoses verifies the handler half of the #77 fix:
// a redemption whose claim was lost (issuance.ErrCodeNotClaimed) is refused as an invalid code, and
// does NOT run the session-wide reuse cascade (no transaction, no session teardown, no reuse audit),
// which running concurrently with the winner's mint on the same session rows is what deadlocks the
// winner. That the loser mints nothing is the issuer's, and is pinned in issuance's
// TestIssueAuthorizationCodeGrant_ALostClaimMintsNothing. A genuine LATER replay is still cascaded,
// by the sequential-reuse path (covered by the integration CodeReuse_* tests).
func TestHandleTokenPost_AuthCode_ConcurrentDoubleSpendLoses(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	racedCode := &record.Code{Id: 42, ClientId: 7, UserId: 13, SessionIdentifier: "sid-raced"}
	endpoint.validates(&protocolvalidation.AuthorizationCodeGrant{Code: racedCode})

	endpoint.issuer.On("IssueAuthorizationCodeGrant", mock.Anything, mock.Anything, racedCode).
		Return(nil, issuance.ErrCodeNotClaimed).Once()
	endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		detail, ok := err.(*oauth.ErrorDetail)
		return ok && detail.Code() == "invalid_grant" && detail.Description() == "Code is invalid." &&
			detail.HTTPStatus() == http.StatusBadRequest
	})).Return().Once()

	endpoint.post(t, "grant_type=authorization_code&code=raced&redirect_uri=http://example.com&client_id=test_client")

	endpoint.assertExpectations(t)
	endpoint.database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
	endpoint.database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything, mock.Anything)
	endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleTokenPost_Refresh_ConcurrentDoubleSpendLoses pins the answer to a refresh whose claim was
// lost (issuance.ErrRefreshTokenNotClaimed): refused, and nothing audited (#128). That the lost claim
// cascades over nothing and mints nothing is the issuer's, pinned in issuance's
// TestIssueRefreshTokenGrant_ALostClaimContainsAndMintsNothing.
//
// What it does NOT prove: the inter-request ordering that produced this state. A mocked unit test
// fixes the state and asserts the resulting branch; no mocked test can establish that one HTTP
// request really arrived before another. Its sibling for the other branch is the replayed subtest
// inside TestHandleTokenPost.
func TestHandleTokenPost_Refresh_ConcurrentDoubleSpendLoses(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	endpoint.validates(codeRefreshGrant(false))

	endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil, issuance.ErrRefreshTokenNotClaimed).Once()
	endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
		detail, ok := err.(*oauth.ErrorDetail)
		return ok && detail.Code() == "invalid_grant" &&
			detail.Description() == "This refresh token has been revoked." &&
			detail.HTTPStatus() == http.StatusBadRequest
	})).Return().Once()

	endpoint.post(t, "grant_type=refresh_token&refresh_token=raced")

	endpoint.assertExpectations(t)
	endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleTokenPost_Refresh_Replay_AuditsContainment asserts the replay-containment
// audit payload EXACTLY. It lives at the unit tier deliberately: the mock logger makes
// the payload observable, and the integration tier cannot see it at all (#128).
//
// Both linkage shapes are run against the same expectations on purpose. A security-event
// consumer must not need flow-specific logic to identify the client and user, which is
// where this departs from EventTokenIssuedRefreshTokenResponse (codeId on one shape,
// userId/clientId on the other).
//
// The exact-key assertion is what pins the two negative requirements from decision 8: the
// payload carries neither the presented refresh token itself nor a list of revoked JTIs.
// A set-based update yields an exact COUNT but not an exact cross-engine row set, and an
// inaccurate security field is worse than an omitted one.
//
// Containment itself, and that a replay reaches neither the flow gate nor the claim nor the mint,
// is the issuer's: issuance's TestIssueRefreshTokenGrant_AReplayContainsItsFamilyAndGoesNoFurther.
func TestHandleTokenPost_Refresh_Replay_AuditsContainment(t *testing.T) {
	const (
		presentedJti = "jti-presented"
		familyJti    = "jti-family"
		clientId     = int64(123)
		userId       = int64(456)
	)

	testCases := []struct {
		name     string
		grant    *protocolvalidation.RefreshTokenGrant
		wantFlow string
	}{
		// The principal fields come from the loaded code on this shape.
		{name: "authorization code family", grant: codeRefreshGrant(true), wantFlow: "auth_code"},
		// No code at all: the client and user are on the refresh token row.
		{name: "ROPC family", grant: ropcRefreshGrant(true), wantFlow: "ropc"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			endpoint.validates(tc.grant)

			// Two live members transitioned, so this is a real containment.
			endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
				Return(nil, nil, &issuance.RefreshTokenReplayedError{FamilyRevokedCount: 2}).Once()

			var logged []map[string]interface{}
			endpoint.auditLogger.On("Log", mock.Anything, audit.EventRefreshTokenReplayDetected, mock.AnythingOfType("map[string]interface {}")).
				Run(func(args mock.Arguments) {
					logged = append(logged, args.Get(2).(map[string]interface{}))
				}).Return()

			endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*oauth.ErrorDetail)
				return ok && detail.Code() == "invalid_grant" &&
					detail.Description() == "This refresh token has been revoked."
			})).Return().Once()

			endpoint.post(t, "grant_type=refresh_token&refresh_token=replayed")

			endpoint.assertExpectations(t)

			require.Len(t, logged, 1, "exactly one replay event must be emitted")
			assert.Equal(t, map[string]interface{}{
				"presented_refresh_token_jti": presentedJti,
				"first_refresh_token_jti":     familyJti,
				"revoked_count":               int64(2),
				"client_id":                   clientId,
				"user_id":                     userId,
				"flow":                        tc.wantFlow,
			}, logged[0], "the replay payload must carry exactly these six fields")
		})
	}
}

// TestHandleTokenPost_Refresh_Replay_ContainmentErrorReturns500 pins that a failed
// containment is surfaced rather than swallowed, and that no event is emitted for it.
//
// Emitting on a failed containment would be worse than emitting nothing: the event's
// contract is that it records members actually revoked, and a failure revoked none. The issuer
// returns the failure itself rather than a RefreshTokenReplayedError, which issuance's
// TestIssueRefreshTokenGrant_AFailedContainmentIsAFault pins.
func TestHandleTokenPost_Refresh_Replay_ContainmentErrorReturns500(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	endpoint.validates(codeRefreshGrant(true))

	failure := oauth.NewErrorDetailWithHTTPStatus("server_error", "Failed to contain family", http.StatusInternalServerError)
	endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil, failure).Once()
	endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, failure).Return().Once()

	endpoint.post(t, "grant_type=refresh_token&refresh_token=replayed")

	endpoint.assertExpectations(t)
	// No event, and no invalid_grant either: the request did not get a clean refusal,
	// it got a server error.
	endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	endpoint.jsonWriter.AssertNumberOfCalls(t, "JSONError", 1)
}

// TestHandleTokenPost_ScopeNormalizationWiring proves the handler normalizes the scope with
// oidc.NormalizeScope and passes its OUTPUT to the validator, which oidc's own whitespace table
// cannot show. That table is where the rule is pinned; the rows here are the consumer's (#116).
//
// The validator is mocked with mock.MatchedBy so the scope it receives is captured rather than
// merely type-checked. Every accepting row returns a validation error afterwards, because what is
// under test is the input handed over, not what happens next.
//
// It is also the handler's consumer test for oidc.GrantType.ReadsScope, whose rows are pinned in
// oidc's grant table test: the three refusing rows (client_credentials, refresh_token, password)
// and the authorization_code row that must pass the malformed scope through (#437).
func TestHandleTokenPost_ScopeNormalizationWiring(t *testing.T) {
	// omittedScope distinguishes "no scope parameter in the form" from "scope=<something>".
	const omittedScope = "\x00omitted\x00"

	testCases := []struct {
		name      string
		grantType string
		rawScope  string
		// wantScope is what the validator must receive. Only read when wantValidatorCalled.
		wantScope           string
		wantValidatorCalled bool
	}{
		{
			name:                "one space between two scopes reaches the validator unchanged",
			grantType:           "client_credentials",
			rawScope:            "billing-api:read billing-api:write",
			wantScope:           "billing-api:read billing-api:write",
			wantValidatorCalled: true,
		},
		{
			// The space alone separates (#244): a tab is part of the value it sits in, so the scope
			// is one value, which the validator then refuses as an unknown scope. It used to be
			// collapsed to two.
			name:                "a tab is not a separator, so one joined value reaches the validator",
			grantType:           "client_credentials",
			rawScope:            "billing-api:read\tbilling-api:write",
			wantScope:           "billing-api:read\tbilling-api:write",
			wantValidatorCalled: true,
		},
		{
			name:                "a duplicate scope is dropped",
			grantType:           "client_credentials",
			rawScope:            "billing-api:read billing-api:read",
			wantScope:           "billing-api:read",
			wantValidatorCalled: true,
		},
		{
			// Nothing is trimmed (#244): a U+00A0 after a single space stays on its element, where
			// #116's splitter trimmed it off.
			name:                "a U+00A0 after a space is kept with its element",
			grantType:           "refresh_token",
			rawScope:            "billing-api:read \u00a0billing-api:write",
			wantScope:           "billing-api:read \u00a0billing-api:write",
			wantValidatorCalled: true,
		},
		// RFC 6749 3.3's grammar allows one space between two scopes and none at either end, so
		// each of these is refused as malformed before the validator, for every grant that reads
		// the scope. Each used to be collapsed or trimmed and handed on (#244).
		{
			name:                "surrounding spaces are refused before the validator, client credentials",
			grantType:           "client_credentials",
			rawScope:            "  billing-api:read  ",
			wantValidatorCalled: false,
		},
		{
			name:                "a run of spaces is refused before the validator, refresh",
			grantType:           "refresh_token",
			rawScope:            "billing-api:read  billing-api:write",
			wantValidatorCalled: false,
		},
		{
			name:                "a trailing space is refused before the validator, ROPC",
			grantType:           "password",
			rawScope:            "openid ",
			wantValidatorCalled: false,
		},
		{
			name:                "whitespace-only is rejected before the validator, client credentials",
			grantType:           "client_credentials",
			rawScope:            "   ",
			wantValidatorCalled: false,
		},
		{
			name:                "whitespace-only is rejected before the validator, refresh",
			grantType:           "refresh_token",
			rawScope:            "   ",
			wantValidatorCalled: false,
		},
		{
			// Accept-to-reject change. ROPC currently treats a whitespace-only scope as absent and
			// issues an "openid" token, so this row is the one behaviour regression the
			// normalization work introduces, on a deprecated grant receiving malformed input.
			name:                "whitespace-only is rejected before the validator, ROPC",
			grantType:           "password",
			rawScope:            "   ",
			wantValidatorCalled: false,
		},
		{
			// LOAD-BEARING: fails if someone applies the rejection to every grant type. The
			// authorization code grant never reads the scope parameter, so a malformed one must be
			// ignored rather than break an otherwise valid exchange.
			name:                "whitespace-only is ignored for the authorization code grant",
			grantType:           "authorization_code",
			rawScope:            "   ",
			wantScope:           "",
			wantValidatorCalled: true,
		},
		{
			// LOAD-BEARING: fails if someone implements the rejection as "empty scope is invalid"
			// rather than "provided-but-empty is invalid". An omitted scope must still reach the
			// validator as "", which is what selects the client credentials all-permissions branch.
			name:                "an omitted scope still reaches the validator as empty",
			grantType:           "client_credentials",
			rawScope:            omittedScope,
			wantScope:           "",
			wantValidatorCalled: true,
		},
		{
			// LOAD-BEARING, and distinct from the row above: this one encodes an explicitly empty
			// `scope=` in the form body, which is a DIFFERENT wire format from omitting the
			// parameter even though PostForm.Get returns "" for both. Verified: Set("scope", "")
			// encodes as `scope=`, where Has("scope") is true and Get("scope") is "".
			//
			// Decision 15 and the release note both promise `scope=` keeps working, because plenty
			// of HTTP clients serialize empty values and rejecting them would break integrations
			// for no security gain. Switching the rejection's presence test to PostForm.Has would
			// honour omission while newly rejecting this, and the row above would not notice. Do
			// not merge these two rows.
			name:                "an explicitly empty scope= is treated as omitted",
			grantType:           "client_credentials",
			rawScope:            "",
			wantScope:           "",
			wantValidatorCalled: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonWriter := handlersmocks.NewJSONWriter(t)
			database := datamocks.NewDatabase(t)
			tokenIssuer := handlersmocks.NewTokenIssuer(t)
			tokenValidator := handlersmocks.NewTokenValidator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			handler := HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())

			form := url.Values{"grant_type": {tc.grantType}, "client_id": {"test_client"}}
			if tc.rawScope != omittedScope {
				form.Set("scope", tc.rawScope)
			}

			req, _ := http.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req = withSettings(req, &record.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			if tc.wantValidatorCalled {
				// Capture what the handler passed. Returning an error keeps the test focused on
				// the input rather than on downstream token issuance.
				validationError := oauth.NewErrorDetailWithHTTPStatus("invalid_request",
					"stop here", http.StatusBadRequest)
				tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.MatchedBy(
					func(input *protocolvalidation.ValidateTokenRequestInput) bool {
						return input.Scope == tc.wantScope
					})).Return(nil, validationError).Once()
				jsonWriter.On("JSONError", rr, req, validationError).Return()

				handler.ServeHTTP(rr, req)

				// AssertExpectations is what proves the scope matched: an input whose Scope differed
				// would not satisfy MatchedBy, so the expectation would go unmet.
				tokenValidator.AssertExpectations(t)
				jsonWriter.AssertExpectations(t)
				return
			}

			// Rejected before the validator runs. handlersmocks.NewTokenValidator(t) fails the
			// test if ValidateTokenRequest is called with no expectation registered, so registering
			// none is the assertion that it was not reached.
			var rejection *oauth.ErrorDetail
			jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*oauth.ErrorDetail)
				if !ok {
					return false
				}
				rejection = detail
				return true
			})).Return()

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
			if assert.NotNil(t, rejection, "the handler should have rejected the request") {
				assert.Equal(t, "invalid_scope", rejection.Code())
				assert.Equal(t, http.StatusBadRequest, rejection.HTTPStatus())
				assert.Equal(t, "The 'scope' parameter is malformed. Separate its values with a single space, with no space before the first value or after the last.",
					rejection.Description())
			}
		})
	}
}

// TestHandleTokenPost_ScopeDenialAudit covers the audit half of the #104 work.
//
// Before this, a successful client credentials issuance logged only clientId, so there was no
// record of which scopes were granted to whom, and a denial logged nothing at all. Exploitation of
// the cross-resource escalation therefore cannot be reconstructed for any period before the fix.
//
// Deliberately thin on WHICH requests are denied, since stage 1's validator table owns that. What
// these four cases pin is that a denial reaches the audit logger, that the predicate is not gated on
// grant type, and that there is exactly one call site.
func TestHandleTokenPost_ScopeDenialAudit(t *testing.T) {
	newHandler := func(t *testing.T) (*handlersmocks.JSONWriter, *handlersmocks.TokenValidator,
		*handlersmocks.TokenIssuer, *handlersmocks.AuditLogger, http.HandlerFunc) {
		t.Helper()
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)
		tokenIssuer := handlersmocks.NewTokenIssuer(t)
		tokenValidator := handlersmocks.NewTokenValidator(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		return jsonWriter, tokenValidator, tokenIssuer, auditLogger,
			HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())
	}

	// Rows 1 and 2 differ ONLY in grant type. Row 2 fails if a GrantType check is ever added to the
	// predicate, which would leave ROPC scope probing unlogged despite being the identical signal.
	// Row 3 is the refresh arm's request for a scope beyond its grant, which answered invalid_grant
	// and went unaudited until #425 gave it invalid_scope; the audited scope is the request's, not
	// the grant's.
	for _, tc := range []struct {
		name        string
		grantType   string
		form        string
		description string
		wantScope   string
	}{
		{
			name:        "client credentials scope denial is audited",
			grantType:   "client_credentials",
			form:        "grant_type=client_credentials&client_id=test_client&client_secret=s&scope=reports-api:read",
			description: "Permission to access scope 'reports-api:read' is not granted to the client.",
			wantScope:   "reports-api:read",
		},
		{
			name:        "ROPC scope denial is audited too",
			grantType:   "password",
			form:        "grant_type=password&client_id=test_client&username=u&password=p&scope=reports-api:read",
			description: "Permission to access scope 'reports-api:read' is not granted to the client.",
			wantScope:   "reports-api:read",
		},
		{
			name:        "a refresh asking beyond its grant is audited",
			grantType:   "refresh_token",
			form:        "grant_type=refresh_token&client_id=test_client&client_secret=s&refresh_token=rt&scope=openid+reports-api:read",
			description: "Scope 'reports-api:read' is not recognized. The original access token does not grant the 'reports-api:read' permission.",
			wantScope:   "openid reports-api:read",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jsonWriter, tokenValidator, _, auditLogger, handler := newHandler(t)

			req, _ := http.NewRequest("POST", "/token", strings.NewReader(tc.form))
			req = withSettings(req, &record.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			denial := oauth.NewErrorDetailWithHTTPStatus("invalid_scope", tc.description,
				http.StatusBadRequest)
			tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything,
				mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(nil, denial)

			auditLogger.On("Log", mock.Anything, audit.EventTokenScopeDenied, mock.MatchedBy(
				func(details map[string]interface{}) bool {
					return details["client_identifier"] == "test_client" &&
						details["grant_type"] == tc.grantType &&
						details["scope"] == tc.wantScope
				})).Return()

			jsonWriter.On("JSONError", rr, req, denial).Return()

			handler.ServeHTTP(rr, req)

			auditLogger.AssertExpectations(t)
			jsonWriter.AssertExpectations(t)
		})
	}

	// Row 3 asserts the ABSENCE of an event, which looks like an oversight and is not: it is the
	// guard against reintroducing an unauthenticated audit row. The provided-but-empty rejection
	// fires before the client is authenticated, so auditing it would let anyone forge rows against a
	// legitimate client. A second call site there passes every other row and fails only this one.
	t.Run("the provided-but-empty rejection emits no audit event", func(t *testing.T) {
		jsonWriter, tokenValidator, _, auditLogger, handler := newHandler(t)

		form := url.Values{
			"grant_type": {"client_credentials"},
			"client_id":  {"test_client"},
			"scope":      {"   "},
		}
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		var rejection *oauth.ErrorDetail
		jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
			detail, ok := err.(*oauth.ErrorDetail)
			if !ok {
				return false
			}
			rejection = detail
			return true
		})).Return()

		// No auditLogger expectation is registered, and none is registered on the validator either.
		// handlersmocks.NewAuditLogger(t) fails the test if Log is called without a matching
		// expectation, so registering nothing IS the assertion.
		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		tokenValidator.AssertNotCalled(t, "ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything)
		if assert.NotNil(t, rejection) {
			assert.Equal(t, "invalid_scope", rejection.Code())
		}
	})

	// Row 4: the forensic field on the success path. Nothing asserted this payload's shape before.
	t.Run("successful issuance records the scope", func(t *testing.T) {
		jsonWriter, tokenValidator, tokenIssuer, auditLogger, handler := newHandler(t)

		form := "grant_type=client_credentials&client_id=test_client&client_secret=s&scope=billing-api:read"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockClient := &record.Client{Id: 42, ClientIdentifier: "test_client"}
		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything,
			mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(&protocolvalidation.ClientCredentialsGrant{Client: mockClient, Scope: "billing-api:read"}, nil)

		tokenResponse := &oauth.TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600}
		tokenIssuer.On("IssueClientCredentialsGrant", req.Context(), mock.Anything, mockClient, "billing-api:read").
			Return(tokenResponse, nil)

		auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedClientCredentialsResponse, mock.MatchedBy(
			func(details map[string]interface{}) bool {
				clientId, ok := details["client_id"].(int64)
				return ok && clientId == mockClient.Id && details["scope"] == "billing-api:read"
			})).Return()

		jsonWriter.On("EncodeJSON", rr, req, tokenResponse).Return()

		handler.ServeHTTP(rr, req)

		auditLogger.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		jsonWriter.AssertExpectations(t)
	})
}

// TestHandleTokenPost_ROPC_IgnoresBrowserSession pins that the HANDLER never forwards a
// session identifier from the request into a password grant.
//
// Scope note: the token issuer is mocked here, so this proves the handoff and nothing about
// the tokens themselves. That neither generated token carries a sid is proven separately, in
// issuance's TestIssuePasswordGrant_* and TestMintROPCRefreshTokens cases.
// Neither half substitutes for the other.
//
// This closes a real leak rather than guarding a hypothetical. middleware.SessionIdentifier
// is mounted globally with router.Use, so a browser cookie's session lands in the request
// context even on /auth/token. The handler used to copy that into ROPCGrantInput, and the
// shared ROPC input builder forwarded it into ID-token generation. A password grant for
// user B, made while the browser happened to be logged in as user A, therefore received an
// ID token carrying A's session identifier.
//
// The fix was structural: ROPCGrantInput no longer has the field, so this test asserts the
// handler builds an input the type cannot even express a session on, with a session
// identifier deliberately present in the context to prove it is ignored rather than merely
// absent (#106).
func TestHandleTokenPost_ROPC_IgnoresBrowserSession(t *testing.T) {
	jsonWriter := handlersmocks.NewJSONWriter(t)
	database := datamocks.NewDatabase(t)
	tokenIssuer := handlersmocks.NewTokenIssuer(t)
	tokenValidator := handlersmocks.NewTokenValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)
	handler := HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())

	form := "grant_type=password&client_id=test_client&username=u&password=p&scope=openid"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
	req = withSettings(req, &record.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// A DIFFERENT user's browser session, present exactly as the global middleware would
	// leave it. Nothing in a password grant may consume this.
	req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), "some-other-users-browser-session"))
	rr := httptest.NewRecorder()

	client := &record.Client{Id: 1, ClientIdentifier: "test_client"}
	user := &record.User{Id: 42, Subject: fake.UUID(), AuthStateGeneration: 7}

	tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
		mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(&protocolvalidation.PasswordGrant{Client: client, User: user, Scope: "openid"}, nil)

	var captured *issuance.ROPCGrantInput
	tokenIssuer.On("IssuePasswordGrant", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(2).(*issuance.ROPCGrantInput) }).
		Return(&oauth.TokenResponse{AccessToken: "at", TokenType: "Bearer"}, nil)

	auditLogger.On("Log", mock.Anything, audit.EventTokenIssuedROPCResponse, mock.Anything).Return()
	jsonWriter.On("EncodeJSON", rr, mock.Anything, mock.Anything).Return()

	handler.ServeHTTP(rr, req)

	require.NotNil(t, captured, "IssuePasswordGrant was never called")
	assert.Equal(t, client, captured.Client)
	assert.Equal(t, user, captured.User)
	// The generation travels on the validated User snapshot, which is what the issuer stamps
	// initial ROPC tokens from (#106 decision 13).
	assert.EqualValues(t, 7, captured.User.AuthStateGeneration)
}

// TestHandleTokenPost_SupersededRefreshTokenIsSurfaced is the handler-layer smoke case for
// the generation boundary (#106 stage 3). Deliberately thin: the comparison logic is owned
// exhaustively by TestValidateTokenRequest_AuthStateGeneration in the validator package, and
// the validator is a mock here, so this can only show that the handler passes the rejection
// through to the client rather than swallowing it or turning it into a 500.
//
// It also pins that neither audit branch fires. The generation rejection is invalid_grant,
// which is not a UserDisabledError and not invalid_scope, so a superseded refresh token must not
// be recorded as either. Stage 5 adds the event that does cover this.
func TestHandleTokenPost_SupersededRefreshTokenIsSurfaced(t *testing.T) {
	jsonWriter := handlersmocks.NewJSONWriter(t)
	database := datamocks.NewDatabase(t)
	tokenIssuer := handlersmocks.NewTokenIssuer(t)
	tokenValidator := handlersmocks.NewTokenValidator(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())

	formData := "grant_type=refresh_token&refresh_token=superseded&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &record.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// The exact error the validator's refresh grant returns on a generation mismatch.
	supersededErr := oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
		"The refresh token is invalid because it was superseded.", http.StatusBadRequest)

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(nil, supersededErr)

	jsonWriter.On("JSONError", rr, req, supersededErr).Return().Once()

	handler.ServeHTTP(rr, req)

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleTokenPost_ROPC_SpendsTheLimiterBudgetOnInvalidGrantOnly is seam 2 for the
// password grant: the handler driven through a real middleware.RateLimiter, so what is
// asserted is the limiter's own observable behaviour rather than a spy reporting that a
// method was called.
//
// Through the middleware rather than directly, and this is the point of the case. The
// reservation the handler converts is placed by the limiter and lives in the request
// context, so a handler invoked on a bare request has nothing to convert and
// RecordCredentialFailure is a no-op. A case written that way passes while proving nothing.
//
// The budgets and keys are pinned at seam 1 in authserver/internal/middleware. What is new here is the
// predicate: which of the validator's failures is a guess against an account, and which is
// not. Charging one of the others would let a caller spend an account's budget, shared with
// the browser password form, without ever guessing a password (#219).
func TestHandleTokenPost_ROPC_SpendsTheLimiterBudgetOnInvalidGrantOnly(t *testing.T) {
	const tightBudget = 10 // failures per 15 minutes per (account, client block)
	const username = "victim@example.com"

	// newHandler wires one handler behind its own limiter, the way routes.go does. failure
	// is what ValidateTokenRequest answers every time; nil means the grant succeeds.
	newHandler := func(t *testing.T, failure error) (http.Handler, *handlersmocks.AuditLogger) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)
		tokenIssuer := handlersmocks.NewTokenIssuer(t)
		tokenValidator := handlersmocks.NewTokenValidator(t)
		auditLogger := handlersmocks.NewAuditLogger(t)

		if failure != nil {
			tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
				Return(nil, failure)
			jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.Anything).Return()
		} else {
			client := &record.Client{Id: 1, ClientIdentifier: "app"}
			user := &record.User{Id: 42, Subject: fake.UUID()}
			tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
				Return(&protocolvalidation.PasswordGrant{Client: client, User: user, Scope: "openid"}, nil)
			tokenIssuer.On("IssuePasswordGrant", mock.Anything, mock.Anything, mock.Anything).
				Return(&oauth.TokenResponse{AccessToken: "at", TokenType: "Bearer"}, nil)
			jsonWriter.On("EncodeJSON", mock.Anything, mock.Anything, mock.Anything).Return()
		}
		auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		rateLimiter := newTestRateLimiter(nil)
		handler := HandleTokenPost(jsonWriter, database, tokenIssuer,
			tokenValidator, auditLogger, rateLimiter, testTokenMetrics())
		return rateLimiter.LimitROPC(handler), auditLogger
	}

	// post submits one password grant from a fixed host and reports the status. A refusal
	// is the limiter's 429; anything the handler answers leaves the recorder's default 200,
	// since JSONError and EncodeJSON are mocks that write nothing.
	post := func(handler http.Handler) int {
		form := url.Values{
			"grant_type": {"password"},
			"client_id":  {"app"},
			"username":   {username},
			"password":   {"guess"},
		}
		req, _ := http.NewRequest("POST", "/auth/token", strings.NewReader(form.Encode()))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:5000"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	// spends drives the budget and reports whether the attempt past it was refused, which
	// is the only observable difference between a failure that was charged and one that
	// was not.
	spends := func(t *testing.T, failure error) bool {
		t.Helper()
		handler, _ := newHandler(t, failure)
		for i := 0; i < tightBudget; i++ {
			if code := post(handler); code != http.StatusOK {
				t.Fatalf("attempt %d: got code %d, want it to reach the handler", i+1, code)
			}
		}
		return post(handler) == http.StatusTooManyRequests
	}

	invalidGrant := oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
		"Invalid resource owner credentials.", http.StatusBadRequest)

	t.Run("invalid_grant fills the budget and the next attempt gets the oauth 429", func(t *testing.T) {
		handler, _ := newHandler(t, invalidGrant)
		for i := 0; i < tightBudget; i++ {
			assert.Equal(t, http.StatusOK, post(handler), "attempt %d should reach the handler", i+1)
		}
		assert.Equal(t, http.StatusTooManyRequests, post(handler),
			"attempt %d should be refused by the limiter", tightBudget+1)
	})

	t.Run("invalid_grant emits ropc_auth_failed, with the account and the client named", func(t *testing.T) {
		handler, auditLogger := newHandler(t, invalidGrant)
		assert.Equal(t, http.StatusOK, post(handler))
		// Declared since the grant was written and never fired until now (#126).
		auditLogger.AssertCalled(t, "Log", mock.Anything, audit.EventROPCAuthFailed, map[string]interface{}{
			"email":             username,
			"client_identifier": "app",
		})
	})

	t.Run("the recorded address is normalized, so it names the bucket the limiter keyed", func(t *testing.T) {
		handler, auditLogger := newHandler(t, invalidGrant)
		form := url.Values{
			"grant_type": {"password"},
			"client_id":  {"app"},
			"username":   {"  Victim@Example.COM "},
			"password":   {"guess"},
		}
		req, _ := http.NewRequest("POST", "/auth/token", strings.NewReader(form.Encode()))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:5000"
		handler.ServeHTTP(httptest.NewRecorder(), req)
		auditLogger.AssertCalled(t, "Log", mock.Anything, audit.EventROPCAuthFailed, map[string]interface{}{
			"email":             username,
			"client_identifier": "app",
		})
	})

	// A disabled user is refused through UserDisabledError, whose detail is still the plain
	// invalid_grant the predicate charges: the password was compared, so this is a guess against
	// the account, and the wrapper must not hide the detail from it (#137).
	t.Run("a disabled user spends the budget and emits both user_disabled and ropc_auth_failed", func(t *testing.T) {
		disabled := &protocolvalidation.UserDisabledError{Detail: oauth.NewErrorDetailWithHTTPStatus(
			"invalid_grant", "The user account is disabled.", http.StatusBadRequest)}
		assert.True(t, spends(t, disabled), "a disabled user's refusal compared the password, so it is charged")

		handler, auditLogger := newHandler(t, disabled)
		assert.Equal(t, http.StatusOK, post(handler))
		auditLogger.AssertCalled(t, "Log", mock.Anything, audit.EventUserDisabled, map[string]interface{}{
			"client_identifier": "app",
		})
		auditLogger.AssertCalled(t, "Log", mock.Anything, audit.EventROPCAuthFailed, map[string]interface{}{
			"email":             username,
			"client_identifier": "app",
		})
	})

	// The three error codes that are not a guess against the account. Each names the gate that
	// must not charge it.
	notCharged := []struct {
		name string
		err  error
	}{
		{"unauthorized_client, the grant is switched off for this client",
			oauth.NewErrorDetailWithHTTPStatus("unauthorized_client",
				"The client is not authorized to use the resource owner password credentials grant type.",
				http.StatusBadRequest)},
		{"invalid_request, a parameter is missing",
			oauth.NewErrorDetailWithHTTPStatus("invalid_request",
				"Missing required password parameter.", http.StatusBadRequest)},
		{"invalid_client, the client failed to authenticate",
			oauth.NewErrorDetailWithHTTPStatus("invalid_client",
				"Client authentication failed.", http.StatusUnauthorized)},
		// Before #437 this was invalid_grant and needed an exclusion by value of its own (#219).
		{"invalid_client, the client is disabled and no credential was read",
			protocolvalidation.NewErrorDetailWithHTTPStatusAndWWWAuthenticate("invalid_client",
				"Client is disabled.", http.StatusUnauthorized, protocolvalidation.BasicChallenge)},
	}
	for _, tc := range notCharged {
		t.Run(tc.name+" spends nothing", func(t *testing.T) {
			assert.False(t, spends(t, tc.err),
				"this failure compared no credential against %s, so it must not spend the account's budget", username)
		})
		t.Run(tc.name+" emits no ropc_auth_failed", func(t *testing.T) {
			handler, auditLogger := newHandler(t, tc.err)
			assert.Equal(t, http.StatusOK, post(handler))
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventROPCAuthFailed, mock.Anything)
		})
	}

	t.Run("a successful grant spends nothing", func(t *testing.T) {
		handler, auditLogger := newHandler(t, nil)
		// Well past the budget. A tier that counted every request would refuse the 11th,
		// which is a machine-driven integration throttled for authenticating successfully.
		for i := 0; i < 25; i++ { // under ropc_ip's 30, which counts every request
			assert.Equal(t, http.StatusOK, post(handler), "grant %d should succeed", i+1)
		}
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventROPCAuthFailed, mock.Anything)
	})
}

// theseSettings matches the very settings value a test put on its request, by identity, so a
// handler that built its own or read another request's would match nothing.
func theseSettings(want *record.Settings) interface{} {
	return mock.MatchedBy(func(got *record.Settings) bool { return got == want })
}

// withSettings puts resolved settings on a request, as the settings middleware does.
func withSettings(req *http.Request, settings *record.Settings) *http.Request {
	return req.WithContext(reqctx.WithSettings(req.Context(), settings))
}

// TestHandleTokenPost_Refresh_FlowDisabledAnswer pins the answer to a refresh the issuer refused
// because the flow that minted its token is switched off for the client (#250): unauthorized_client,
// worded for that flow. The truth table of when the gate refuses, and that it sits below containment
// and above the claim, is the issuer's: issuance's TestIssueRefreshTokenGrant_FlowGate and
// TestIssueRefreshTokenGrant_ContainmentPrecedesTheFlowGate.
func TestHandleTokenPost_Refresh_FlowDisabledAnswer(t *testing.T) {
	for _, tc := range []struct {
		name        string
		grant       *protocolvalidation.RefreshTokenGrant
		wantRefusal string
	}{
		// The refusal the password grant itself answers, so an operator reads one story about
		// turning ROPC off.
		{"a password grant's token", ropcRefreshGrant(false), protocolvalidation.ROPCNotAuthorizedErrorMsg},
		// The authorization code half keeps the refusal it had, word for word.
		{"an authorization code's token", codeRefreshGrant(false), authCodeNotAuthorizedErrorMsg},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			endpoint.validates(tc.grant)

			endpoint.issuer.On("IssueRefreshTokenGrant", mock.Anything, mock.Anything, mock.Anything).
				Return(nil, nil, issuance.ErrRefreshFlowDisabled).Once()
			endpoint.jsonWriter.On("JSONError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*oauth.ErrorDetail)
				return ok && detail.Code() == "unauthorized_client" &&
					detail.Description() == tc.wantRefusal &&
					detail.HTTPStatus() == http.StatusBadRequest
			})).Return().Once()

			endpoint.post(t, "grant_type=refresh_token&refresh_token=live")

			endpoint.assertExpectations(t)
			// The gate is not containment: nothing is audited.
			endpoint.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestHandleTokenPost_RedemptionRegistrationRefusalAudit covers the handler half of #241 decision
// 10: a code refused because its own redirect URI was deregistered has to reach the audit logger,
// because the admin console and GET /api/v1/admin/audit-logs are the surfaces an operator can ask
// "did pulling that callback stop anything" on. A server log line is not one of them.
//
// Thin on WHICH redemptions are refused, since the validator's own table owns that. What these two
// cases pin is the discrimination, which is the whole of decision 8's name-not-payload rule: the
// event fires on the sentinel and on nothing else that carries invalid_grant.
func TestHandleTokenPost_RedemptionRegistrationRefusalAudit(t *testing.T) {
	newHandler := func(t *testing.T) (*handlersmocks.JSONWriter, *handlersmocks.TokenValidator,
		*handlersmocks.AuditLogger, http.HandlerFunc) {
		t.Helper()
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)
		tokenIssuer := handlersmocks.NewTokenIssuer(t)
		tokenValidator := handlersmocks.NewTokenValidator(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		return jsonWriter, tokenValidator, auditLogger,
			HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{}, testTokenMetrics())
	}

	const form = "grant_type=authorization_code&client_id=test_client&client_secret=s&" +
		"code=the_code&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"

	t.Run("a deregistered redirect URI on the code is audited", func(t *testing.T) {
		jsonWriter, tokenValidator, auditLogger, handler := newHandler(t)

		req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		refusal := protocolvalidation.ErrCodeRedirectURIDeregistered
		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything,
			mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(nil, refusal)

		auditLogger.On("Log", mock.Anything, audit.EventRedemptionRefusedRedirectURI, mock.MatchedBy(
			func(details map[string]interface{}) bool {
				// client_identifier, the request's string, matching the neighbouring events.
				// Unlike EventTokenScopeDenied's it has been PROVED rather than asserted: this
				// refusal is reachable only below client authentication and PKCE.
				return details["client_identifier"] == "test_client"
			})).Return()

		jsonWriter.On("JSONError", rr, req, mock.Anything).Return()

		handler.ServeHTTP(rr, req)

		auditLogger.AssertExpectations(t)
	})

	t.Run("an ordinary invalid_grant refusal emits no registration event", func(t *testing.T) {
		// The ABSENCE case, and it is the point of the whole test. The validator answers a
		// revoked code, a superseded generation, a cross-bound session and a submitted URI that
		// differs from the code's all with invalid_grant, so a predicate keyed on the error CODE
		// rather than matched by value against the sentinel would name every one of them a
		// deregistration. This row is what fails if somebody makes that simplification. Note the
		// strict mockery double: an unexpected Log call fails the test on its own.
		jsonWriter, tokenValidator, _, handler := newHandler(t)

		req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		refusal := oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
			"Code is invalid.", http.StatusBadRequest)
		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything,
			mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(nil, refusal)

		jsonWriter.On("JSONError", rr, req, mock.Anything).Return()

		handler.ServeHTTP(rr, req)
	})
}
