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

	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"

	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
	"github.com/leodip/goiabada/core/customerrors"
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
				jsonWriter := mocks_handlers.NewJSONWriter(t)
				database := mocks_data.NewDatabase(t)
				handler := HandleTokenPost(jsonWriter, mocks_handlers.NewUserSessionManager(t), database,
					mocks_handlers.NewTokenIssuer(t), mocks_handlers.NewTokenValidator(t),
					mocks_handlers.NewAuditLogger(t), noCredentialFailures{})

				rr := httptest.NewRecorder()
				req, _ := http.NewRequest("POST", "/token", test.body(rr))
				req = withSettings(req, &models.Settings{})
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
					detail, ok := err.(*customerrors.ErrorDetail)
					return ok && detail.GetCode() == "invalid_request" &&
						detail.GetHttpStatusCode() == http.StatusBadRequest &&
						detail.GetDescription() == "The request body could not be parsed."
				})).Return().Once()

				handler.ServeHTTP(rr, req)

				jsonWriter.AssertExpectations(t)
				database.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
			})
		}

		// The accept side of the limit: the same form under a limit equal to its length is read
		// whole, and every field of it reaches the validator.
		t.Run("the same body at exactly the limit", func(t *testing.T) {
			refused := customerrors.NewErrorDetailWithHttpStatusCode("invalid_client", "Client authentication failed.", http.StatusUnauthorized)
			tokenValidator := mocks_handlers.NewTokenValidator(t)
			tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.MatchedBy(func(input *protocolvalidation.ValidateTokenRequestInput) bool {
				return input.GrantType == "client_credentials" && input.ClientId == "a-client" && input.ClientSecret == "a-secret"
			})).Return(nil, refused).Once()
			jsonWriter := mocks_handlers.NewJSONWriter(t)

			handler := HandleTokenPost(jsonWriter, mocks_handlers.NewUserSessionManager(t), mocks_data.NewDatabase(t),
				mocks_handlers.NewTokenIssuer(t), tokenValidator, mocks_handlers.NewAuditLogger(t), noCredentialFailures{})

			rr := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/token",
				http.MaxBytesReader(rr, io.NopCloser(strings.NewReader(form)), int64(len(form))))
			req = withSettings(req, &models.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*customerrors.ErrorDetail)
				return ok && detail.GetCode() == "invalid_client"
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
			tokenValidator.AssertExpectations(t)
		})

		// With the ROPC limiter on, its own ParseForm meets the cut body first and passes the
		// request through, and net/http leaves an empty form behind for the handler's. The real
		// validator answers that empty form, which names no client.
		t.Run("a body cut before the handler, as the ROPC limiter leaves it", func(t *testing.T) {
			jsonWriter := mocks_handlers.NewJSONWriter(t)
			database := mocks_data.NewDatabase(t)
			handler := HandleTokenPost(jsonWriter, mocks_handlers.NewUserSessionManager(t), database,
				mocks_handlers.NewTokenIssuer(t), protocolvalidation.NewTokenValidator(database, nil, nil, testDataCipher),
				mocks_handlers.NewAuditLogger(t), noCredentialFailures{})

			rr := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/token",
				http.MaxBytesReader(rr, io.NopCloser(strings.NewReader(form)), int64(len(form)-1)))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = req.WithContext(reqctx.WithSettings(req.Context(), &models.Settings{Id: 1}))
			require.Error(t, req.ParseForm(), "the limiter's parse fails")

			jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*customerrors.ErrorDetail)
				return ok && detail.GetCode() == "invalid_request" &&
					detail.GetHttpStatusCode() == http.StatusBadRequest &&
					detail.GetDescription() == "Missing required client_id parameter."
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
		})
	})

	t.Run("ValidateTokenRequest gives error", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		validationError := customerrors.NewErrorDetailWithHttpStatusCode("invalid_request", "Validation error", http.StatusBadRequest)

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(nil, validationError)

		jsonWriter.On("JsonError", rr, req, validationError).Return()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
	})

	t.Run("Authorization_code GenerateTokenResponseForAuthCode gives error", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockCode := &models.Code{Id: 1, Used: false}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{CodeEntity: mockCode}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		// Code is claimed successfully, but token generation then fails.
		database.On("MarkCodeAsUsed", mock.Anything, (*sql.Tx)(nil), mockCode.Id).Return(true, nil)

		tokenIssuer.On("GenerateTokenResponseForAuthCode", req.Context(), mock.Anything, mockCode).
			Return(nil, customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to generate token", http.StatusInternalServerError))

		jsonWriter.On("JsonError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err *customerrors.ErrorDetail) bool {
				return err.GetCode() == "server_error" && err.GetDescription() == "Failed to generate token"
			})).
			Return().Once()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
	})

	t.Run("Authorization_code MarkCodeAsUsed gives error", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockCode := &models.Code{Id: 1, Used: false}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{CodeEntity: mockCode}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		// Claiming the code errors out. Tokens must NOT be generated.
		database.On("MarkCodeAsUsed", mock.Anything, (*sql.Tx)(nil), mockCode.Id).
			Return(false, customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to mark code as used", http.StatusInternalServerError))

		jsonWriter.On("JsonError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "Failed to mark code as used")
			}),
		).Return().Once()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		// Token generation must not happen when the claim fails.
		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForAuthCode", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Authorization_code successful flow", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=authorization_code&code=test_code&redirect_uri=http://example.com&client_id=test_client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockCode := &models.Code{Id: 1, Used: false}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{CodeEntity: mockCode}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken: "access_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		// Code is claimed atomically before minting; only the winner proceeds.
		database.On("MarkCodeAsUsed", mock.Anything, (*sql.Tx)(nil), mockCode.Id).Return(true, nil)

		tokenIssuer.On("GenerateTokenResponseForAuthCode", req.Context(), mock.Anything, mockCode).
			Return(mockTokenResponse, nil)

		auditLogger.On("Log", mock.Anything, "token_issued_authorization_code_response", mock.MatchedBy(func(details map[string]interface{}) bool {
			codeId, ok := details["codeId"].(int64)
			return ok && codeId == mockCode.Id
		})).Return()

		jsonWriter.On("EncodeJson", rr, req, mockTokenResponse).Return()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Client_credentials successful flow", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=client_credentials&client_id=test_client&client_secret=test_secret&scope=test_scope"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		// The validator and the issuer are both handed the request's own settings.
		requestSettings := &models.Settings{Issuer: "https://issuer.example"}
		req = withSettings(req, requestSettings)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test_client"}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{
			Client: mockClient,
			Scope:  "test_scope",
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), theseSettings(requestSettings), mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken: "access_token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		tokenIssuer.On("GenerateTokenResponseForClientCred", req.Context(), theseSettings(requestSettings), mockClient, "test_scope").
			Return(mockTokenResponse, nil)

		auditLogger.On("Log", mock.Anything, "token_issued_client_credentials_response", mock.MatchedBy(func(details map[string]interface{}) bool {
			clientId, ok := details["clientId"].(int64)
			return ok && clientId == mockClient.Id
		})).Return()

		jsonWriter.On("EncodeJson", rr, req, mockTokenResponse).Return()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))
	})

	t.Run("Refresh_token and token is revoked", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockRefreshToken := &models.RefreshToken{Id: 1, Revoked: true, FirstRefreshTokenJti: "family-1"}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{RefreshToken: mockRefreshToken}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		// Containment runs but finds nothing live, which is the idempotent no-op an
		// already-swept family produces. Zero count means no audit event (#128).
		database.On("RevokeRefreshTokenFamily", mock.Anything, (*sql.Tx)(nil), "family-1").Return(int64(0), nil)

		jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.(*customerrors.ErrorDetail).GetCode() == "invalid_grant" &&
				err.(*customerrors.ErrorDetail).GetDescription() == "This refresh token has been revoked."
		})).Return()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Refresh_token MarkRefreshTokenAsRevoked gives error", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = withSettings(req, &models.Settings{})
		rr := httptest.NewRecorder()

		mockRefreshToken := &models.RefreshToken{Id: 1, Revoked: false}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{
			Client:       authCodeClient(),
			RefreshToken: mockRefreshToken,
			CodeEntity:   &models.Code{},
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		database.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), int64(1)).
			Return(false, customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to claim refresh token", http.StatusInternalServerError))

		jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "Failed to claim refresh token")
		})).Return()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Refresh_token GenerateTokenResponseForRefresh gives error", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = withSettings(req, &models.Settings{})
		rr := httptest.NewRecorder()

		mockRefreshToken := &models.RefreshToken{Id: 1, Revoked: false}
		mockCode := &models.Code{Id: 1}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{
			Client:           authCodeClient(),
			RefreshToken:     mockRefreshToken,
			CodeEntity:       mockCode,
			RefreshTokenInfo: &oauth.JwtToken{},
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		database.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), int64(1)).
			Return(true, nil)

		tokenIssuer.On("GenerateTokenResponseForRefresh", req.Context(), mock.Anything, mock.AnythingOfType("*issuance.GenerateTokenForRefreshInput")).
			Return(nil, customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to generate token", http.StatusInternalServerError))

		jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "Failed to generate token")
		})).Return()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
	})

	t.Run("Refresh_token with SessionIdentifier bumps user session", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = withSettings(req, &models.Settings{})
		rr := httptest.NewRecorder()

		mockSessionIdentifier := "test_session_identifier"
		mockClientId := int64(123)
		mockUserId := int64(456)
		mockCodeId := int64(789)
		mockRefreshTokenJti := "test_jti"

		mockRefreshToken := &models.RefreshToken{
			Id:                1,
			Revoked:           false,
			SessionIdentifier: mockSessionIdentifier,
			RefreshTokenJti:   mockRefreshTokenJti,
			Code: models.Code{
				Id:       mockCodeId,
				ClientId: mockClientId,
			},
		}
		mockCode := &models.Code{Id: mockCodeId, ClientId: mockClientId}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{
			Client:           authCodeClient(),
			RefreshToken:     mockRefreshToken,
			CodeEntity:       mockCode,
			RefreshTokenInfo: &oauth.JwtToken{},
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		database.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), int64(1)).
			Return(true, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}
		tokenIssuer.On("GenerateTokenResponseForRefresh", req.Context(), mock.Anything, mock.AnythingOfType("*issuance.GenerateTokenForRefreshInput")).
			Return(mockTokenResponse, nil)

		mockUserSession := &models.UserSession{
			Id:     1,
			UserId: mockUserId,
		}
		// For refresh token flow, empty strings are passed (no step-up authentication)
		userSessionManager.On("BumpUserSession", mock.Anything, mockSessionIdentifier, mockClientId, "", models.AcrLevel(""), "").
			Return(mockUserSession, nil)

		auditLogger.On("Log", mock.Anything, audit.AuditBumpedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == mockUserId && details["clientId"] == mockClientId
		})).Return()

		auditLogger.On("Log", mock.Anything, audit.AuditTokenIssuedRefreshTokenResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["codeId"] == mockCodeId && details["refreshTokenJti"] == mockRefreshTokenJti
		})).Return()

		jsonWriter.On("EncodeJson", rr, req, mockTokenResponse).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		userSessionManager.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Refresh_token success path without session", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=refresh_token&refresh_token=test_refresh_token"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = withSettings(req, &models.Settings{})
		rr := httptest.NewRecorder()

		mockClientId := int64(123)
		mockCodeId := int64(789)
		mockRefreshTokenJti := "test_jti"

		mockRefreshToken := &models.RefreshToken{
			Id:              1,
			Revoked:         false,
			RefreshTokenJti: mockRefreshTokenJti,
			Code: models.Code{
				Id:       mockCodeId,
				ClientId: mockClientId,
			},
		}
		mockCode := &models.Code{Id: mockCodeId, ClientId: mockClientId}
		validationResult := &protocolvalidation.ValidateTokenRequestResult{
			Client:           authCodeClient(),
			RefreshToken:     mockRefreshToken,
			CodeEntity:       mockCode,
			RefreshTokenInfo: &oauth.JwtToken{},
		}

		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(validationResult, nil)

		database.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), int64(1)).
			Return(true, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}
		tokenIssuer.On("GenerateTokenResponseForRefresh", req.Context(), mock.Anything, mock.AnythingOfType("*issuance.GenerateTokenForRefreshInput")).
			Return(mockTokenResponse, nil)

		auditLogger.On("Log", mock.Anything, audit.AuditTokenIssuedRefreshTokenResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["codeId"] == mockCodeId && details["refreshTokenJti"] == mockRefreshTokenJti
		})).Return()

		jsonWriter.On("EncodeJson", rr, req, mockTokenResponse).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
		assert.Equal(t, "no-cache", rr.Header().Get("Pragma"))

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)

		// Ensure that BumpUserSession was not called
		userSessionManager.AssertNotCalled(t, "BumpUserSession",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Unsupported_grant_type", func(t *testing.T) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

		formData := "grant_type=unsupported_type&client_id=test_client&client_secret=test_secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		// Mock the ValidateTokenRequest to return a result (even though it's not used in this case)
		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(&protocolvalidation.ValidateTokenRequestResult{}, nil)

		// Expect a JSON error response for unsupported grant type
		jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			if customErr, ok := err.(*customerrors.ErrorDetail); ok {
				return customErr.GetCode() == "unsupported_grant_type" &&
					customErr.GetDescription() == "Unsupported grant_type." &&
					customErr.GetHttpStatusCode() == http.StatusBadRequest
			}
			return false
		})).Return()

		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		tokenValidator.AssertExpectations(t)

		// Ensure that other methods were not called
		database.AssertNotCalled(t, "UpdateRefreshToken", mock.Anything, mock.Anything, mock.Anything)
		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForAuthCode", mock.Anything, mock.Anything, mock.Anything)
		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForClientCred",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForRefresh", mock.Anything, mock.Anything, mock.Anything)
		userSessionManager.AssertNotCalled(t, "BumpUserSession",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})
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
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
		assert.True(t, usedBasicAuth)
	})

	t.Run("POST body only - credentials extracted from form", func(t *testing.T) {
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
		assert.False(t, usedBasicAuth)
	})

	t.Run("Both methods provided - returns error", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.Error(t, err)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
		assert.False(t, usedBasicAuth)

		errDetail, ok := err.(*customerrors.ErrorDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", errDetail.GetCode())
		assert.Contains(t, errDetail.GetDescription(), "multiple authentication methods")
	})

	t.Run("No credentials provided - returns empty values", func(t *testing.T) {
		formData := "grant_type=authorization_code&code=test"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
		assert.False(t, usedBasicAuth)
	})

	t.Run("Basic auth with client_id in POST but no client_secret - allowed", func(t *testing.T) {
		// This is allowed because only client_secret in POST triggers the conflict
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
		assert.True(t, usedBasicAuth)
	})

	t.Run("Invalid Basic auth header falls back to POST body", func(t *testing.T) {
		// Malformed Basic auth should be ignored, not cause an error
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic invalid-base64!")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
		assert.False(t, usedBasicAuth)
	})

	t.Run("Bearer token header does not interfere with POST body", func(t *testing.T) {
		// A Bearer token should not be treated as Basic auth
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer some-access-token")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
		assert.False(t, usedBasicAuth)
	})

	t.Run("Empty client_secret in POST body is not considered authentication", func(t *testing.T) {
		// Empty string for client_secret should not trigger the "multiple methods" error
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client&client_secret="
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
		assert.True(t, usedBasicAuth)
	})

	t.Run("Public client - only client_id in POST, no secret", func(t *testing.T) {
		formData := "grant_type=authorization_code&client_id=public-client&code=auth-code"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, usedBasicAuth, err := extractClientCredentials(req)
		assert.NoError(t, err)
		assert.Equal(t, "public-client", clientId)
		assert.Equal(t, "", clientSecret)
		assert.False(t, usedBasicAuth)
	})
}

// TestHandleTokenPost_AuthCodeReuse_RevokeFailureReturns500 verifies the
// failure path of the RFC 6749 §4.1.2 revocation flow: when the validator
// signals auth-code reuse but the transactional revoke fails, the handler
// MUST return 500 (not invalid_grant) so the client never sees a response
// that looks like a clean denial while linked tokens may still be live.
// It must also skip the audit log, which fires only after a successful commit.
func TestHandleTokenPost_AuthCodeReuse_RevokeFailureReturns500(t *testing.T) {
	jsonWriter := mocks_handlers.NewJSONWriter(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

	formData := "grant_type=authorization_code&code=replayed&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &models.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	reusedCode := &models.Code{
		Id:                42,
		ClientId:          7,
		UserId:            13,
		SessionIdentifier: "sid-reused",
	}
	reuseErr := &protocolvalidation.AuthCodeReusedError{
		Detail: customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", http.StatusBadRequest),
		Code:   reusedCode,
	}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(nil, reuseErr)

	stub := mocks_data.ExpectRunInTransaction(database, revokeTx)

	// The session row is taken first, ahead of the grants that hang off it (#139). Stubbed as
	// succeeding so this case still fails where it means to, at the token read below. Both reads
	// name revokeTx rather than nil, which is what says they happened inside the transaction:
	// until #422 this case expected (*sql.Tx)(nil), which a call made outside one also matches.
	database.On("AcquireUserSessionRow", mock.Anything, revokeTx, "sid-reused").
		Return(true, nil).Once()

	dbErr := errors.New("connection refused")
	database.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, "sid-reused").
		Return(nil, dbErr).Once()

	jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
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
	// The one JsonError call is the 500 matched above; a second would be the invalid_grant.
	jsonWriter.AssertNumberOfCalls(t, "JsonError", 1)
}

// TestHandleTokenPost_AuthCodeReuse_BeginTransactionFailureReturns500 covers
// the earliest failure point: BeginTransaction itself errors. The handler
// must still surface a 500 and skip both the audit log and the invalid_grant.
func TestHandleTokenPost_AuthCodeReuse_BeginTransactionFailureReturns500(t *testing.T) {
	jsonWriter := mocks_handlers.NewJSONWriter(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

	formData := "grant_type=authorization_code&code=replayed&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &models.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	reuseErr := &protocolvalidation.AuthCodeReusedError{
		Detail: customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", http.StatusBadRequest),
		Code: &models.Code{
			Id:                7,
			SessionIdentifier: "sid-reused",
		},
	}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(nil, reuseErr)

	beginErr := errors.New("tx begin failed")
	mocks_data.ExpectRunInTransactionRefused(database, beginErr)

	jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "tx begin failed")
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	jsonWriter.AssertNumberOfCalls(t, "JsonError", 1)
}

// TestHandleTokenPost_AuthCodeReuse_AuditsAfterTheCommit pins where the reuse audit row falls: after
// revocation.RevokeOnAuthCodeReuseTx has committed, and before the invalid_grant answer. The order
// is not cosmetic. AuditLogger.Log writes on a nil transaction, and on SQLite the whole process
// shares the one connection the reuse transaction holds, so an audit written inside it would wait
// on itself; and a row written before a commit that then failed would list JTIs never revoked.
func TestHandleTokenPost_AuthCodeReuse_AuditsAfterTheCommit(t *testing.T) {
	jsonWriter := mocks_handlers.NewJSONWriter(t)
	database := mocks_data.NewDatabase(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, mocks_handlers.NewUserSessionManager(t), database,
		mocks_handlers.NewTokenIssuer(t), tokenValidator, auditLogger, noCredentialFailures{})

	formData := "grant_type=authorization_code&code=replayed&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &models.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	reuseErr := &protocolvalidation.AuthCodeReusedError{
		Detail: customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.", http.StatusBadRequest),
		Code:   &models.Code{Id: 42, ClientId: 7, UserId: 13, SessionIdentifier: "sid-reused"},
	}
	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(nil, reuseErr)

	var order []string
	note := func(what string) func(mock.Arguments) {
		return func(mock.Arguments) { order = append(order, what) }
	}
	token := &models.RefreshToken{Id: 1, RefreshTokenJti: "rt-1"}
	mocks_data.ExpectRunInTransaction(database, revokeTx, func(edge string) { order = append(order, edge) })
	database.On("AcquireUserSessionRow", mock.Anything, revokeTx, "sid-reused").Return(true, nil).Once()
	database.On("GetRefreshTokensBySessionIdentifier", mock.Anything, revokeTx, "sid-reused").
		Return([]*models.RefreshToken{token}, nil).Once()
	database.On("UpdateRefreshToken", mock.Anything, revokeTx, token).Run(note("revoke")).Return(nil).Once()
	database.On("GetUserSessionBySessionIdentifier", mock.Anything, revokeTx, "sid-reused").
		Return(&models.UserSession{Id: 9, SessionIdentifier: "sid-reused"}, nil).Once()
	database.On("DeleteUserSession", mock.Anything, revokeTx, int64(9)).Return(nil).Once()

	var audited map[string]interface{}
	auditLogger.On("Log", mock.Anything, audit.AuditAuthCodeReuseDetected, mock.Anything).
		Run(func(args mock.Arguments) {
			order = append(order, "audit")
			audited, _ = args.Get(2).(map[string]interface{})
		}).Return().Once()
	jsonWriter.On("JsonError", rr, req, reuseErr.Detail).Run(note("answer")).Return().Once()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, []string{"begin", "revoke", "commit", "audit", "answer"}, order,
		"the audit row must wait for the commit, and the client's answer for the audit row")
	assert.Equal(t, []string{"rt-1"}, audited["revokedRefreshTokenJtis"],
		"the row lists what the committed transaction revoked")
	database.AssertExpectations(t)
}

// TestHandleTokenPost_AuthCode_ConcurrentDoubleSpendLoses verifies the #77 fix:
// when two requests race to redeem the same code, the loser (whose atomic claim
// via MarkCodeAsUsed returns false) is rejected with invalid_grant. Crucially it
// must NOT mint tokens and must NOT run the session-wide reuse cascade (no
// BeginTransaction, no session teardown, no reuse audit) — that cascade running
// concurrently with the winner's mint on the same session rows is what deadlocks
// the winner. A genuine *later* replay is still cascaded by the sequential-reuse
// path (covered by the integration CodeReuse_* tests).
func TestHandleTokenPost_AuthCode_ConcurrentDoubleSpendLoses(t *testing.T) {
	jsonWriter := mocks_handlers.NewJSONWriter(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

	formData := "grant_type=authorization_code&code=raced&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &models.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	racedCode := &models.Code{
		Id:                42,
		ClientId:          7,
		UserId:            13,
		SessionIdentifier: "sid-raced",
	}
	validationResult := &protocolvalidation.ValidateTokenRequestResult{CodeEntity: racedCode}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(validationResult, nil)

	// This request loses the race: the code was already claimed concurrently.
	database.On("MarkCodeAsUsed", mock.Anything, (*sql.Tx)(nil), racedCode.Id).Return(false, nil)

	jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
		detail, ok := err.(*customerrors.ErrorDetail)
		return ok && detail.GetCode() == "invalid_grant"
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	// The loser must not mint tokens, and must not run the reuse cascade: no
	// transaction, no session teardown, no reuse audit.
	tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForAuthCode", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "RunInTransaction", mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleTokenPost_Refresh_ConcurrentDoubleSpendLoses pins the branch a refresh
// request takes when its validation read saw the token live but the compare-and-set
// then failed: refuse, and do NOT run the family cascade (#128).
//
// The two negative assertions are the test. Without them it would pass under the
// design decision 1 rejected, which cascades on the compare-and-set's false return.
// That version tears down the winner's freshly minted child, because a false return
// means only "the row was no longer live when this statement ran" and so merges the
// concurrent loser with the sequential replayer.
//
// What it does NOT prove: the inter-request ordering that produced this state. A mocked
// unit test fixes the state the handler reads and asserts the resulting branch; no
// mocked test can establish that one HTTP request really arrived before another. Its
// sibling for the other branch is the already-revoked subtest inside TestHandleTokenPost.
func TestHandleTokenPost_Refresh_ConcurrentDoubleSpendLoses(t *testing.T) {
	jsonWriter := mocks_handlers.NewJSONWriter(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

	formData := "grant_type=refresh_token&refresh_token=raced"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withSettings(req, &models.Settings{})
	rr := httptest.NewRecorder()

	// Revoked=false is the whole point: the validation read saw a live token, so this
	// request is a compare-and-set loser rather than a replay.
	racedToken := &models.RefreshToken{
		Id:                   42,
		Revoked:              false,
		RefreshTokenJti:      "jti-raced",
		FirstRefreshTokenJti: "jti-family",
	}
	validationResult := &protocolvalidation.ValidateTokenRequestResult{
		Client:       authCodeClient(),
		RefreshToken: racedToken,
		CodeEntity:   &models.Code{Id: 1},
	}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(validationResult, nil)

	// This request loses the race: the row stopped being live between the validation
	// read and the claim.
	database.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), racedToken.Id).Return(false, nil)

	jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
		detail, ok := err.(*customerrors.ErrorDetail)
		return ok && detail.GetCode() == "invalid_grant"
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	// The loser must not mint tokens, must not cascade over the family, and must not
	// audit anything.
	tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForRefresh", mock.Anything, mock.Anything, mock.Anything)
	tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForRefreshROPC", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "RevokeRefreshTokenFamily", mock.Anything, mock.Anything, mock.Anything)
	userSessionManager.AssertNotCalled(t, "BumpUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleTokenPost_Refresh_Replay_AuditsContainment asserts the replay-containment
// audit payload EXACTLY. It lives at the unit tier deliberately: the mock logger makes
// the payload observable, and the integration tier cannot see it at all (#128).
//
// Both linkage shapes are run against the same expectations on purpose. A security-event
// consumer must not need flow-specific logic to identify the client and user, which is
// where this departs from AuditTokenIssuedRefreshTokenResponse (codeId on one shape,
// userId/clientId on the other).
//
// The exact-key assertion is what pins the two negative requirements from decision 8: the
// payload carries neither the presented refresh token itself nor a list of revoked JTIs.
// A set-based update yields an exact COUNT but not an exact cross-engine row set, and an
// inaccurate security field is worse than an omitted one.
func TestHandleTokenPost_Refresh_Replay_AuditsContainment(t *testing.T) {
	const (
		presentedJti = "jti-presented"
		familyJti    = "jti-family"
		clientId     = int64(111)
		userId       = int64(222)
	)

	testCases := []struct {
		name     string
		result   *protocolvalidation.ValidateTokenRequestResult
		wantFlow string
	}{
		{
			name: "authorization code family",
			result: &protocolvalidation.ValidateTokenRequestResult{
				RefreshToken: &models.RefreshToken{
					Id:                   1,
					Revoked:              true,
					RefreshTokenJti:      presentedJti,
					FirstRefreshTokenJti: familyJti,
					CodeId:               sql.NullInt64{Int64: 9, Valid: true},
				},
				// The principal fields come from the loaded code on this shape.
				CodeEntity: &models.Code{Id: 9, ClientId: clientId, UserId: userId},
			},
			wantFlow: "auth_code",
		},
		{
			name: "ROPC family",
			result: &protocolvalidation.ValidateTokenRequestResult{
				// No code at all: the client and user are on the refresh token row.
				RefreshToken: &models.RefreshToken{
					Id:                   1,
					Revoked:              true,
					RefreshTokenJti:      presentedJti,
					FirstRefreshTokenJti: familyJti,
					UserId:               sql.NullInt64{Int64: userId, Valid: true},
					ClientId:             sql.NullInt64{Int64: clientId, Valid: true},
				},
			},
			wantFlow: "ropc",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonWriter := mocks_handlers.NewJSONWriter(t)
			userSessionManager := mocks_handlers.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)
			tokenIssuer := mocks_handlers.NewTokenIssuer(t)
			tokenValidator := mocks_handlers.NewTokenValidator(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)

			handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

			formData := "grant_type=refresh_token&refresh_token=replayed"
			req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
			req = withSettings(req, &models.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
				Return(tc.result, nil)

			// Two live members transitioned, so this is a real containment.
			database.On("RevokeRefreshTokenFamily", mock.Anything, (*sql.Tx)(nil), familyJti).Return(int64(2), nil)

			var logged []map[string]interface{}
			auditLogger.On("Log", mock.Anything, audit.AuditRefreshTokenReplayDetected, mock.AnythingOfType("map[string]interface {}")).
				Run(func(args mock.Arguments) {
					logged = append(logged, args.Get(2).(map[string]interface{}))
				}).Return()

			jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*customerrors.ErrorDetail)
				return ok && detail.GetCode() == "invalid_grant"
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
			tokenValidator.AssertExpectations(t)
			database.AssertExpectations(t)
			auditLogger.AssertExpectations(t)

			require.Len(t, logged, 1, "exactly one replay event must be emitted")
			assert.Equal(t, map[string]interface{}{
				"presentedRefreshTokenJti": presentedJti,
				"firstRefreshTokenJti":     familyJti,
				"revokedCount":             int64(2),
				"clientId":                 clientId,
				"userId":                   userId,
				"flow":                     tc.wantFlow,
			}, logged[0], "the replay payload must carry exactly these six fields")

			// A replay mints nothing and bumps nothing.
			tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForRefresh", mock.Anything, mock.Anything, mock.Anything)
			tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForRefreshROPC", mock.Anything, mock.Anything, mock.Anything)
			userSessionManager.AssertNotCalled(t, "BumpUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestHandleTokenPost_Refresh_Replay_ContainmentErrorReturns500 pins that a failed
// containment is surfaced rather than swallowed, and that no event is emitted for it.
//
// Emitting on a failed containment would be worse than emitting nothing: the event's
// contract is that it records members actually revoked, and a failure revoked none.
func TestHandleTokenPost_Refresh_Replay_ContainmentErrorReturns500(t *testing.T) {
	jsonWriter := mocks_handlers.NewJSONWriter(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

	formData := "grant_type=refresh_token&refresh_token=replayed"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &models.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	replayed := &models.RefreshToken{
		Id:                   1,
		Revoked:              true,
		RefreshTokenJti:      "jti-presented",
		FirstRefreshTokenJti: "jti-family",
	}
	validationResult := &protocolvalidation.ValidateTokenRequestResult{
		RefreshToken: replayed,
		CodeEntity:   &models.Code{Id: 9},
	}

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(validationResult, nil)

	database.On("RevokeRefreshTokenFamily", mock.Anything, (*sql.Tx)(nil), "jti-family").
		Return(int64(0), customerrors.NewErrorDetailWithHttpStatusCode("server_error", "Failed to contain family", http.StatusInternalServerError))

	jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
		return strings.Contains(err.Error(), "Failed to contain family")
	})).Return().Once()

	handler.ServeHTTP(rr, req)

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	database.AssertExpectations(t)

	// No event, and no invalid_grant either: the request did not get a clean refusal,
	// it got a server error.
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	jsonWriter.AssertNumberOfCalls(t, "JsonError", 1)
}

// TestGrantTypeConsumesScope pins which grant types the provided-but-empty rejection applies to.
// The authorization_code row is the one that matters: it never reads the scope parameter, so
// rejecting on it would break a valid token exchange.
func TestGrantTypeConsumesScope(t *testing.T) {
	testCases := []struct {
		grantType string
		want      bool
	}{
		{"client_credentials", true},
		{"refresh_token", true},
		{"password", true},
		{"authorization_code", false},
		{"", false},
		{"urn:ietf:params:oauth:grant-type:device_code", false},
	}

	for _, tc := range testCases {
		t.Run(tc.grantType, func(t *testing.T) {
			assert.Equal(t, tc.want, grantTypeConsumesScope(tc.grantType))
		})
	}
}

// TestHandleTokenPost_ScopeNormalizationWiring proves the handler normalizes the scope with
// oidc.NormalizeScope and passes its OUTPUT to the validator, which oidc's own whitespace table
// cannot show. That table is where the rule is pinned; the rows here are the consumer's (#116).
//
// The validator is mocked with mock.MatchedBy so the scope it receives is captured rather than
// merely type-checked. Every accepting row returns a validation error afterwards, because what is
// under test is the input handed over, not what happens next.
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
			name:                "tab-separated scopes are collapsed",
			grantType:           "client_credentials",
			rawScope:            "billing-api:read\tbilling-api:write",
			wantScope:           "billing-api:read billing-api:write",
			wantValidatorCalled: true,
		},
		{
			name:                "surrounding whitespace is trimmed",
			grantType:           "client_credentials",
			rawScope:            "  billing-api:read  ",
			wantScope:           "billing-api:read",
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
			// The widening #116's one splitter brought to this endpoint: a U+00A0 beside a
			// separator is trimmed off its element, where the endpoint used to hand the validator
			// " billing-api:write" and have it refused as an unknown scope.
			name:                "a U+00A0 after a separator is trimmed",
			grantType:           "refresh_token",
			rawScope:            "billing-api:read  billing-api:write",
			wantScope:           "billing-api:read billing-api:write",
			wantValidatorCalled: true,
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
			jsonWriter := mocks_handlers.NewJSONWriter(t)
			userSessionManager := mocks_handlers.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)
			tokenIssuer := mocks_handlers.NewTokenIssuer(t)
			tokenValidator := mocks_handlers.NewTokenValidator(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)

			handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

			form := url.Values{"grant_type": {tc.grantType}, "client_id": {"test_client"}}
			if tc.rawScope != omittedScope {
				form.Set("scope", tc.rawScope)
			}

			req, _ := http.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
			req = withSettings(req, &models.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			if tc.wantValidatorCalled {
				// Capture what the handler passed. Returning an error keeps the test focused on
				// the input rather than on downstream token issuance.
				validationError := customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
					"stop here", http.StatusBadRequest)
				tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.MatchedBy(
					func(input *protocolvalidation.ValidateTokenRequestInput) bool {
						return input.Scope == tc.wantScope
					})).Return(nil, validationError).Once()
				jsonWriter.On("JsonError", rr, req, validationError).Return()

				handler.ServeHTTP(rr, req)

				// AssertExpectations is what proves the scope matched: an input whose Scope differed
				// would not satisfy MatchedBy, so the expectation would go unmet.
				tokenValidator.AssertExpectations(t)
				jsonWriter.AssertExpectations(t)
				return
			}

			// Rejected before the validator runs. mocks_handlers.NewTokenValidator(t) fails the
			// test if ValidateTokenRequest is called with no expectation registered, so registering
			// none is the assertion that it was not reached.
			var rejection *customerrors.ErrorDetail
			jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*customerrors.ErrorDetail)
				if !ok {
					return false
				}
				rejection = detail
				return true
			})).Return()

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
			if assert.NotNil(t, rejection, "the handler should have rejected the request") {
				assert.Equal(t, "invalid_scope", rejection.GetCode())
				assert.Equal(t, http.StatusBadRequest, rejection.GetHttpStatusCode())
				assert.Contains(t, rejection.GetDescription(), "provided but contains no scopes")
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
	newHandler := func(t *testing.T) (*mocks_handlers.JSONWriter, *mocks_handlers.TokenValidator,
		*mocks_handlers.TokenIssuer, *mocks_handlers.AuditLogger, http.HandlerFunc) {
		t.Helper()
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)
		return jsonWriter, tokenValidator, tokenIssuer, auditLogger,
			HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})
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
			req = withSettings(req, &models.Settings{})
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()

			denial := customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope", tc.description,
				http.StatusBadRequest)
			tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything,
				mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(nil, denial)

			auditLogger.On("Log", mock.Anything, audit.AuditTokenScopeDenied, mock.MatchedBy(
				func(details map[string]interface{}) bool {
					return details["clientIdentifier"] == "test_client" &&
						details["grantType"] == tc.grantType &&
						details["scope"] == tc.wantScope
				})).Return()

			jsonWriter.On("JsonError", rr, req, denial).Return()

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
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		var rejection *customerrors.ErrorDetail
		jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			detail, ok := err.(*customerrors.ErrorDetail)
			if !ok {
				return false
			}
			rejection = detail
			return true
		})).Return()

		// No auditLogger expectation is registered, and none is registered on the validator either.
		// mocks_handlers.NewAuditLogger(t) fails the test if Log is called without a matching
		// expectation, so registering nothing IS the assertion.
		handler.ServeHTTP(rr, req)

		jsonWriter.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		tokenValidator.AssertNotCalled(t, "ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything)
		if assert.NotNil(t, rejection) {
			assert.Equal(t, "invalid_scope", rejection.GetCode())
		}
	})

	// Row 4: the forensic field on the success path. Nothing asserted this payload's shape before.
	t.Run("successful issuance records the scope", func(t *testing.T) {
		jsonWriter, tokenValidator, tokenIssuer, auditLogger, handler := newHandler(t)

		form := "grant_type=client_credentials&client_id=test_client&client_secret=s&scope=billing-api:read"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		mockClient := &models.Client{Id: 42, ClientIdentifier: "test_client"}
		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything,
			mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
			Return(&protocolvalidation.ValidateTokenRequestResult{Client: mockClient, Scope: "billing-api:read"}, nil)

		tokenResponse := &oauth.TokenResponse{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 3600}
		tokenIssuer.On("GenerateTokenResponseForClientCred", req.Context(), mock.Anything, mockClient, "billing-api:read").
			Return(tokenResponse, nil)

		auditLogger.On("Log", mock.Anything, audit.AuditTokenIssuedClientCredentialsResponse, mock.MatchedBy(
			func(details map[string]interface{}) bool {
				clientId, ok := details["clientId"].(int64)
				return ok && clientId == mockClient.Id && details["scope"] == "billing-api:read"
			})).Return()

		jsonWriter.On("EncodeJson", rr, req, tokenResponse).Return()

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
// core/oauth's TestGenerateTokenResponseForROPC and TestGenerateTokenResponseForRefreshROPC.
// Neither half substitutes for the other.
//
// This closes a real leak rather than guarding a hypothetical. MiddlewareSessionIdentifier
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
	jsonWriter := mocks_handlers.NewJSONWriter(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)
	handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

	form := "grant_type=password&client_id=test_client&username=u&password=p&scope=openid"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
	req = withSettings(req, &models.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// A DIFFERENT user's browser session, present exactly as the global middleware would
	// leave it. Nothing in a password grant may consume this.
	req = req.WithContext(reqctx.WithSessionIdentifier(req.Context(), "some-other-users-browser-session"))
	rr := httptest.NewRecorder()

	client := &models.Client{Id: 1, ClientIdentifier: "test_client"}
	user := &models.User{Id: 42, Subject: fake.UUID(), AuthStateGeneration: 7}

	tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
		mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(&protocolvalidation.ValidateTokenRequestResult{Client: client, User: user, Scope: "openid"}, nil)

	var captured *issuance.ROPCGrantInput
	tokenIssuer.On("GenerateTokenResponseForROPC", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(2).(*issuance.ROPCGrantInput) }).
		Return(&issuance.ROPCGrantResponse{AccessToken: "at", TokenType: "Bearer"}, nil)

	auditLogger.On("Log", mock.Anything, audit.AuditTokenIssuedROPCResponse, mock.Anything).Return()
	jsonWriter.On("EncodeJson", rr, mock.Anything, mock.Anything).Return()

	handler.ServeHTTP(rr, req)

	require.NotNil(t, captured, "GenerateTokenResponseForROPC was never called")
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
// which is not ErrUserDisabled and not invalid_scope, so a superseded refresh token must not
// be recorded as either. Stage 5 adds the event that does cover this.
func TestHandleTokenPost_SupersededRefreshTokenIsSurfaced(t *testing.T) {
	jsonWriter := mocks_handlers.NewJSONWriter(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

	formData := "grant_type=refresh_token&refresh_token=superseded&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &models.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	// The exact error the validator's two refresh branches return on a generation mismatch.
	supersededErr := customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
		"The refresh token is invalid because it was superseded.", http.StatusBadRequest)

	tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
		Return(nil, supersededErr)

	jsonWriter.On("JsonError", rr, req, supersededErr).Return().Once()

	handler.ServeHTTP(rr, req)

	jsonWriter.AssertExpectations(t)
	tokenValidator.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// TestHandleTokenPost_ROPC_SpendsTheLimiterBudgetOnInvalidGrantOnly is seam 2 for the
// password grant: the handler driven through a real RateLimiterMiddleware, so what is
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
	newHandler := func(t *testing.T, failure error) (http.Handler, *mocks_handlers.AuditLogger) {
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)

		if failure != nil {
			tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
				Return(nil, failure)
			jsonWriter.On("JsonError", mock.Anything, mock.Anything, mock.Anything).Return()
		} else {
			client := &models.Client{Id: 1, ClientIdentifier: "app"}
			user := &models.User{Id: 42, Subject: fake.UUID()}
			tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything, mock.Anything).
				Return(&protocolvalidation.ValidateTokenRequestResult{Client: client, User: user, Scope: "openid"}, nil)
			tokenIssuer.On("GenerateTokenResponseForROPC", mock.Anything, mock.Anything, mock.Anything).
				Return(&issuance.ROPCGrantResponse{AccessToken: "at", TokenType: "Bearer"}, nil)
			jsonWriter.On("EncodeJson", mock.Anything, mock.Anything, mock.Anything).Return()
		}
		auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).Return().Maybe()

		rateLimiter := newTestRateLimiter(nil)
		handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer,
			tokenValidator, auditLogger, rateLimiter)
		return rateLimiter.LimitROPC(handler), auditLogger
	}

	// post submits one password grant from a fixed host and reports the status. A refusal
	// is the limiter's 429; anything the handler answers leaves the recorder's default 200,
	// since JsonError and EncodeJson are mocks that write nothing.
	post := func(handler http.Handler) int {
		form := url.Values{
			"grant_type": {"password"},
			"client_id":  {"app"},
			"username":   {username},
			"password":   {"guess"},
		}
		req, _ := http.NewRequest("POST", "/auth/token", strings.NewReader(form.Encode()))
		req = withSettings(req, &models.Settings{})
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

	invalidGrant := customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
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
		auditLogger.AssertCalled(t, "Log", mock.Anything, audit.AuditROPCAuthFailed, map[string]interface{}{
			"email":            username,
			"clientIdentifier": "app",
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
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:5000"
		handler.ServeHTTP(httptest.NewRecorder(), req)
		auditLogger.AssertCalled(t, "Log", mock.Anything, audit.AuditROPCAuthFailed, map[string]interface{}{
			"email":            username,
			"clientIdentifier": "app",
		})
	})

	// The three error codes that are not a guess against the account, plus the one
	// invalid_grant that is not. Each names the gate that must not charge it.
	notCharged := []struct {
		name string
		err  error
	}{
		{"unauthorized_client, the grant is switched off for this client",
			customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
				"The client is not authorized to use the resource owner password credentials grant type.",
				http.StatusBadRequest)},
		{"invalid_request, a parameter is missing",
			customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				"Missing required password parameter.", http.StatusBadRequest)},
		{"invalid_client, the client failed to authenticate",
			customerrors.NewErrorDetailWithHttpStatusCode("invalid_client",
				"Client authentication failed.", http.StatusUnauthorized)},
		{"invalid_grant, but the client is disabled and no credential was read",
			customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
				"Client is disabled.", http.StatusBadRequest)},
	}
	for _, tc := range notCharged {
		t.Run(tc.name+" spends nothing", func(t *testing.T) {
			assert.False(t, spends(t, tc.err),
				"this failure compared no credential against %s, so it must not spend the account's budget", username)
		})
		t.Run(tc.name+" emits no ropc_auth_failed", func(t *testing.T) {
			handler, auditLogger := newHandler(t, tc.err)
			assert.Equal(t, http.StatusOK, post(handler))
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.AuditROPCAuthFailed, mock.Anything)
		})
	}

	t.Run("a successful grant spends nothing", func(t *testing.T) {
		handler, auditLogger := newHandler(t, nil)
		// Well past the budget. A tier that counted every request would refuse the 11th,
		// which is a machine-driven integration throttled for authenticating successfully.
		for i := 0; i < 25; i++ { // under ropc_ip's 30, which counts every request
			assert.Equal(t, http.StatusOK, post(handler), "grant %d should succeed", i+1)
		}
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.AuditROPCAuthFailed, mock.Anything)
	})
}

// withSettings puts resolved settings on a request, which the refresh arm's flow gate reads to
// resolve a client left on "inherit". Every refresh fixture that reaches past replay containment
// needs it, and needs a Client on its validation result beside it: a refresh token exists only
// where the flow that issued it was switched on, so saying so is the fixture stating what it
// always meant rather than working around the gate (#250).
// theseSettings matches the very settings value a test put on its request, by identity, so a
// handler that built its own or read another request's would match nothing.
func theseSettings(want *models.Settings) interface{} {
	return mock.MatchedBy(func(got *models.Settings) bool { return got == want })
}

func withSettings(req *http.Request, settings *models.Settings) *http.Request {
	return req.WithContext(reqctx.WithSettings(req.Context(), settings))
}

// authCodeClient is the client an authorization code flow refresh fixture implies: the flow that
// minted the token is on. Its zero-valued ROPC override leaves that grant inheriting, which is
// irrelevant on this arm because a token carrying a CodeEntity is never judged by the ROPC switch.
func authCodeClient() *models.Client {
	return &models.Client{Id: 1, ClientIdentifier: "test_client", AuthorizationCodeEnabled: true}
}

// TestHandleTokenPost_Refresh_FlowGate owns the whole truth table for the rule that a refresh is
// governed by the switch of the flow that ISSUED the token, not by the authorization code flag
// alone. Before this landed the arm refused on !AuthorizationCodeEnabled whatever minted the
// token, so an ROPC-only client could never redeem the token ROPC handed it (row 2) and turning
// ROPC off stopped nothing already issued (rows 3 to 5) (#250).
//
// Every row presents a LIVE token, so the flow gate is what answers rather than replay
// containment. The containment cases are the two tests below this one.
//
// An accepted row is proved by reaching MarkRefreshTokenAsRevoked, which is the first thing past
// the gate. It is stubbed to lose its claim so the row stops there rather than dragging the whole
// minting chain into a test about a gate; a lost claim answers invalid_grant, which is visibly not
// the refusal the gate emits.
func TestHandleTokenPost_Refresh_FlowGate(t *testing.T) {
	ropcOn, ropcOff := true, false

	testCases := []struct {
		name          string
		client        *models.Client
		globalROPC    bool
		ropcToken     bool // true: no CodeEntity, so ROPC minted it
		wantRefusal   string
		wantRefusalIs string
	}{
		{
			name:       "row 1: ROPC token, both flows on, accepted",
			client:     &models.Client{Id: 1, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOn},
			globalROPC: true,
			ropcToken:  true,
		},
		{
			// The defect this stage exists to close. Refused today, with a sentence about a
			// flow the client never used.
			name:       "row 2: ROPC token, ROPC-only client, accepted",
			client:     &models.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOn},
			globalROPC: true,
			ropcToken:  true,
		},
		{
			// Reverses today's behaviour, where turning ROPC off stops nothing already issued.
			name:          "row 3: ROPC token, ROPC off on the client, refused",
			client:        &models.Client{Id: 1, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOff},
			globalROPC:    true,
			ropcToken:     true,
			wantRefusal:   protocolvalidation.ROPCNotAuthorizedErrorMsg,
			wantRefusalIs: "unauthorized_client",
		},
		{
			name:          "row 4: ROPC token, both flows off, refused for ROPC",
			client:        &models.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOff},
			globalROPC:    true,
			ropcToken:     true,
			wantRefusal:   protocolvalidation.ROPCNotAuthorizedErrorMsg,
			wantRefusalIs: "unauthorized_client",
		},
		{
			// Decision 3, and the only row that fails if the gate reads the per-client override
			// alone: the client inherits, and the global switch is what turns ROPC off.
			name:          "row 5: ROPC token, client inherits, global ROPC off, refused",
			client:        &models.Client{Id: 1, AuthorizationCodeEnabled: true},
			globalROPC:    false,
			ropcToken:     true,
			wantRefusal:   protocolvalidation.ROPCNotAuthorizedErrorMsg,
			wantRefusalIs: "unauthorized_client",
		},
		{
			// Goal 3: the authorization code half keeps the refusal it has today, word for word.
			name:          "row 6: authorization code token, that flow off, refused for auth code",
			client:        &models.Client{Id: 1, AuthorizationCodeEnabled: false, ResourceOwnerPasswordCredentialsEnabled: &ropcOn},
			globalROPC:    true,
			ropcToken:     false,
			wantRefusal:   authCodeNotAuthorizedErrorMsg,
			wantRefusalIs: "unauthorized_client",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonWriter := mocks_handlers.NewJSONWriter(t)
			userSessionManager := mocks_handlers.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)
			tokenIssuer := mocks_handlers.NewTokenIssuer(t)
			tokenValidator := mocks_handlers.NewTokenValidator(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)

			handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

			formData := "grant_type=refresh_token&refresh_token=live"
			req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			// The mocked validator is matched against THIS request's context, so the settings
			// have to be on it before the expectation is set up.
			req = withSettings(req, &models.Settings{ResourceOwnerPasswordCredentialsEnabled: tc.globalROPC})
			rr := httptest.NewRecorder()

			liveToken := &models.RefreshToken{
				Id:                   7,
				Revoked:              false,
				RefreshTokenJti:      "jti-live",
				FirstRefreshTokenJti: "jti-family",
			}
			result := &protocolvalidation.ValidateTokenRequestResult{
				Client:           tc.client,
				RefreshToken:     liveToken,
				RefreshTokenInfo: &oauth.JwtToken{},
			}
			if tc.ropcToken {
				liveToken.ClientId = sql.NullInt64{Int64: tc.client.Id, Valid: true}
				liveToken.UserId = sql.NullInt64{Int64: 5, Valid: true}
			} else {
				liveToken.CodeId = sql.NullInt64{Int64: 9, Valid: true}
				result.CodeEntity = &models.Code{Id: 9, ClientId: tc.client.Id, UserId: 5}
			}

			tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
				Return(result, nil)

			if tc.wantRefusal == "" {
				// Accepted: the request reaches the claim, and loses it, which is as far as a
				// test about the gate needs to go.
				database.On("MarkRefreshTokenAsRevoked", mock.Anything, (*sql.Tx)(nil), liveToken.Id).Return(false, nil).Once()
				jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
					detail, ok := err.(*customerrors.ErrorDetail)
					return ok && detail.GetCode() == "invalid_grant"
				})).Return().Once()
			} else {
				jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
					detail, ok := err.(*customerrors.ErrorDetail)
					return ok && detail.GetCode() == tc.wantRefusalIs &&
						detail.GetDescription() == tc.wantRefusal &&
						detail.GetHttpStatusCode() == http.StatusBadRequest
				})).Return().Once()
			}

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
			tokenValidator.AssertExpectations(t)
			database.AssertExpectations(t)

			if tc.wantRefusal != "" {
				// A refused token is not spent. The operator may turn the switch back on, and a
				// live token should still be live when they do.
				database.AssertNotCalled(t, "MarkRefreshTokenAsRevoked", mock.Anything, mock.Anything, mock.Anything)
				// The gate is not containment: nothing is cascaded and nothing is audited.
				database.AssertNotCalled(t, "RevokeRefreshTokenFamily", mock.Anything, mock.Anything, mock.Anything)
				auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			}
			tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForRefresh", mock.Anything, mock.Anything, mock.Anything)
			tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForRefreshROPC", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// TestHandleTokenPost_Refresh_ContainmentPrecedesFlowGate is why the flow gate lives in this
// handler rather than in ValidateTokenRequest, and it is the case that was broken before this
// stage: a stolen token replayed while its flow is switched off was refused by the validator, so
// its rotation family stayed live and the theft went unrecorded.
//
// Whether a theft is detected must not depend on which switches happen to be on. Both rows
// therefore present a REVOKED token with the issuing flow off, and require that containment ran
// and was audited, and that the answer is the containment refusal rather than the gate's (#250).
func TestHandleTokenPost_Refresh_ContainmentPrecedesFlowGate(t *testing.T) {
	ropcOff := false

	testCases := []struct {
		name     string
		client   *models.Client
		result   *protocolvalidation.ValidateTokenRequestResult
		wantFlow string
	}{
		{
			name:   "ROPC token replayed while ROPC is off",
			client: &models.Client{Id: 111, AuthorizationCodeEnabled: true, ResourceOwnerPasswordCredentialsEnabled: &ropcOff},
			result: &protocolvalidation.ValidateTokenRequestResult{
				RefreshToken: &models.RefreshToken{
					Id:                   1,
					Revoked:              true,
					RefreshTokenJti:      "jti-presented",
					FirstRefreshTokenJti: "jti-family",
					ClientId:             sql.NullInt64{Int64: 111, Valid: true},
					UserId:               sql.NullInt64{Int64: 222, Valid: true},
				},
			},
			wantFlow: "ropc",
		},
		{
			name:   "authorization code token replayed while that flow is off",
			client: &models.Client{Id: 111, AuthorizationCodeEnabled: false},
			result: &protocolvalidation.ValidateTokenRequestResult{
				RefreshToken: &models.RefreshToken{
					Id:                   1,
					Revoked:              true,
					RefreshTokenJti:      "jti-presented",
					FirstRefreshTokenJti: "jti-family",
					CodeId:               sql.NullInt64{Int64: 9, Valid: true},
				},
				CodeEntity: &models.Code{Id: 9, ClientId: 111, UserId: 222},
			},
			wantFlow: "auth_code",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonWriter := mocks_handlers.NewJSONWriter(t)
			userSessionManager := mocks_handlers.NewUserSessionManager(t)
			database := mocks_data.NewDatabase(t)
			tokenIssuer := mocks_handlers.NewTokenIssuer(t)
			tokenValidator := mocks_handlers.NewTokenValidator(t)
			auditLogger := mocks_handlers.NewAuditLogger(t)

			handler := HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})

			formData := "grant_type=refresh_token&refresh_token=replayed"
			req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			// Global ROPC off as well, so neither arm of the gate would let this through if it
			// were reached.
			req = withSettings(req, &models.Settings{ResourceOwnerPasswordCredentialsEnabled: false})
			rr := httptest.NewRecorder()

			result := tc.result
			result.Client = tc.client
			tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything, mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).
				Return(result, nil)

			database.On("RevokeRefreshTokenFamily", mock.Anything, (*sql.Tx)(nil), "jti-family").Return(int64(2), nil).Once()

			var logged []map[string]interface{}
			auditLogger.On("Log", mock.Anything, audit.AuditRefreshTokenReplayDetected, mock.AnythingOfType("map[string]interface {}")).
				Run(func(args mock.Arguments) {
					logged = append(logged, args.Get(2).(map[string]interface{}))
				}).Return().Once()

			jsonWriter.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
				detail, ok := err.(*customerrors.ErrorDetail)
				return ok && detail.GetCode() == "invalid_grant" &&
					detail.GetDescription() == "This refresh token has been revoked."
			})).Return().Once()

			handler.ServeHTTP(rr, req)

			jsonWriter.AssertExpectations(t)
			tokenValidator.AssertExpectations(t)
			database.AssertExpectations(t)
			auditLogger.AssertExpectations(t)

			require.Len(t, logged, 1, "containment must be audited even though the flow is switched off")
			assert.Equal(t, tc.wantFlow, logged[0]["flow"])
			assert.Equal(t, int64(2), logged[0]["revokedCount"])

			// The flow gate must not have answered: it sits below containment, and a replay
			// never reaches it.
			database.AssertNotCalled(t, "MarkRefreshTokenAsRevoked", mock.Anything, mock.Anything, mock.Anything)
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
	newHandler := func(t *testing.T) (*mocks_handlers.JSONWriter, *mocks_handlers.TokenValidator,
		*mocks_handlers.AuditLogger, http.HandlerFunc) {
		t.Helper()
		jsonWriter := mocks_handlers.NewJSONWriter(t)
		userSessionManager := mocks_handlers.NewUserSessionManager(t)
		database := mocks_data.NewDatabase(t)
		tokenIssuer := mocks_handlers.NewTokenIssuer(t)
		tokenValidator := mocks_handlers.NewTokenValidator(t)
		auditLogger := mocks_handlers.NewAuditLogger(t)
		return jsonWriter, tokenValidator, auditLogger,
			HandleTokenPost(jsonWriter, userSessionManager, database, tokenIssuer, tokenValidator, auditLogger, noCredentialFailures{})
	}

	const form = "grant_type=authorization_code&client_id=test_client&client_secret=s&" +
		"code=the_code&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"

	t.Run("a deregistered redirect URI on the code is audited", func(t *testing.T) {
		jsonWriter, tokenValidator, auditLogger, handler := newHandler(t)

		req, _ := http.NewRequest("POST", "/token", strings.NewReader(form))
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		refusal := protocolvalidation.ErrCodeRedirectURIDeregistered
		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything,
			mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(nil, refusal)

		auditLogger.On("Log", mock.Anything, audit.AuditRedemptionRefusedRedirectURI, mock.MatchedBy(
			func(details map[string]interface{}) bool {
				// clientIdentifier, the request's string, matching the neighbouring events.
				// Unlike AuditTokenScopeDenied's it has been PROVED rather than asserted: this
				// refusal is reachable only below client authentication and PKCE.
				return details["clientIdentifier"] == "test_client"
			})).Return()

		jsonWriter.On("JsonError", rr, req, mock.Anything).Return()

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
		req = withSettings(req, &models.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		refusal := customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
			"Code is invalid.", http.StatusBadRequest)
		tokenValidator.On("ValidateTokenRequest", req.Context(), mock.Anything,
			mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(nil, refusal)

		jsonWriter.On("JsonError", rr, req, mock.Anything).Return()

		handler.ServeHTTP(rr, req)
	})
}
