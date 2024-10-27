package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"
)

func TestHandleAuthCallbackPost(t *testing.T) {
	t.Run("Valid auth callback", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		form.Add("code", "valid_code")

		req, err := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		aesEncryptionKey := []byte("test_encryption_key_000000000000")
		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSession.Values[constants.SessionKeyNonce] = "test_nonce"
		mockSession.Values[constants.SessionKeyRedirectBack] = "/dashboard"

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)
		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.MatchedBy(func(s *sessions.Session) bool {
			// Assert that the specified session values have been deleted
			_, stateExists := s.Values[constants.SessionKeyState]
			_, nonceExists := s.Values[constants.SessionKeyNonce]
			_, redirectURIExists := s.Values[constants.SessionKeyRedirectURI]
			_, codeVerifierExists := s.Values[constants.SessionKeyCodeVerifier]
			_, redirectBackExists := s.Values[constants.SessionKeyRedirectBack]

			return !stateExists && !nonceExists && !redirectURIExists && !codeVerifierExists && !redirectBackExists
		})).Return(nil)

		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(&models.Code{
			Id:       1,
			ClientId: 1,
		}, nil)

		mockDB.On("CodeLoadClient", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

		clientSecret := "client_secret"
		clientSecretEncrypted, err := encryption.EncryptText(clientSecret, aesEncryptionKey)
		assert.NoError(t, err)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(&models.Client{
			Id:                    1,
			ClientIdentifier:      "test_client",
			ClientSecretEncrypted: clientSecretEncrypted,
		}, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "access_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh_token",
			IdToken:      "id_token",
		}

		mockTokenExchanger.On("ExchangeCodeForTokens",
			"valid_code",
			"http://localhost:8080/callback",
			"test_client",
			clientSecret,
			"code_verifier",
			mock.AnythingOfType("string"), // Keep this one as AnythingOfType since it might be dynamically generated
		).Return(mockTokenResponse, nil)

		nonce := "test_nonce"
		hashedNonce, err := hashutil.HashString(nonce)
		assert.NoError(t, err)

		mockJwtInfo := &oauth.JwtInfo{
			TokenResponse: *mockTokenResponse,
			IdToken: &oauth.JwtToken{
				Claims: map[string]interface{}{
					"nonce": hashedNonce,
				},
			},
		}

		mockTokenParser.On("DecodeAndValidateTokenResponse", mockTokenResponse).Return(mockJwtInfo, nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "/dashboard", rr.Header().Get("Location"))

		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockTokenExchanger.AssertExpectations(t)
		mockTokenParser.AssertExpectations(t)
	})
}

func TestHandleAuthCallbackPost_Failures(t *testing.T) {
	t.Run("Missing state in session", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		req, _ := http.NewRequest("POST", "/auth/callback", nil)
		rr := httptest.NewRecorder()

		// Add settings to the context
		settings := &models.Settings{
			AESEncryptionKey: []byte("test_encryption_key_000000000000"),
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "expecting state in the session, but it was nil"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("State mismatch", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "invalid_state")
		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		// Add settings to the context
		settings := &models.Settings{
			AESEncryptionKey: []byte("test_encryption_key_000000000000"),
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "state from session is different from state posted"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Missing code verifier in session", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		// Add settings to the context
		settings := &models.Settings{
			AESEncryptionKey: []byte("test_encryption_key_000000000000"),
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "expecting code verifier in the session, but it was nil"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Missing redirect URI in session", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		// Add settings to the context
		settings := &models.Settings{
			AESEncryptionKey: []byte("test_encryption_key_000000000000"),
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "expecting redirect URI in the session, but it was nil"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Missing code in form data", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		// Add settings to the context
		settings := &models.Settings{
			AESEncryptionKey: []byte("test_encryption_key_000000000000"),
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "expecting code, but it was empty"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Code not found in database", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		form.Add("code", "valid_code")
		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		// Add settings to the context
		settings := &models.Settings{
			AESEncryptionKey: []byte("test_encryption_key_000000000000"),
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(nil, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "expecting code, but it was nil"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Token exchange error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		form.Add("code", "valid_code")

		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		aesEncryptionKey := []byte("test_encryption_key_000000000000")
		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSession.Values[constants.SessionKeyNonce] = "test_nonce"
		mockSession.Values[constants.SessionKeyRedirectBack] = "/dashboard"

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(&models.Code{
			Id:       1,
			ClientId: 1,
		}, nil)

		mockDB.On("CodeLoadClient", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

		clientSecret := "client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(&models.Client{
			Id:                    1,
			ClientIdentifier:      "test_client",
			ClientSecretEncrypted: clientSecretEncrypted,
		}, nil)

		mockTokenExchanger.On("ExchangeCodeForTokens",
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
		).Return(nil, errors.New("token exchange failed"))

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "could not exchange code for tokens")
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockTokenExchanger.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Token parsing error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		form.Add("code", "valid_code")

		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		aesEncryptionKey := []byte("test_encryption_key_000000000000")
		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSession.Values[constants.SessionKeyNonce] = "test_nonce"
		mockSession.Values[constants.SessionKeyRedirectBack] = "/dashboard"

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(&models.Code{
			Id:       1,
			ClientId: 1,
		}, nil)

		mockDB.On("CodeLoadClient", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

		clientSecret := "client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(&models.Client{
			Id:                    1,
			ClientIdentifier:      "test_client",
			ClientSecretEncrypted: clientSecretEncrypted,
		}, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "access_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh_token",
			IdToken:      "id_token",
		}

		mockTokenExchanger.On("ExchangeCodeForTokens",
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
		).Return(mockTokenResponse, nil)

		mockTokenParser.On("DecodeAndValidateTokenResponse", mockTokenResponse).Return(nil, errors.New("token parsing failed"))

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "error parsing token response")
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockTokenExchanger.AssertExpectations(t)
		mockTokenParser.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Nonce mismatch", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		form.Add("code", "valid_code")

		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		aesEncryptionKey := []byte("test_encryption_key_000000000000")
		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSession.Values[constants.SessionKeyNonce] = "session_nonce"
		mockSession.Values[constants.SessionKeyRedirectBack] = "/dashboard"

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(&models.Code{
			Id:       1,
			ClientId: 1,
		}, nil)

		mockDB.On("CodeLoadClient", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

		clientSecret := "client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(&models.Client{
			Id:                    1,
			ClientIdentifier:      "test_client",
			ClientSecretEncrypted: clientSecretEncrypted,
		}, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "access_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh_token",
			IdToken:      "id_token",
		}

		mockTokenExchanger.On("ExchangeCodeForTokens",
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
		).Return(mockTokenResponse, nil)

		mockJwtInfo := &oauth.JwtInfo{
			TokenResponse: *mockTokenResponse,
			IdToken: &oauth.JwtToken{
				Claims: map[string]interface{}{
					"nonce": "different_nonce",
				},
			},
		}

		mockTokenParser.On("DecodeAndValidateTokenResponse", mockTokenResponse).Return(mockJwtInfo, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "nonce from session is different from the one in id token")
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockTokenExchanger.AssertExpectations(t)
		mockTokenParser.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Missing redirect back", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		form.Add("code", "valid_code")

		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		aesEncryptionKey := []byte("test_encryption_key_000000000000")
		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSession.Values[constants.SessionKeyNonce] = "test_nonce"
		// Intentionally not setting SessionKeyRedirectBack

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(&models.Code{
			Id:       1,
			ClientId: 1,
		}, nil)

		mockDB.On("CodeLoadClient", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

		clientSecret := "client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(&models.Client{
			Id:                    1,
			ClientIdentifier:      "test_client",
			ClientSecretEncrypted: clientSecretEncrypted,
		}, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "access_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh_token",
			IdToken:      "id_token",
		}

		mockTokenExchanger.On("ExchangeCodeForTokens",
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
		).Return(mockTokenResponse, nil)

		nonce := "test_nonce"
		hashedNonce, _ := hashutil.HashString(nonce)

		mockJwtInfo := &oauth.JwtInfo{
			TokenResponse: *mockTokenResponse,
			IdToken: &oauth.JwtToken{
				Claims: map[string]interface{}{
					"nonce": hashedNonce,
				},
			},
		}

		mockTokenParser.On("DecodeAndValidateTokenResponse", mockTokenResponse).Return(mockJwtInfo, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "expecting referrer but it was nil")
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockTokenExchanger.AssertExpectations(t)
		mockTokenParser.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Error saving session", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		form.Add("code", "valid_code")

		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		aesEncryptionKey := []byte("test_encryption_key_000000000000")
		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSession.Values[constants.SessionKeyNonce] = "test_nonce"
		mockSession.Values[constants.SessionKeyRedirectBack] = "/dashboard"

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(&models.Code{
			Id:       1,
			ClientId: 1,
		}, nil)

		mockDB.On("CodeLoadClient", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

		clientSecret := "client_secret"
		clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, aesEncryptionKey)

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(&models.Client{
			Id:                    1,
			ClientIdentifier:      "test_client",
			ClientSecretEncrypted: clientSecretEncrypted,
		}, nil)

		mockTokenResponse := &oauth.TokenResponse{
			AccessToken:  "access_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh_token",
			IdToken:      "id_token",
		}

		mockTokenExchanger.On("ExchangeCodeForTokens",
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
			mock.AnythingOfType("string"),
		).Return(mockTokenResponse, nil)

		nonce := "test_nonce"
		hashedNonce, _ := hashutil.HashString(nonce)

		mockJwtInfo := &oauth.JwtInfo{
			TokenResponse: *mockTokenResponse,
			IdToken: &oauth.JwtToken{
				Claims: map[string]interface{}{
					"nonce": hashedNonce,
				},
			},
		}

		mockTokenParser.On("DecodeAndValidateTokenResponse", mockTokenResponse).Return(mockJwtInfo, nil)

		mockSessionStore.On("Save", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to save session"))

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "failed to save session"
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockTokenExchanger.AssertExpectations(t)
		mockTokenParser.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid client secret", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockSessionStore := mocks_sessionstore.NewStore(t)
		mockDB := mocks_data.NewDatabase(t)
		mockTokenParser := mocks_oauth.NewTokenParser(t)
		mockTokenExchanger := mocks_oauth.NewTokenExchanger(t)

		handler := HandleAuthCallbackPost(
			mockHttpHelper,
			mockSessionStore,
			mockDB,
			mockTokenParser,
			mockTokenExchanger,
		)

		form := url.Values{}
		form.Add("state", "valid_state")
		form.Add("code", "valid_code")

		req, _ := http.NewRequest("POST", "/auth/callback", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rr := httptest.NewRecorder()

		aesEncryptionKey := []byte("test_encryption_key_000000000000")
		settings := &models.Settings{
			AESEncryptionKey: aesEncryptionKey,
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		mockSession := sessions.NewSession(mockSessionStore, constants.SessionName)
		mockSession.Values[constants.SessionKeyState] = "valid_state"
		mockSession.Values[constants.SessionKeyCodeVerifier] = "code_verifier"
		mockSession.Values[constants.SessionKeyRedirectURI] = "http://localhost:8080/callback"
		mockSession.Values[constants.SessionKeyNonce] = "test_nonce"
		mockSession.Values[constants.SessionKeyRedirectBack] = "/dashboard"

		mockSessionStore.On("Get", mock.Anything, constants.SessionName).Return(mockSession, nil)

		mockDB.On("GetCodeByCodeHash", mock.Anything, mock.AnythingOfType("string"), false).Return(&models.Code{
			Id:       1,
			ClientId: 1,
		}, nil)

		mockDB.On("CodeLoadClient", mock.Anything, mock.AnythingOfType("*models.Code")).Return(nil)

		invalidClientSecretEncrypted := []byte("invalid_encrypted_secret")

		mockDB.On("GetClientByClientIdentifier", mock.Anything, mock.AnythingOfType("string")).Return(&models.Client{
			Id:                    1,
			ClientIdentifier:      "test_client",
			ClientSecretEncrypted: invalidClientSecretEncrypted,
		}, nil)

		mockHttpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "cipher: message authentication failed")
		})).Return()

		handler.ServeHTTP(rr, req)

		mockSessionStore.AssertExpectations(t)
		mockDB.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}
