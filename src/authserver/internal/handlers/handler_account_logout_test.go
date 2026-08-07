package handlers

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mocks_sessionstore "github.com/leodip/goiabada/core/sessionstore/mocks"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// encryptIDTokenHintForTest builds a compact JWE id_token_hint the way a client
// must: dir + A256GCM with the key derived from the client secret (SHA-256).
// This mirrors the documented wire contract the logout endpoint decrypts.
func encryptIDTokenHintForTest(t *testing.T, innerToken, clientSecret string) string {
	t.Helper()
	key := encryption.DeriveIDTokenHintKey(clientSecret)
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	obj, err := encrypter.Encrypt([]byte(innerToken))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return compact
}

func TestHandleAccountLogoutGet(t *testing.T) {
	t.Run("No id token hint given", func(t *testing.T) {

		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req, _ := http.NewRequest("GET", "/logout", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("GetFromUrlQueryOrFormPost", req, "id_token_hint").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "post_logout_redirect_uri").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "client_id").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "ui_locales").Return("")
		httpHelper.On("LookupFromUrlQueryOrFormPost", req, "state").Return("", false)
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/logout_consent.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			_, hasCsrfField := data["csrfField"]
			return hasCsrfField
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
	})

	// The consent page must carry forward everything the confirming POST needs, and it must NOT
	// carry the id_token_hint. Dropping the hint is what stops a cross-site POST with a bogus hint
	// from being converted into a teardown once the POST binding is CSRF-exempt on hint presence:
	// confirming this page is always a hintless POST, and a hintless POST had to pass CSRF (#109).
	t.Run("Hintless GET carries the confirming POST's fields and never the hint", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req, _ := http.NewRequest("GET", "/auth/logout", nil)
		rr := httptest.NewRecorder()
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))

		httpHelper.On("GetFromUrlQueryOrFormPost", req, "id_token_hint").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "post_logout_redirect_uri").Return("https://example.com/out")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "client_id").Return("test_client")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "ui_locales").Return("pt-BR")
		httpHelper.On("LookupFromUrlQueryOrFormPost", req, "state").Return("abc", true)

		var bound map[string]interface{}
		httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logout_consent.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				bound = data
				return true
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, "/auth/logout", bound["formAction"])
		assert.Equal(t, "https://example.com/out", bound["postLogoutRedirectUri"])
		assert.Equal(t, "test_client", bound["clientId"])
		assert.Equal(t, "abc", bound["state"])
		assert.Equal(t, true, bound["statePresent"])
		assert.Equal(t, "pt-BR", bound["uiLocales"])
		assert.NotContains(t, bound, "idTokenHint")
		httpHelper.AssertExpectations(t)
	})

	// state supplied empty and state absent are different requests, and the difference has to
	// survive the consent hop: the hidden field is emitted on presence, so an RP that sent nothing
	// does not get "state=" invented for it on the way back (#109 decision 16).
	t.Run("Hintless GET distinguishes an empty state from an absent one", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			value   string
			present bool
		}{
			{"supplied empty", "", true},
			{"absent", "", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				httpSession := mocks_sessionstore.NewStore(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				tokenParser := mocks_oauth.NewTokenParser(t)
				auditLogger := mocks_audit.NewAuditLogger(t)
				handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

				req, _ := http.NewRequest("GET", "/auth/logout", nil)
				rr := httptest.NewRecorder()
				req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))

				httpHelper.On("GetFromUrlQueryOrFormPost", req, mock.Anything).Return("")
				httpHelper.On("LookupFromUrlQueryOrFormPost", req, "state").Return(tc.value, tc.present)

				var bound map[string]interface{}
				httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logout_consent.html",
					mock.MatchedBy(func(data map[string]interface{}) bool {
						bound = data
						return true
					})).Return(nil)

				handler.ServeHTTP(rr, req)

				assert.Equal(t, tc.present, bound["statePresent"])
				assert.Equal(t, tc.value, bound["state"])
			})
		}
	})

	// The global locale middleware reads the query only, so a GET's ui_locales already reaches it.
	// This case exists to pin that the handler's own refinement does not undo that, and it is the
	// half of decision 17 the POST case below completes.
	t.Run("Hintless GET honours ui_locales", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req, _ := http.NewRequest("GET", "/auth/logout?ui_locales=pt-BR", nil)
		rr := httptest.NewRecorder()
		req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, mock.Anything).Return("")
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("", false)
		httpHelper.On("RenderTemplate", rr, mock.MatchedBy(func(rendered *http.Request) bool {
			return i18n.T(rendered.Context(), "logout_consent.title") == "Sair"
		}), "/layouts/auth_layout.html", "/logout_consent.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("No postLogoutRedirectURI given", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint=sometoken", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("GetFromUrlQueryOrFormPost", req, "id_token_hint").Return("sometoken")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "post_logout_redirect_uri").Return("")
		httpHelper.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html", "/auth_error.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			title, hasTitle := data["title"].(string)
			error, hasError := data["error"].(string)
			return hasTitle && title == "Logout error" &&
				hasError && error == "The post_logout_redirect_uri parameter is required. This parameter must match one of the redirect URIs that was registered for this client."
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Fails to parse encrypted idTokenHint as JWE", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
		assert.Nil(t, err)

		// A 5-segment token is detected as a JWE, but this one is malformed, so
		// JWE parsing fails and the handler reports a decrypt failure.
		idTokenHint := "not.a.valid.jwe.token"
		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHint)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHint)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(&models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
		}, nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html", mock.MatchedBy(func(data map[string]interface{}) bool {
			errorMsg, ok := data["error"].(string)
			return ok && strings.Contains(errorMsg, "Failed to decrypt the id_token_hint.")
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Fails to decrypt idTokenHint", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
		assert.Nil(t, err)

		// A structurally valid JWE, but encrypted with a different secret than the
		// client's, so authenticated decryption fails.
		idTokenHint := encryptIDTokenHintForTest(t, "some_id_token", "a-different-client-secret")
		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHint)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHint)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "Failed to decrypt the id_token_hint")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Token parser fails to validate id token", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		idTokenHint := "some_id_token"
		idTokenHintEncryptedBase64 := encryptIDTokenHintForTest(t, idTokenHint, clientSecret)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		settings := &models.Settings{}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		tokenParser.On("DecodeAndValidateTokenString", idTokenHint, (*rsa.PublicKey)(nil), true).
			Return(nil, errors.New("some error")).Once()

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "The id_token_hint parameter is invalid.")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
	})

	t.Run("Issuer does not match", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		idTokenHint := "some_id_token"
		idTokenHintEncryptedBase64 := encryptIDTokenHintForTest(t, idTokenHint, clientSecret)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		config.GetAuthServer().BaseURL = "http://correct-issuer.com"
		settings := &models.Settings{
			Issuer: config.GetAuthServer().BaseURL,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": "http://wrong-issuer.com",
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", idTokenHint, (*rsa.PublicKey)(nil), true).Return(mockIdToken, nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "The id_token_hint parameter is invalid: the iss claim does not match the issuer of this server.")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Aud claim does not match any client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		idTokenHint := "some_id_token"
		idTokenHintEncryptedBase64 := encryptIDTokenHintForTest(t, idTokenHint, clientSecret)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		config.GetAuthServer().BaseURL = "http://correct-issuer.com"
		settings := &models.Settings{
			Issuer: config.GetAuthServer().BaseURL,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.GetAuthServer().BaseURL,
				"aud": "non_existent_client_id",
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", idTokenHint, (*rsa.PublicKey)(nil), true).Return(mockIdToken, nil)
		database.On("GetClientByClientIdentifier", mock.Anything, "non_existent_client_id").Return(nil, nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "Invalid client.")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Post logout redirect URI not authorized", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		idTokenHint := "some_id_token"
		idTokenHintEncryptedBase64 := encryptIDTokenHintForTest(t, idTokenHint, clientSecret)

		unauthorizedRedirectURI := "http://unauthorized-redirect.com"
		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri="+url.QueryEscape(unauthorizedRedirectURI)+"&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		config.GetAuthServer().BaseURL = "http://correct-issuer.com"
		settings := &models.Settings{
			Issuer: config.GetAuthServer().BaseURL,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", req, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "post_logout_redirect_uri").Return(unauthorizedRedirectURI)
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.GetAuthServer().BaseURL,
				"aud": "someclientid",
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", idTokenHint, (*rsa.PublicKey)(nil), true).Return(mockIdToken, nil)

		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			client := args.Get(1).(*models.Client)
			client.RedirectURIs = []models.RedirectURI{
				{URI: "http://authorized-redirect.com"},
			}
		}).Return(nil)

		httpHelper.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html",
			mock.MatchedBy(func(bind map[string]interface{}) bool {
				errorMsg, ok := bind["error"].(string)
				return ok && strings.Contains(errorMsg, "Invalid post_logout_redirect_uri")
			})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("SessionIdentifier exists but sid claim is missing from ID token", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		idTokenHint := "some_id_token"
		idTokenHintEncryptedBase64 := encryptIDTokenHintForTest(t, idTokenHint, clientSecret)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		config.GetAuthServer().BaseURL = "http://correct-issuer.com"
		settings := &models.Settings{
			Issuer: config.GetAuthServer().BaseURL,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "existing-session-id")
		req = req.WithContext(ctx)

		client := &models.Client{
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.GetAuthServer().BaseURL,
				"aud": "someclientid",
				// Note: 'sid' claim is intentionally missing
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", idTokenHint, (*rsa.PublicKey)(nil), true).Return(mockIdToken, nil)

		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			client := args.Get(1).(*models.Client)
			client.RedirectURIs = []models.RedirectURI{
				{URI: "http://example.com"},
			}
		}).Return(nil)

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err != nil && err.Error() == "Invalid session identifier in id_token_hint"
		})).Return(nil).Once()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Sid claim does not match", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		idTokenHint := "some_id_token"
		idTokenHintEncryptedBase64 := encryptIDTokenHintForTest(t, idTokenHint, clientSecret)

		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid", nil)
		rr := httptest.NewRecorder()

		config.GetAuthServer().BaseURL = "http://correct-issuer.com"
		settings := &models.Settings{Issuer: config.GetAuthServer().BaseURL}
		ctx := context.WithValue(req.Context(), constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, "existing-session-id")
		req = req.WithContext(ctx)

		client := &models.Client{ClientSecretEncrypted: clientSecretEncrypted, ClientIdentifier: "someclientid"}
		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.GetAuthServer().BaseURL,
				"aud": "someclientid",
				"sid": "some-other-session-id",
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", idTokenHint, (*rsa.PublicKey)(nil), true).Return(mockIdToken, nil)

		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			client := args.Get(1).(*models.Client)
			client.RedirectURIs = []models.RedirectURI{{URI: "http://example.com"}}
		}).Return(nil)

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err != nil && err.Error() == "Invalid session identifier in id_token_hint"
		})).Return(nil).Once()

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Successful logout with DeleteUserSession call", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		clientSecret := "some_client_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)

		idTokenHint := "some_id_token"
		idTokenHintEncryptedBase64 := encryptIDTokenHintForTest(t, idTokenHint, clientSecret)

		sessionIdentifier := "existing-session-id"
		req, _ := http.NewRequest("GET", "/logout?id_token_hint="+url.QueryEscape(idTokenHintEncryptedBase64)+"&post_logout_redirect_uri=http://example.com&client_id=someclientid&state=abc123", nil)
		rr := httptest.NewRecorder()

		config.GetAuthServer().BaseURL = "http://correct-issuer.com"
		settings := &models.Settings{
			Issuer: config.GetAuthServer().BaseURL,
		}
		ctx := req.Context()
		ctx = context.WithValue(ctx, constants.ContextKeySettings, settings)
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
		req = req.WithContext(ctx)

		client := &models.Client{
			Id:                    1,
			ClientSecretEncrypted: clientSecretEncrypted,
			ClientIdentifier:      "someclientid",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "someclientid").Return(client, nil)

		mockIdToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"iss": config.GetAuthServer().BaseURL,
				"aud": "someclientid",
				"sid": sessionIdentifier,
			},
		}

		tokenParser.On("DecodeAndValidateTokenString", idTokenHint, (*rsa.PublicKey)(nil), true).Return(mockIdToken, nil)

		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			client := args.Get(1).(*models.Client)
			client.RedirectURIs = []models.RedirectURI{
				{URI: "http://example.com"},
			}
		}).Return(nil)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			Clients: []models.UserSessionClient{
				{
					Id:       1,
					ClientId: 1,
					Client:   *client,
				},
			},
		}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
		database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)
		database.On("DeleteUserSessionClient", mock.Anything, int64(1)).Return(nil)
		database.On("DeleteUserSession", mock.Anything, int64(1)).Return(nil)

		auditLogger.On("Log", constants.AuditDeletedUserSessionClient, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditLogout, mock.Anything).Return()

		mockSession := &sessions.Session{
			Values: make(map[interface{}]interface{}),
		}
		httpSession.On("Get", mock.Anything, constants.AuthServerSessionName).Return(mockSession, nil)
		httpSession.On("Save", mock.Anything, mock.Anything, mockSession).Return(nil)

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(idTokenHintEncryptedBase64)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("http://example.com")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("someclientid")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "state").Return("abc-123")

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "http://example.com?sid="+sessionIdentifier+"&state=abc-123")

		httpHelper.AssertExpectations(t)
		tokenParser.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		httpSession.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})
}

func TestIsEncryptedIDTokenHint(t *testing.T) {
	tests := []struct {
		name string
		hint string
		want bool
	}{
		{"compact JWE (5 segments)", "a.b.c.d.e", true},
		{"compact JWS (3 segments)", "a.b.c", false},
		{"plain string", "not-a-token", false},
		{"empty", "", false},
		{"too many segments", "a.b.c.d.e.f", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEncryptedIDTokenHint(tt.hint); got != tt.want {
				t.Errorf("isEncryptedIDTokenHint(%q) = %v, want %v", tt.hint, got, tt.want)
			}
		})
	}
}

func TestDecryptIDTokenHint(t *testing.T) {

	t.Run("Successful decryption", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		clientSecret := "test_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)
		client := &models.Client{ClientSecretEncrypted: clientSecretEncrypted}
		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		innerToken := "test_token"
		jwe := encryptIDTokenHintForTest(t, innerToken, clientSecret)

		result, err := decryptIDTokenHint(jwe, "test_client", database)

		assert.Nil(t, err)
		assert.Equal(t, innerToken, result)
	})

	t.Run("Invalid client", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		database.On("GetClientByClientIdentifier", mock.Anything, "invalid_client").Return(nil, nil)

		_, err := decryptIDTokenHint("a.b.c.d.e", "invalid_client", database)

		assert.NotNil(t, err)
		assert.Equal(t, i18n.ErrCodeLogoutInvalidClient, err.Code)
	})

	t.Run("Not a valid JWE", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		clientSecret := "test_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)
		client := &models.Client{ClientSecretEncrypted: clientSecretEncrypted}
		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		_, err := decryptIDTokenHint("not.a.valid.jwe.token", "test_client", database)

		assert.NotNil(t, err)
		assert.Equal(t, i18n.ErrCodeLogoutIdTokenHintDecryptFailed, err.Code)
	})

	t.Run("Decryption failure (wrong key)", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		clientSecret := "test_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)
		client := &models.Client{ClientSecretEncrypted: clientSecretEncrypted}
		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		// Encrypted with a different secret than the client's.
		jwe := encryptIDTokenHintForTest(t, "test_token", "a-different-secret")

		_, err := decryptIDTokenHint(jwe, "test_client", database)

		assert.NotNil(t, err)
		assert.Equal(t, i18n.ErrCodeLogoutIdTokenHintDecryptFailed, err.Code)
	})
}

func TestValidateClientAndRedirectURI(t *testing.T) {
	t.Run("Valid client and redirect URI", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"aud": "test_client",
			},
		}
		postLogoutRedirectURI := "https://example.com/logout"
		clientId := "test_client"

		client := &models.Client{
			ClientIdentifier: "test_client",
			RedirectURIs: []models.RedirectURI{
				{URI: "https://example.com/logout"},
			},
		}

		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			// RedirectURIs are already set, so we don't need to do anything here
		}).Return(nil)

		result, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.Nil(t, err)
		assert.Equal(t, client, result)
	})

	t.Run("Missing aud claim", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{},
		}
		postLogoutRedirectURI := "https://example.com/logout"
		clientId := "test_client"

		_, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.NotNil(t, err)
		assert.Equal(t, i18n.ErrCodeLogoutAudClaimMissing, err.Code)
	})

	t.Run("Invalid client", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"aud": "invalid_client",
			},
		}
		postLogoutRedirectURI := "https://example.com/logout"
		clientId := "invalid_client"

		database.On("GetClientByClientIdentifier", mock.Anything, "invalid_client").Return(nil, nil)

		_, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.NotNil(t, err)
		assert.Equal(t, i18n.ErrCodeLogoutInvalidClient, err.Code)
	})

	t.Run("Mismatched client_id", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"aud": "test_client",
			},
		}
		postLogoutRedirectURI := "https://example.com/logout"
		clientId := "different_client"

		// Set up mock for GetClientByClientIdentifier
		client := &models.Client{
			ClientIdentifier: "test_client",
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		_, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.NotNil(t, err)
		assert.Equal(t, i18n.ErrCodeLogoutClientIdMismatch, err.Code)
	})

	t.Run("Invalid redirect URI", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"aud": "test_client",
			},
		}
		postLogoutRedirectURI := "https://example.com/invalid"
		clientId := "test_client"

		client := &models.Client{
			ClientIdentifier: "test_client",
			RedirectURIs: []models.RedirectURI{
				{URI: "https://example.com/logout"},
			},
		}

		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
		database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
			// RedirectURIs are already set, so we don't need to do anything here
		}).Return(nil)

		_, err := validateClientAndRedirectURI(idToken, postLogoutRedirectURI, database, clientId)

		assert.NotNil(t, err)
		assert.Equal(t, i18n.ErrCodeLogoutInvalidPostLogoutRedirect, err.Code)
	})
}

func TestHandleExistingSessionOnLogout(t *testing.T) {
	t.Run("Invalid session identifier", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "different-session",
			},
		}
		client := &models.Client{}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid session identifier in id_token_hint")
	})

	t.Run("Session not found", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "test-session",
			},
		}
		client := &models.Client{}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(nil, nil)

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.NoError(t, err) // The function should not return an error if the session is not found
		database.AssertExpectations(t)
	})

	t.Run("Delete user session client", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "test-session",
			},
		}
		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			Clients: []models.UserSessionClient{
				{
					Id: 1,
					Client: models.Client{
						ClientIdentifier: "test-client",
					},
				},
				{
					Id: 2,
					Client: models.Client{
						ClientIdentifier: "other-client",
					},
				},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
		database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)
		database.On("DeleteUserSessionClient", mock.Anything, int64(1)).Return(nil)
		// We don't expect DeleteUserSession to be called in this case

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")

		auditLogger.On("Log", constants.AuditDeletedUserSessionClient, mock.Anything).Return()

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.NoError(t, err)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Delete entire user session", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "test-session",
			},
		}
		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			Clients: []models.UserSessionClient{
				{
					Id: 1,
					Client: models.Client{
						ClientIdentifier: "test-client",
					},
				},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
		database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)
		database.On("DeleteUserSessionClient", mock.Anything, int64(1)).Return(nil)
		database.On("DeleteUserSession", mock.Anything, int64(1)).Return(nil)

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")

		auditLogger.On("Log", constants.AuditDeletedUserSessionClient, mock.Anything).Return()
		auditLogger.On("Log", constants.AuditLogout, mock.Anything).Return()

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.NoError(t, err)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Client not found in user session", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
		idToken := &oauth.JwtToken{
			Claims: map[string]interface{}{
				"sid": "test-session",
			},
		}
		client := &models.Client{
			ClientIdentifier: "test-client",
		}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		userSession := &models.UserSession{
			Id:     1,
			UserId: 123,
			Clients: []models.UserSessionClient{
				{
					Id: 1,
					Client: models.Client{
						ClientIdentifier: "other-client",
					},
				},
			},
		}

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
		database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
		database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)

		err := handleExistingSessionOnLogout(r, sessionIdentifier, idToken, client, database, auditLogger, authHelper)

		assert.NoError(t, err) // The function should not return an error if the client is not found in the session
		database.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log")
		authHelper.AssertNotCalled(t, "GetLoggedInSubject")
	})
}

// logoutPostRequest builds a hintless POST the way the consent form submits one: a real
// urlencoded body, because refineLogoutLocale reads ui_locales straight off the request with
// r.FormValue rather than through the mocked HttpHelper.
func logoutPostRequest(t *testing.T, form url.Values) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "/auth/logout", strings.NewReader(form.Encode()))
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req.WithContext(context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{}))
}

// withSessionIdentifier puts the identifier the session-identifier middleware would have attached,
// which it does only when the cookie's session still resolves to a live row.
func withSessionIdentifier(req *http.Request, sessionIdentifier string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), constants.ContextKeySessionIdentifier, sessionIdentifier))
}

// expectCookieWipedBeforeSave stubs the session store for a request that reaches the terminal
// response, and pins the ordering the wipe depends on: the session must already be empty at the
// moment it is serialized.
//
// Two things make this the only assertion that works, and both were demonstrated by mutation rather
// than reasoned about. The wipe replaces the map on the session in place, so reading the same pointer
// after the handler returns cannot tell a wipe that ran before the save from one that ran after it,
// and moving it after the save leaves such a check green. And seeding the session non-empty is what
// makes an omitted wipe fail at all, so a case that starts from an empty map proves nothing on this
// axis whatever it asserts afterwards.
//
// The invariant is unconditional and belongs on every branch: the cookie IS the OP session, so a
// response that writes it back still carrying the session identifier leaves the End-User signed in
// at the OP immediately after asking to be signed out. It matters most on the redirect branch, where
// the browser goes straight back to a relying party (#109).
func expectCookieWipedBeforeSave(t *testing.T, httpSession *mocks_sessionstore.Store) *sessions.Session {
	t.Helper()
	sess := &sessions.Session{Values: map[interface{}]interface{}{"something": "here"}}
	httpSession.On("Get", mock.Anything, constants.AuthServerSessionName).Return(sess, nil)
	httpSession.On("Save", mock.Anything, mock.Anything, sess).
		Run(func(args mock.Arguments) {
			assert.Empty(t, args.Get(2).(*sessions.Session).Values,
				"the OP session cookie must be cleared before it is written back")
		}).Return(nil)
	return sess
}

// TestHandleAccountLogoutPost covers the hintless half of the endpoint. Reaching the POST binding
// without a hint means the confirming submission of the consent page, so these cases are what a
// user sees after answering "yes".
//
// Every one of them asserts the teardown, whatever the redirect target turned out to be. That is
// the property #109 is about: the parameters used to be validated first and every failure returned
// before both the database teardown and the cookie wipe, so a user who asked to be logged out and
// got an error page was still logged in.
func TestHandleAccountLogoutPost(t *testing.T) {

	t.Run("Deletes the whole session and lands on the signed-out page", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req := withSessionIdentifier(logoutPostRequest(t, url.Values{}), "test-session")
		rr := httptest.NewRecorder()

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")

		userSession := &models.UserSession{Id: 42, UserId: 123}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(userSession, nil)
		database.On("DeleteUserSession", mock.Anything, int64(42)).Return(nil)

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")

		auditLogger.On("Log", constants.AuditDeletedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userSessionId"] == int64(42) && details["loggedInUser"] == "user-123"
		})).Return()
		auditLogger.On("Log", constants.AuditLogout, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) &&
				details["sessionIdentifier"] == "test-session" &&
				details["loggedInUser"] == "user-123"
		})).Return()

		mockSession := expectCookieWipedBeforeSave(t, httpSession)

		httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logged_out.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["redirectDeclined"] == false
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Empty(t, mockSession.Values, "the OP session cookie must be cleared")
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		httpSession.AssertExpectations(t)
	})

	// Decision 4: client_id is the "other means of confirming the legitimacy of the post-logout
	// redirection target" the spec requires when there is no id_token_hint to read a signed aud
	// from. The state here is the one the concatenation this replaced could not carry: "+" decoded
	// to a space, "/" and "=" were left raw, and "#" and "&" truncated it or injected parameters.
	t.Run("client_id plus a registered URI redirects, with exactly one state and no sid", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req := withSessionIdentifier(logoutPostRequest(t, url.Values{}), "test-session")
		rr := httptest.NewRecorder()

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("https://example.com/out?state=registered&lang=en")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("test_client")
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("aB+cd/efgh==#&x=1", true)

		client := &models.Client{
			ClientIdentifier: "test_client",
			RedirectURIs:     []models.RedirectURI{{URI: "https://example.com/out?state=registered&lang=en"}},
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
		database.On("ClientLoadRedirectURIs", mock.Anything, client).Return(nil)

		userSession := &models.UserSession{Id: 42, UserId: 123}
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(userSession, nil)
		database.On("DeleteUserSession", mock.Anything, int64(42)).Return(nil)

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")
		auditLogger.On("Log", mock.Anything, mock.Anything).Return()

		// The redirect branch is the one where an omitted or late wipe hides: the browser leaves for
		// the relying party immediately, so nothing else in the response would show that the OP
		// session cookie went back out intact.
		mockSession := expectCookieWipedBeforeSave(t, httpSession)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location, err := url.Parse(rr.Header().Get("Location"))
		assert.NoError(t, err)
		assert.Equal(t, "https://example.com/out", location.Scheme+"://"+location.Host+location.Path)
		assert.Equal(t, []string{"aB+cd/efgh==#&x=1"}, location.Query()["state"],
			"exactly one state, byte-identical to what the RP sent")
		assert.Equal(t, "en", location.Query().Get("lang"), "the registered query survives")
		assert.Empty(t, location.Query().Get("sid"), "sid is not a parameter RP-initiated logout defines")
		assert.Empty(t, mockSession.Values, "the OP session cookie must be cleared")
		database.AssertExpectations(t)
		httpSession.AssertExpectations(t)
	})

	// Every way a target fails to authorize. Each one still tears the session down and lands on the
	// signed-out page with the note, because whether a redirect can be honoured is a question about
	// the response and never about whether the logout happens (#109).
	//
	// The table is three groups that fail for different reasons, and only the first is ordinary.
	// Rows 1 to 3 are plain refusals: the request did not earn a redirect. Rows 4 to 11 are near
	// misses, where the requested URI differs from a registered one in a way exact string comparison
	// catches and a looser one does not; they exist because no plain refusal can tell those apart,
	// so every loose comparison listed below passed this table before its row was added. Rows 12 to
	// 14 are faults, a database that will not answer and a registered URI that will not parse, and
	// those are the shapes where a plausible future edit turns "lose the redirect" into "return a
	// 500", which would put a user who is still signed in on a terminal page. Every row asserts the
	// whole teardown and the absence of an InternalServerError, not just the absent Location.
	//
	// The near misses come in two families, and each row differs from its registration in exactly
	// one respect so that it names the comparison it kills. Rows 4 to 6 kill comparisons that are
	// loose about the string: prefix in either direction, substring, and case folding. Rows 7 to 11
	// kill comparisons that parse the URI and then compare or normalize selected components, which
	// is the family that survives a table built only from the first: each of query omission, scheme
	// omission, trailing-slash normalization, percent-decoding the path, and default-port
	// normalization accepts a URI no operator registered.
	t.Run("A target that cannot be authorized is declined, and the logout still happens", func(t *testing.T) {
		const unparseableURI = "https://example.com/out\x7f"

		// One registered URI on test_client, so a row need only say how the requested URI differs.
		registers := func(uri string) func(*mocks_data.Database) {
			return func(database *mocks_data.Database) {
				client := &models.Client{
					ClientIdentifier: "test_client",
					RedirectURIs:     []models.RedirectURI{{URI: uri}},
				}
				database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
				database.On("ClientLoadRedirectURIs", mock.Anything, client).Return(nil)
			}
		}

		// A near-miss row reaches the state lookup only if the comparison has been loosened, so the
		// stub is optional. Allowing it means a loosened build runs on and fails on the assertions
		// that state the property, rather than dying earlier on an unexpected mock call.
		allowStateLookup := func(httpHelper *mocks_handlerhelpers.HttpHelper) {
			httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("abc", true).Maybe()
		}

		for _, tc := range []struct {
			name        string
			clientId    string
			redirectURI string
			stubDB      func(database *mocks_data.Database)
			stubHelper  func(httpHelper *mocks_handlerhelpers.HttpHelper)
		}{
			{
				name:     "no client_id, so nothing can confirm the target",
				clientId: "",
				stubDB:   func(database *mocks_data.Database) {},
			},
			{
				name:     "client_id names no client",
				clientId: "ghost_client",
				stubDB: func(database *mocks_data.Database) {
					database.On("GetClientByClientIdentifier", mock.Anything, "ghost_client").Return(nil, nil)
				},
			},
			{
				name:     "the URI is not registered to the named client",
				clientId: "test_client",
				stubDB:   registers("https://example.com/somewhere-else"),
			},
			{
				// The classic loose-match bypass. The requested URI begins with the whole registered
				// value, so HasPrefix or Contains accepts it, while url.Parse reads
				// "trusted.example" as userinfo and sends the browser to evil.example. Only exact
				// string comparison refuses it, which both governing texts require: RP-Initiated
				// Logout 1.0 section 3, "the OP also MUST NOT perform post-logout redirection if the
				// post_logout_redirect_uri value supplied does not exactly match one of the
				// previously registered post_logout_redirect_uris values", and RFC 9700 section 2.1,
				// "authorization servers MUST utilize exact string matching".
				name:        "the requested URI only starts with a registered one",
				clientId:    "test_client",
				redirectURI: "https://trusted.example@evil.example/callback",
				stubDB:      registers("https://trusted.example"),
				stubHelper:  allowStateLookup,
			},
			{
				// The same defect with the operands reversed, which a comparison written as
				// HasPrefix(registered, requested) would accept.
				name:        "a registered URI merely extends the requested one",
				clientId:    "test_client",
				redirectURI: "https://example.com/out",
				stubDB:      registers("https://example.com/out/deeper"),
				stubHelper:  allowStateLookup,
			},
			{
				// Exact means byte for byte, so a case-folded comparison is too loose as well. The
				// path differs in case here and not only the host, and paths are case-sensitive
				// under RFC 3986 section 6.2.2.1.
				name:        "the requested URI differs from a registered one only in case",
				clientId:    "test_client",
				redirectURI: "https://EXAMPLE.com/OUT",
				stubDB:      registers("https://example.com/out"),
				stubHelper:  allowStateLookup,
			},
			{
				// Scheme, authority and path all match, and only the query differs, so a comparison
				// that parses both and omits RawQuery accepts this. That hands an initiator who
				// knows nothing but a public client_id the ability to choose the query the trusted
				// RP's logout endpoint is called with, on a URI its operator never registered.
				name:        "the requested URI differs from a registered one only in its query",
				clientId:    "test_client",
				redirectURI: "https://trusted.example/logout?fixed=2",
				stubDB:      registers("https://trusted.example/logout?fixed=1"),
				stubHelper:  allowStateLookup,
			},
			{
				// Omitting the scheme is the same family and the worst member of it: it turns a
				// registered https target into a cleartext one, so the state the RP relies on for
				// its own CSRF check travels in the clear.
				name:        "the requested URI differs from a registered one only in its scheme",
				clientId:    "test_client",
				redirectURI: "http://example.com/out",
				stubDB:      registers("https://example.com/out"),
				stubHelper:  allowStateLookup,
			},
			{
				// "Exact string matching" leaves no room for the tidying a canonicalizer does, and a
				// trailing slash is the tidying most likely to be reached for. Under RFC 3986
				// section 6.2.2.3 these are different paths, and on many RPs they are different
				// routes.
				name:        "the requested URI differs from a registered one only by a trailing slash",
				clientId:    "test_client",
				redirectURI: "https://example.com/out/",
				stubDB:      registers("https://example.com/out"),
				stubHelper:  allowStateLookup,
			},
			{
				// The subtlest member, and the one a careful implementation walks into: url.URL.Path
				// is percent-decoded, so comparing it rather than EscapedPath() makes %6f and o the
				// same character. Byte-for-byte equality is what both texts ask for, not equality
				// after decoding.
				name:        "the requested URI differs from a registered one only in percent-encoding",
				clientId:    "test_client",
				redirectURI: "https://example.com/%6fut",
				stubDB:      registers("https://example.com/out"),
				stubHelper:  allowStateLookup,
			},
			{
				// A URL canonicalizer drops the port when it is the scheme's default, which makes
				// this pair equal to it and unequal to string comparison. Same family, and it is the
				// one that reads most like a harmless normalization.
				name:        "the requested URI differs from a registered one only by an explicit default port",
				clientId:    "test_client",
				redirectURI: "https://example.com:443/out",
				stubDB:      registers("https://example.com/out"),
				stubHelper:  allowStateLookup,
			},
			{
				name:     "the client lookup fails",
				clientId: "test_client",
				stubDB: func(database *mocks_data.Database) {
					database.On("GetClientByClientIdentifier", mock.Anything, "test_client").
						Return(nil, errors.New("client lookup exploded"))
				},
			},
			{
				name:     "the client's registered URIs cannot be loaded",
				clientId: "test_client",
				stubDB: func(database *mocks_data.Database) {
					client := &models.Client{ClientIdentifier: "test_client"}
					database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)
					database.On("ClientLoadRedirectURIs", mock.Anything, client).
						Return(errors.New("load redirect URIs exploded"))
				},
			},
			{
				// The registered URI matches exactly and then fails to parse, so this row reaches
				// buildPostLogoutRedirect's error return, which nothing else here does. A DEL byte
				// is what url.Parse refuses; the shape is defensive rather than reachable through
				// the admin UI, and defensive is exactly why it needs pinning.
				name:        "the redirect cannot be built from the registered URI",
				clientId:    "test_client",
				redirectURI: unparseableURI,
				stubDB:      registers(unparseableURI),
				stubHelper: func(httpHelper *mocks_handlerhelpers.HttpHelper) {
					httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("abc", true)
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				httpSession := mocks_sessionstore.NewStore(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

				req := withSessionIdentifier(logoutPostRequest(t, url.Values{}), "test-session")
				rr := httptest.NewRecorder()

				redirectURI := tc.redirectURI
				if redirectURI == "" {
					redirectURI = "https://example.com/out"
				}

				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("")
				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return(redirectURI)
				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "client_id").Return(tc.clientId)
				tc.stubDB(database)
				if tc.stubHelper != nil {
					tc.stubHelper(httpHelper)
				}

				userSession := &models.UserSession{Id: 42, UserId: 123}
				database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(userSession, nil)
				database.On("DeleteUserSession", mock.Anything, int64(42)).Return(nil)

				authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")
				auditLogger.On("Log", constants.AuditDeletedUserSession, mock.MatchedBy(func(details map[string]interface{}) bool {
					return details["userSessionId"] == int64(42) && details["loggedInUser"] == "user-123"
				})).Return()
				auditLogger.On("Log", constants.AuditLogout, mock.MatchedBy(func(details map[string]interface{}) bool {
					return details["userId"] == int64(123) && details["sessionIdentifier"] == "test-session"
				})).Return()

				mockSession := expectCookieWipedBeforeSave(t, httpSession)

				httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logged_out.html",
					mock.MatchedBy(func(data map[string]interface{}) bool {
						return data["redirectDeclined"] == true
					})).Return(nil)

				handler.ServeHTTP(rr, req)

				assert.Empty(t, rr.Header().Get("Location"), "a declined target must never become a redirect")
				assert.Empty(t, mockSession.Values, "the OP session cookie must be cleared")
				httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
				database.AssertExpectations(t)
				httpHelper.AssertExpectations(t)
				auditLogger.AssertExpectations(t)
				httpSession.AssertExpectations(t)
			})
		}
	})

	// Decision 8: a database error and a session that is simply not there used to be one branch,
	// which returned a variable that was sometimes nil to mean both. They have different answers.
	t.Run("A failed teardown is a 500", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			stubDB func(database *mocks_data.Database)
			errMsg string
		}{
			{
				name: "the session lookup fails",
				stubDB: func(database *mocks_data.Database) {
					database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").
						Return(nil, errors.New("lookup exploded"))
				},
				errMsg: "lookup exploded",
			},
			{
				name: "the delete fails",
				stubDB: func(database *mocks_data.Database) {
					userSession := &models.UserSession{Id: 42, UserId: 123}
					database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(userSession, nil)
					database.On("DeleteUserSession", mock.Anything, int64(42)).Return(errors.New("delete exploded"))
				},
				errMsg: "delete exploded",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				httpSession := mocks_sessionstore.NewStore(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

				req := withSessionIdentifier(logoutPostRequest(t, url.Values{}), "test-session")
				rr := httptest.NewRecorder()

				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("")
				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")
				tc.stubDB(database)

				httpHelper.On("InternalServerError", mock.Anything, mock.Anything,
					mock.MatchedBy(func(err error) bool { return err.Error() == tc.errMsg })).
					Run(func(args mock.Arguments) {
						args.Get(0).(http.ResponseWriter).WriteHeader(http.StatusInternalServerError)
					}).Return()

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusInternalServerError, rr.Code)
				// A failed teardown must not be reported as a completed logout.
				auditLogger.AssertNotCalled(t, "Log", constants.AuditLogout, mock.Anything)
				httpHelper.AssertExpectations(t)
			})
		}
	})

	// Decision 10: a hintless logout has nothing to fall back on when the cookie names no live
	// session, because the session-identifier middleware attaches the identifier only when it
	// resolves and there is no id_token_hint to read a sid claim from. Having no session to end is
	// not a failure, so both shapes complete rather than erroring.
	t.Run("Nothing to tear down still completes", func(t *testing.T) {
		for _, tc := range []struct {
			name              string
			sessionIdentifier string
			stubDB            func(database *mocks_data.Database)
		}{
			{
				name:              "no session identifier on the request",
				sessionIdentifier: "",
				stubDB:            func(database *mocks_data.Database) {},
			},
			{
				name:              "the session row is gone",
				sessionIdentifier: "test-session",
				stubDB: func(database *mocks_data.Database) {
					database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(nil, nil)
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
				httpSession := mocks_sessionstore.NewStore(t)
				authHelper := mocks_handlerhelpers.NewAuthHelper(t)
				database := mocks_data.NewDatabase(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

				req := logoutPostRequest(t, url.Values{})
				if tc.sessionIdentifier != "" {
					req = withSessionIdentifier(req, tc.sessionIdentifier)
				}
				rr := httptest.NewRecorder()

				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("")
				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")
				tc.stubDB(database)

				authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")
				auditLogger.On("Log", constants.AuditLogout, mock.MatchedBy(func(details map[string]interface{}) bool {
					return details["userId"] == int64(0) && details["sessionIdentifier"] == tc.sessionIdentifier
				})).Return()

				mockSession := expectCookieWipedBeforeSave(t, httpSession)

				httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logged_out.html",
					mock.Anything).Return(nil)

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusOK, rr.Code)
				assert.Empty(t, mockSession.Values, "the OP session cookie must be cleared")
				database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
				auditLogger.AssertNotCalled(t, "Log", constants.AuditDeletedUserSession, mock.Anything)
				auditLogger.AssertExpectations(t)
			})
		}
	})

	// Decision 17: the confirming POST carries ui_locales in its body, where the global locale
	// middleware cannot see it, so without the handler's own refinement the signed-out page would
	// render in a different language from the consent page the user had just read.
	t.Run("ui_locales in the body only renders the signed-out page in that locale", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req := logoutPostRequest(t, url.Values{"ui_locales": {"pt-BR"}})
		rr := httptest.NewRecorder()

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")
		auditLogger.On("Log", mock.Anything, mock.Anything).Return()

		mockSession := expectCookieWipedBeforeSave(t, httpSession)

		httpHelper.On("RenderTemplate", rr, mock.MatchedBy(func(rendered *http.Request) bool {
			return i18n.T(rendered.Context(), "logged_out.title") == "Sessão encerrada"
		}), "/layouts/auth_layout.html", "/logged_out.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Empty(t, mockSession.Values, "the OP session cookie must be cleared")
		httpHelper.AssertExpectations(t)
	})

	// The other half of decision 17 on this method, and the half the case above cannot reach. A POST
	// carrying a hint returns before doLogoutWithoutIdToken is ever called, so the refinement has to
	// happen above that branch rather than inside the hintless one. Move it down and the case above
	// still passes while every hinted POST that renders anything renders it in the fallback language,
	// which an RP posting ui_locales in its body has no way to correct.
	//
	// Which page comes back is deliberately not asserted: the hinted branch is stage 4's to rewrite,
	// and the property here is that whatever this handler renders is localized from the body. Today
	// the shortest hinted render is the missing-target error page.
	t.Run("ui_locales in the body only reaches a hinted POST's render", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req := logoutPostRequest(t, url.Values{
			"id_token_hint": {"a.b.c"},
			"ui_locales":    {"pt-BR"},
		})
		rr := httptest.NewRecorder()

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("a.b.c")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")

		httpHelper.On("RenderTemplate", rr, mock.MatchedBy(func(rendered *http.Request) bool {
			return i18n.T(rendered.Context(), "logout_consent.title") == "Sair"
		}), mock.Anything, mock.Anything, mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
	})

	t.Run("Session store error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req := logoutPostRequest(t, url.Values{})
		rr := httptest.NewRecorder()

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")
		auditLogger.On("Log", mock.Anything, mock.Anything).Return()

		httpSession.On("Get", mock.Anything, constants.AuthServerSessionName).
			Return(nil, errors.New("session store error"))

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "session store error" })).
			Run(func(args mock.Arguments) {
				args.Get(0).(http.ResponseWriter).WriteHeader(http.StatusInternalServerError)
			}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		httpSession.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Session save error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, auditLogger)

		req := logoutPostRequest(t, url.Values{})
		rr := httptest.NewRecorder()

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")

		authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")
		auditLogger.On("Log", mock.Anything, mock.Anything).Return()

		mockSession := &sessions.Session{Values: make(map[interface{}]interface{})}
		httpSession.On("Get", mock.Anything, constants.AuthServerSessionName).Return(mockSession, nil)
		httpSession.On("Save", mock.Anything, mock.Anything, mockSession).Return(errors.New("session save error"))

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "session save error" })).Return()

		handler.ServeHTTP(rr, req)

		httpSession.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})
}

func TestBuildPostLogoutRedirect(t *testing.T) {
	tests := []struct {
		name          string
		registeredURI string
		state         string
		statePresent  bool
		expected      string
		expectError   bool
	}{
		{
			name:          "Base64 state survives byte-identical",
			registeredURI: "https://app.example.com/out",
			state:         "aB+cd/efgh==",
			statePresent:  true,
			expected:      "https://app.example.com/out?state=aB%2Bcd%2Fefgh%3D%3D",
		},
		{
			name:          "Fragment and parameter separators in state are escaped",
			registeredURI: "https://app.example.com/out",
			state:         "a#b&c=d",
			statePresent:  true,
			expected:      "https://app.example.com/out?state=a%23b%26c%3Dd",
		},
		{
			name:          "Absent state writes no query",
			registeredURI: "https://app.example.com/out",
			state:         "",
			statePresent:  false,
			expected:      "https://app.example.com/out",
		},
		{
			name:          "Empty state supplied comes back empty",
			registeredURI: "https://app.example.com/out",
			state:         "",
			statePresent:  true,
			expected:      "https://app.example.com/out?state=",
		},
		{
			name:          "Whitespace-only state is not trimmed",
			registeredURI: "https://app.example.com/out",
			state:         "   ",
			statePresent:  true,
			expected:      "https://app.example.com/out?state=+++",
		},
		{
			name:          "A registered query is preserved",
			registeredURI: "https://app.example.com/out?lang=en",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?lang=en&state=abc",
		},
		{
			name:          "A registered state is replaced, not duplicated",
			registeredURI: "https://app.example.com/out?state=fixed",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?state=abc",
		},
		{
			// The counterpart to the row above, and it reads like a bug beside it: with
			// no state supplied the builder writes nothing at all, so whatever the
			// registered URI carried survives untouched, including its own state.
			name:          "A registered state survives when none is supplied",
			registeredURI: "https://app.example.com/out?state=fixed",
			state:         "",
			statePresent:  false,
			expected:      "https://app.example.com/out?state=fixed",
		},
		{
			// What forces url.Parse over the model's url.ParseRequestURI: the latter
			// keeps the "#" in the path and yields ".../out%23frag?state=abc".
			name:          "A fragment stays a fragment",
			registeredURI: "https://app.example.com/out#frag",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?state=abc#frag",
		},
		{
			// Registered parameters keep their order. Decoding the query into url.Values
			// and re-encoding it sorts by key, which would rewrite a query an RP signs
			// over as a raw string.
			name:          "Registered parameter order is preserved",
			registeredURI: "https://app.example.com/out?b=2&a=1",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?b=2&a=1&state=abc",
		},
		{
			// The shape that made round-tripping through url.Values lossy: url.ParseQuery
			// rejects a literal semicolon and url.Query throws the error away, so the whole
			// registered query used to vanish and the RP landed on a bare path.
			name:          "A semicolon-separated registered query survives",
			registeredURI: "https://app.example.com/out?lang=en;mode=dark",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?lang=en;mode=dark&state=abc",
		},
		{
			// The same URI with no state, which never went through url.Values at all. The
			// pair is what stops preservation depending on whether the RP sent a state.
			name:          "A semicolon-separated registered query survives with no state",
			registeredURI: "https://app.example.com/out?lang=en;mode=dark",
			state:         "",
			statePresent:  false,
			expected:      "https://app.example.com/out?lang=en;mode=dark",
		},
		{
			name:          "A valueless registered field does not gain an equals sign",
			registeredURI: "https://app.example.com/out?flag",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?flag&state=abc",
		},
		{
			name:          "Registered percent-escapes are not normalised",
			registeredURI: "https://app.example.com/out?p=%7Eok",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?p=%7Eok&state=abc",
		},
		{
			// Field names are decoded before they are compared, so a registered state
			// cannot survive alongside the RP's by hiding behind an escape.
			name:          "A percent-encoded registered state key is still replaced",
			registeredURI: "https://app.example.com/out?%73tate=fixed",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?state=abc",
		},
		{
			name:          "A repeated registered parameter survives intact",
			registeredURI: "https://app.example.com/out?a=1&a=2",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?a=1&a=2&state=abc",
		},
		{
			// An empty field is data the operator registered, not noise. Skipping empty
			// fields while copying is the tidy-looking change that quietly rewrites the
			// target: this row came back as ".../out?a=1&b=2&state=abc" until it did not.
			name:          "An interior empty registered field survives",
			registeredURI: "https://app.example.com/out?a=1&&b=2",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?a=1&&b=2&state=abc",
		},
		{
			// The pair for the row above, on the path that returns the parsed URI
			// untouched. Together they stop preservation depending on whether the RP
			// happened to send a state.
			name:          "An interior empty registered field survives with no state",
			registeredURI: "https://app.example.com/out?a=1&&b=2",
			state:         "",
			statePresent:  false,
			expected:      "https://app.example.com/out?a=1&&b=2",
		},
		{
			name:          "A leading empty registered field survives",
			registeredURI: "https://app.example.com/out?&a=1",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?&a=1&state=abc",
		},
		{
			name:          "A trailing empty registered field survives",
			registeredURI: "https://app.example.com/out?a=1&",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?a=1&&state=abc",
		},
		{
			// Dropping the registered state leaves the empty field behind, so the query
			// opens with a separator. That is the preservation rule applied literally
			// rather than a stray ampersand.
			name:          "A registered state is replaced beside a trailing empty field",
			registeredURI: "https://app.example.com/out?state=fixed&",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?&state=abc",
		},
		{
			// What the RawQuery != "" guard is for. url.Parse leaves RawQuery empty here
			// and sets ForceQuery, and strings.Split("", "&") yields one empty field, so
			// copying unconditionally would emit ".../out?&state=abc".
			name:          "A registered URI ending in a bare question mark gains only state",
			registeredURI: "https://app.example.com/out?",
			state:         "abc",
			statePresent:  true,
			expected:      "https://app.example.com/out?state=abc",
		},
		{
			name:          "An unparseable registered URI is an error, not a panic",
			registeredURI: "://bad",
			state:         "abc",
			statePresent:  true,
			expectError:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := buildPostLogoutRedirect(tc.registeredURI, tc.state, tc.statePresent)
			if tc.expectError {
				assert.Error(t, err)
				assert.Empty(t, result)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestClassifyIdTokenHint is the exhaustive table for the hint classifier. Every negative row
// differs from the confirmed row in exactly one field and names the gate that refuses it, which is
// why the confirmed claims come from a constructor the rows mutate rather than from copy-paste: a
// row that varied two fields could pass because of the field it was not testing.
//
// Nothing calls the classifier yet, so this is the only thing standing behind it until stage 4 wires
// it into the pipeline (#109).
func TestClassifyIdTokenHint(t *testing.T) {
	const (
		theIssuer    = "https://issuer.example"
		theClientId  = "test_client"
		theSessionId = "test-session"
		theHint      = "a.signed.hint"
		// The persisted row ID, distinct from the identifier, because the two are not
		// interchangeable downstream: ClientLoadRedirectURIs queries by Client.Id, so a classifier
		// that rebuilt the client from the identifier alone would carry Id 0 and every registered
		// redirect URI would come back empty (#109).
		theClientDbId int64 = 11
	)

	now := time.Now().UTC()

	// Claims arrive through encoding/json inside jwt.MapClaims, so every numeric claim is a float64.
	// Writing these as int would make GetIntClaim reject values a real token presents perfectly well,
	// and the table would then pass for the wrong reason on every numeric gate.
	confirmedClaims := func() map[string]interface{} {
		return map[string]interface{}{
			"iss": theIssuer,
			"sub": "the-user",
			"iat": float64(now.Add(-2 * time.Minute).Unix()),
			"nbf": float64(now.Add(-2 * time.Minute).Unix()),
			"exp": float64(now.Add(2 * time.Minute).Unix()),
			"aud": theClientId,
			"sid": theSessionId,
		}
	}

	newClient := func() *models.Client {
		return &models.Client{Id: theClientDbId, ClientIdentifier: theClientId}
	}

	// The confirmed row's database: the hint's aud resolves to a client and nothing else is asked.
	// Maybe(), because the rows refused at an earlier gate never get here, and the state assertion is
	// what catches a gate that stopped refusing.
	resolvesClient := func(database *mocks_data.Database) {
		database.On("GetClientByClientIdentifier", mock.Anything, theClientId).Return(newClient(), nil).Maybe()
	}

	// A live session for decision 14's tolerance lookup, which only an expired row reaches.
	resolvesClientAndSession := func(userSession *models.UserSession, err error) func(*mocks_data.Database) {
		return func(database *mocks_data.Database) {
			resolvesClient(database)
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, theSessionId).Return(userSession, err)
		}
	}

	strPtr := func(s string) *string { return &s }

	for _, tc := range []struct {
		name string
		// gate names the check that is expected to refuse the row, so a failure says which one stopped
		// working rather than only that the answer changed.
		gate       string
		mutate     func(claims map[string]interface{})
		hintAbsent bool
		hintValue  *string
		innerToken *string
		// clientId is the value the parameter arrived with; clientIdAbsent says it did not arrive at
		// all. The two are separate fields because the classifier reads client_id for presence, so a
		// row that could only say "" would be unable to tell the gate's two sides apart, which is
		// exactly the hole this pair was added to close.
		clientId       *string
		clientIdAbsent bool
		noSession      bool
		parserErr      error
		stubDB         func(*mocks_data.Database)
		want           hintState
		wantErr        bool
		wantSid        string
	}{
		{
			name: "the confirmed case",
			want: hintConfirmed, wantSid: theSessionId,
		},
		{
			name: "no id_token_hint parameter at all", gate: "presence",
			hintAbsent: true,
			want:       hintAbsent,
		},
		{
			// Rejected rather than absent, and the distinction is load-bearing: the CSRF middleware
			// exempts a cross-site POST on hint PRESENCE and cannot judge validity, so reading
			// "id_token_hint=" as no hint would send an exempted POST down the branch that tears the
			// whole session down without consent.
			name: "id_token_hint supplied with an empty value", gate: "presence",
			hintValue: strPtr(""),
			want:      hintRejected,
		},
		{
			name: "an encrypted hint with no client_id", gate: "JWE key selection",
			hintValue:      strPtr("a.b.c.d.e"),
			clientIdAbsent: true,
			want:           hintRejected,
		},
		{
			// The other side of the key-selection gate, and the reason it reads the VALUE where the
			// gate further down reads the presence: a client_id supplied empty names no client secret
			// either, so it must stop here too rather than reaching the client_id gate.
			name: "an encrypted hint with an empty client_id", gate: "JWE key selection",
			hintValue: strPtr("a.b.c.d.e"),
			clientId:  strPtr(""),
			want:      hintRejected,
		},
		{
			name: "an encrypted hint that will not decrypt", gate: "JWE decryption",
			hintValue: strPtr("a.b.c.d.e"),
			stubDB: func(database *mocks_data.Database) {
				secret, err := encryption.EncryptData("some_client_secret")
				assert.NoError(t, err)
				database.On("GetClientByClientIdentifier", mock.Anything, theClientId).
					Return(&models.Client{ClientIdentifier: theClientId, ClientSecretEncrypted: secret}, nil)
			},
			want: hintRejected,
		},
		{
			// The positive half of the two rows above, and the only thing that pins the decrypted
			// inner token being what gets parsed: the parser is stubbed on the inner value, so a
			// classifier that parsed the JWE itself would find no expectation and fail.
			name: "an encrypted hint that decrypts", gate: "JWE decryption",
			hintValue:  strPtr(encryptIDTokenHintForTest(t, "inner.signed.token", "some_client_secret")),
			innerToken: strPtr("inner.signed.token"),
			stubDB: func(database *mocks_data.Database) {
				secret, err := encryption.EncryptData("some_client_secret")
				assert.NoError(t, err)
				database.On("GetClientByClientIdentifier", mock.Anything, theClientId).
					Return(&models.Client{Id: theClientDbId, ClientIdentifier: theClientId, ClientSecretEncrypted: secret}, nil)
			},
			want: hintConfirmed, wantSid: theSessionId,
		},
		{
			name: "the hint cannot be parsed", gate: "parse and signature",
			parserErr: errors.New("token is malformed"),
			want:      hintRejected,
		},
		{
			name: "the hint is signed with the wrong key", gate: "parse and signature",
			parserErr: errors.New("token signature is invalid"),
			want:      hintRejected,
		},
		{
			// An access token satisfies every other gate under a client/resource identifier
			// collision, so this row is the one standing between a session-bound access token and a
			// consent-free logout. Every other claim is identical to the confirmed row.
			name: "typ says this is an access token", gate: "ID-Token shape",
			mutate: func(claims map[string]interface{}) { claims["typ"] = "Bearer" },
			want:   hintRejected,
		},
		{
			name: "typ says this is an offline refresh token", gate: "ID-Token shape",
			mutate: func(claims map[string]interface{}) { claims["typ"] = "Offline" },
			want:   hintRejected,
		},
		{
			name: "typ says this is a session refresh token", gate: "ID-Token shape",
			mutate: func(claims map[string]interface{}) { claims["typ"] = "Refresh" },
			want:   hintRejected,
		},
		{
			// The gate is a denylist, because no ID Token this server issues carries typ at all.
			// Turning it into a requirement that typ be "ID" would refuse every real hint, so this
			// row fails the moment somebody inverts it.
			name: "typ says this is an ID token", gate: "ID-Token shape",
			mutate: func(claims map[string]interface{}) { claims["typ"] = "ID" },
			want:   hintConfirmed, wantSid: theSessionId,
		},
		{
			name: "sub is missing", gate: "ID-Token shape",
			mutate: func(claims map[string]interface{}) { delete(claims, "sub") },
			want:   hintRejected,
		},
		{
			name: "sub is empty", gate: "ID-Token shape",
			mutate: func(claims map[string]interface{}) { claims["sub"] = "" },
			want:   hintRejected,
		},
		{
			name: "iat is missing", gate: "ID-Token shape",
			mutate: func(claims map[string]interface{}) { delete(claims, "iat") },
			want:   hintRejected,
		},
		{
			name: "iat is not a number", gate: "ID-Token shape",
			mutate: func(claims map[string]interface{}) { claims["iat"] = "yesterday" },
			want:   hintRejected,
		},
		{
			name: "iss is missing", gate: "iss",
			mutate: func(claims map[string]interface{}) { delete(claims, "iss") },
			want:   hintRejected,
		},
		{
			name: "iss names another server", gate: "iss",
			mutate: func(claims map[string]interface{}) { claims["iss"] = "https://elsewhere.example" },
			want:   hintRejected,
		},
		{
			name: "aud is missing", gate: "aud",
			mutate: func(claims map[string]interface{}) { delete(claims, "aud") },
			want:   hintRejected,
		},
		{
			// An ID Token this server issues has exactly one audience, so an array is not a hint
			// shape and GetStringClaim reads it as absent. Pinned because the array form is what a
			// multi-audience access token carries.
			name: "aud arrived as an array", gate: "aud",
			mutate: func(claims map[string]interface{}) {
				claims["aud"] = []interface{}{theClientId}
			},
			want: hintRejected,
		},
		{
			// client_id moves with aud so that the row still reaches the gate it is about. Leaving
			// client_id at the confirmed value would be refused one gate earlier, as a mismatch, and
			// the row would pass without the lookup ever happening.
			name: "aud names no client", gate: "aud",
			mutate:   func(claims map[string]interface{}) { claims["aud"] = "ghost_client" },
			clientId: strPtr("ghost_client"),
			stubDB: func(database *mocks_data.Database) {
				database.On("GetClientByClientIdentifier", mock.Anything, "ghost_client").Return(nil, nil)
			},
			want: hintRejected,
		},
		{
			// Rejected rather than a 500, and the asymmetry with the expiry lookup below is
			// deliberate: this one runs before any teardown, so surfacing it would put the End-User
			// on a terminal page while still signed in.
			name: "the client lookup fails", gate: "aud",
			stubDB: func(database *mocks_data.Database) {
				database.On("GetClientByClientIdentifier", mock.Anything, theClientId).
					Return(nil, errors.New("the database is on fire"))
			},
			want: hintRejected,
		},
		{
			name: "client_id does not match aud", gate: "client_id",
			clientId: strPtr("another_client"),
			want:     hintRejected,
		},
		{
			// The gate only fires when both are present. RP-Initiated Logout makes client_id
			// OPTIONAL, so its absence beside a valid hint is an ordinary conforming request. Absent
			// here means the parameter did not arrive, which is why the row says so rather than
			// passing an empty value: the row below is the empty one and they must not agree.
			name: "client_id is absent beside a valid aud", gate: "client_id",
			clientIdAbsent: true,
			want:           hintConfirmed, wantSid: theSessionId,
		},
		{
			// Supplied empty is supplied. RP-Initiated Logout 1.0 section 2 makes the OP verify the
			// Client Identifier "when both client_id and id_token_hint are present", and "" is not a
			// Client Identifier valid at this server, so the hint is refused exactly as it is for a
			// client_id naming somebody else. Reading this as absent would skip a MUST on a parameter
			// the request carried, and it is the row that stops the two reads of client_id, this gate
			// and the JWE key selection above, from being collapsed back into one.
			name: "client_id supplied with an empty value", gate: "client_id",
			clientId: strPtr(""),
			want:     hintRejected,
		},
		{
			name: "nbf is in the future", gate: "nbf",
			mutate: func(claims map[string]interface{}) {
				claims["nbf"] = float64(now.Add(10 * time.Minute).Unix())
			},
			want: hintRejected,
		},
		{
			// Raw map presence rather than a zero-value test, so a present-but-malformed nbf is
			// refused instead of read as absent and skipped.
			name: "nbf is present and is not a number", gate: "nbf",
			mutate: func(claims map[string]interface{}) { claims["nbf"] = "soon" },
			want:   hintRejected,
		},
		{
			name: "nbf is absent", gate: "nbf",
			mutate: func(claims map[string]interface{}) { delete(claims, "nbf") },
			want:   hintConfirmed, wantSid: theSessionId,
		},
		{
			// Decision 14 tolerates a past exp, never a missing one: a hint with no expiry is an
			// indefinitely replayable forced-logout token.
			name: "exp is missing", gate: "exp",
			mutate: func(claims map[string]interface{}) { delete(claims, "exp") },
			want:   hintRejected,
		},
		{
			// The present-but-malformed half, which the missing row cannot reach. Claims validation is
			// off at the parse, so this gate is the only thing standing between a garbage exp and the
			// expiry-tolerance comparison below, and a build that read an unreadable exp as "not
			// expired yet" would confirm a hint whose lifetime nothing had checked.
			name: "exp is present and is not a number", gate: "exp",
			mutate: func(claims map[string]interface{}) { claims["exp"] = "later" },
			want:   hintRejected,
		},
		{
			name: "sid is missing", gate: "sid",
			mutate: func(claims map[string]interface{}) { delete(claims, "sid") },
			want:   hintRejected,
		},
		{
			name: "sid names a different session than the browser's", gate: "sid",
			mutate: func(claims map[string]interface{}) { claims["sid"] = "another-session" },
			want:   hintRejected,
		},
		{
			// With no cookie the hint's own sid names the session, which is what makes RP-initiated
			// logout work at all from an RP the browser is not currently at. The assertion that
			// proves seeding happened is wantSid: without it the identifier would come back empty.
			name: "no browser session, so sid seeds the identifier", gate: "sid",
			noSession: true,
			want:      hintConfirmed, wantSid: theSessionId,
		},
		{
			// The reachable half of decision 14: the admin console mints a 60-second hint, so a user
			// who pauses on the way through arrives here.
			name: "expired, and sid still names a live session", gate: "expiry tolerance",
			mutate: func(claims map[string]interface{}) {
				claims["exp"] = float64(now.Add(-1 * time.Minute).Unix())
			},
			stubDB: resolvesClientAndSession(&models.UserSession{Id: 7, UserId: 3}, nil),
			want:   hintConfirmed, wantSid: theSessionId,
		},
		{
			name: "expired, and sid names no live session", gate: "expiry tolerance",
			mutate: func(claims map[string]interface{}) {
				claims["exp"] = float64(now.Add(-1 * time.Minute).Unix())
			},
			stubDB: resolvesClientAndSession(nil, nil),
			want:   hintRejected,
		},
		{
			// The one failure that is not a rejection. A database error and a row that is not there
			// have different answers, so reading this as "no such session" would decide the tolerance
			// on the database's health (decision 8's rule for this handler).
			name: "expired, and the session lookup fails", gate: "expiry tolerance",
			mutate: func(claims map[string]interface{}) {
				claims["exp"] = float64(now.Add(-1 * time.Minute).Unix())
			},
			stubDB:  resolvesClientAndSession(nil, errors.New("the database is on fire")),
			want:    hintRejected,
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			database := mocks_data.NewDatabase(t)
			tokenParser := mocks_oauth.NewTokenParser(t)

			req, err := http.NewRequest("GET", "/auth/logout", nil)
			assert.NoError(t, err)
			ctx := context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{Issuer: theIssuer})
			if !tc.noSession {
				ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, theSessionId)
			}
			req = req.WithContext(ctx)

			hint := theHint
			if tc.hintValue != nil {
				hint = *tc.hintValue
			}
			httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").
				Return(hint, !tc.hintAbsent)

			clientId := theClientId
			if tc.clientId != nil {
				clientId = *tc.clientId
			}
			if tc.clientIdAbsent {
				clientId = ""
			}
			httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "client_id").
				Return(clientId, !tc.clientIdAbsent).Maybe()

			claims := confirmedClaims()
			if tc.mutate != nil {
				tc.mutate(claims)
			}

			// The literal false is decision 14's whole mechanism, so it is asserted rather than
			// matched loosely: a classifier that passed true would find no expectation here and the
			// row would fail outright.
			parsed := hint
			if tc.innerToken != nil {
				parsed = *tc.innerToken
			}
			parserCall := tokenParser.On("DecodeAndValidateTokenString", parsed, (*rsa.PublicKey)(nil), false)
			if tc.parserErr != nil {
				parserCall.Return(nil, tc.parserErr).Maybe()
			} else {
				parserCall.Return(&oauth.JwtToken{TokenBase64: parsed, Claims: claims}, nil).Maybe()
			}

			stubDB := tc.stubDB
			if stubDB == nil {
				stubDB = resolvesClient
			}
			stubDB(database)

			got, err := classifyIdTokenHint(req, httpHelper, database, tokenParser)

			if tc.wantErr {
				assert.Error(t, err, "a database failure in the expiry lookup must propagate")
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.want, got.state, "gate: %s", tc.gate)

			if tc.want == hintConfirmed {
				assert.NotNil(t, got.client, "a confirmed hint must yield the client its aud named")
				assert.Equal(t, theClientId, got.client.ClientIdentifier)
				// The persisted row, not a model rebuilt from the identifier. Asserting the identifier
				// alone leaves Id 0 indistinguishable from the real client, and Id is what the
				// redirect path queries by.
				assert.Equal(t, theClientDbId, got.client.Id,
					"a confirmed hint must yield the persisted client, since its Id is what loads the registered redirect URIs")
				assert.Equal(t, tc.wantSid, got.sessionIdentifier)
			} else {
				// RP-Initiated Logout 1.0 section 4: information that failed to validate MUST NOT be
				// used. From a caller's side that looks like having nothing to use.
				assert.Nil(t, got.client, "a hint that was not confirmed must yield no client")
				assert.Empty(t, got.sessionIdentifier, "a hint that was not confirmed must yield no session")
			}

			httpHelper.AssertExpectations(t)
			database.AssertExpectations(t)
			tokenParser.AssertExpectations(t)
		})
	}
}
