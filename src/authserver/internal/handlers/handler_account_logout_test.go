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

		httpHelper.On("LookupFromUrlQueryOrFormPost", req, "id_token_hint").Return("", false)
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "post_logout_redirect_uri").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "client_id").Return("")
		httpHelper.On("GetFromUrlQueryOrFormPost", req, "ui_locales").Return("")
		httpHelper.On("LookupFromUrlQueryOrFormPost", req, "state").Return("", false)
		// This subtest owns the status code and the template choice only. The bind's contents are
		// pinned key by key in the sibling below, which is where the interesting claim lives.
		httpHelper.On("RenderTemplate", rr, req, "/layouts/auth_layout.html", "/logout_consent.html",
			mock.Anything).Return(nil)

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

		httpHelper.On("LookupFromUrlQueryOrFormPost", req, "id_token_hint").Return("", false)
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
		// Exactly the six above, asserted by count as well as by name. Naming six keys says nothing
		// about a seventh, so without this the sibling subtest below can drop to mock.Anything only
		// on the claim that this one pins the whole render, and that claim would be false: a
		// reintroduced csrfField, or any other stray bind, would pass every assertion above (#155).
		assert.Len(t, bound, 6, "the consent render binds exactly these six keys and nothing else")
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
				httpHelper.On("LookupFromUrlQueryOrFormPost", req, "id_token_hint").Return("", false)
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
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("", false)
		httpHelper.On("RenderTemplate", rr, mock.MatchedBy(func(rendered *http.Request) bool {
			return i18n.T(rendered.Context(), "logout_consent.title") == "Sair"
		}), "/layouts/auth_layout.html", "/logout_consent.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	// Item 1, the defect this issue is named for, at the seam where it is visible.
	// post_logout_redirect_uri is OPTIONAL, and the check that treated it as required returned before
	// both the database teardown and the cookie wipe, so the most ordinary conforming request in the
	// specification rendered an error page and left the End-User signed in.
	t.Run("A confirmed hint with no post_logout_redirect_uri still logs the user out", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodGet, url.Values{"id_token_hint": {hintedToken}}, hintedSessionId)
		rr := httptest.NewRecorder()

		client := stubConfirmedHint(httpHelper, database, tokenParser, hintedClaims())
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")
		stubPerClientTeardown(database, auditLogger, authHelper, client, hintedSessionId)

		mockSession := expectCookieWipedBeforeSave(t, httpSession)
		httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logged_out.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["redirectDeclined"] == false
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, rr.Header().Get("Location"))
		assert.Empty(t, mockSession.Values, "the OP session cookie must be cleared")
		httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		httpSession.AssertExpectations(t)
	})

	// The ordinary success, and the two parameters it turns on: state reaches the RP byte-identical
	// through url.Values rather than concatenation, and sid does not reach it at all. RP-Initiated
	// Logout 1.0 defines exactly one parameter on the way back, and sid belongs to Front-Channel
	// Logout, a different endpoint travelling the other way (decisions 5 and 16).
	t.Run("A confirmed hint tears down per client and redirects", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodGet, url.Values{"id_token_hint": {hintedToken}}, hintedSessionId)
		rr := httptest.NewRecorder()

		client := stubConfirmedHint(httpHelper, database, tokenParser, hintedClaims())
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return(hintedRegisteredURI)
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("aB+cd/efgh==#&x=1", true)
		stubRegisteredURI(database, client, hintedRegisteredURI)
		stubPerClientTeardown(database, auditLogger, authHelper, client, hintedSessionId)

		mockSession := expectCookieWipedBeforeSave(t, httpSession)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location, err := url.Parse(rr.Header().Get("Location"))
		assert.NoError(t, err)
		assert.Equal(t, hintedRegisteredURI, location.Scheme+"://"+location.Host+location.Path)
		assert.Equal(t, []string{"aB+cd/efgh==#&x=1"}, location.Query()["state"],
			"exactly one state, byte-identical to what the RP sent")
		assert.Empty(t, location.Query().Get("sid"),
			"sid is not a parameter RP-initiated logout defines, decision 5")
		assert.Empty(t, mockSession.Values, "the OP session cookie must be cleared")
		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		httpSession.AssertExpectations(t)
	})

	// The confirmed half of "whether a redirect can be honoured is a question about the response". The
	// hintless half of this property has its own table above; this row is what says the hinted path
	// answers it the same way rather than returning before the teardown as all seven of its error
	// paths used to.
	t.Run("A confirmed hint whose target is unregistered is declined, and the logout still happens", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodGet, url.Values{"id_token_hint": {hintedToken}}, hintedSessionId)
		rr := httptest.NewRecorder()

		client := stubConfirmedHint(httpHelper, database, tokenParser, hintedClaims())
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").
			Return("https://example.com/somewhere-else")
		stubRegisteredURI(database, client, hintedRegisteredURI)
		stubPerClientTeardown(database, auditLogger, authHelper, client, hintedSessionId)

		mockSession := expectCookieWipedBeforeSave(t, httpSession)
		httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logged_out.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				return data["redirectDeclined"] == true
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Empty(t, rr.Header().Get("Location"), "a declined target must never become a redirect")
		assert.Empty(t, mockSession.Values, "the OP session cookie must be cleared")
		httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	// Divergence C, which is by design rather than a defect: an RP may end a session with a hint alone
	// and no cookie in play, which is what makes RP-initiated logout work from a relying party that
	// cannot reach the End-User's browser session. The hint's own sid then names the session, and the
	// teardown is still scoped to the client the hint is signed over.
	t.Run("A confirmed hint with no browser session tears down the session its sid names", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodGet, url.Values{"id_token_hint": {hintedToken}}, "")
		rr := httptest.NewRecorder()

		client := stubConfirmedHint(httpHelper, database, tokenParser, hintedClaims())
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")
		stubPerClientTeardown(database, auditLogger, authHelper, client, hintedSessionId)

		expectCookieWipedBeforeSave(t, httpSession)
		httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logged_out.html",
			mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		database.AssertExpectations(t)
	})

	// Decision 14, at the seam where the consequence is visible rather than the classification. The
	// admin console mints a 60-second hint, so an operator who pauses on the way through arrives here
	// with an expired one; the spec says to accept it while the session it names is still alive, and
	// what that has to buy is the same per-client teardown and the same redirect a fresh hint gets.
	t.Run("An expired hint whose session is still live is honoured in full", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodGet, url.Values{"id_token_hint": {hintedToken}}, hintedSessionId)
		rr := httptest.NewRecorder()

		claims := hintedClaims()
		claims["exp"] = float64(time.Now().UTC().Add(-1 * time.Minute).Unix())

		client := stubConfirmedHint(httpHelper, database, tokenParser, claims)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return(hintedRegisteredURI)
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("abc", true)
		stubRegisteredURI(database, client, hintedRegisteredURI)
		// The tolerance lookup and the teardown read the same row through the same call, which is one
		// of the reasons a database fault there propagates rather than being read as "no such session".
		stubPerClientTeardown(database, auditLogger, authHelper, client, hintedSessionId)

		expectCookieWipedBeforeSave(t, httpSession)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "abc", mustParseURL(t, rr.Header().Get("Location")).Query().Get("state"))
		database.AssertExpectations(t)
	})

	// The one classification failure that is not a rejection. A database fault while deciding whether
	// an expired hint's session is still alive has a different answer from a row that is not there:
	// reading it as "no such session" would decide whether the hint is honoured on the database's
	// health, and silently widen the teardown at the same time.
	t.Run("A database fault while judging an expired hint is a 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodGet, url.Values{"id_token_hint": {hintedToken}}, hintedSessionId)
		rr := httptest.NewRecorder()

		claims := hintedClaims()
		claims["exp"] = float64(time.Now().UTC().Add(-1 * time.Minute).Unix())

		stubConfirmedHint(httpHelper, database, tokenParser, claims)
		database.On("GetUserSessionBySessionIdentifier", mock.Anything, hintedSessionId).
			Return(nil, errors.New("the database is on fire"))

		httpHelper.On("InternalServerError", mock.Anything, mock.Anything,
			mock.MatchedBy(func(err error) bool { return err.Error() == "the database is on fire" })).
			Run(func(args mock.Arguments) {
				args.Get(0).(http.ResponseWriter).WriteHeader(http.StatusInternalServerError)
			}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		database.AssertNotCalled(t, "DeleteUserSessionClient", mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
		httpHelper.AssertExpectations(t)
	})

	// Decision 15, and the case §5 warns can pass for the wrong reason. The client_id here names a
	// DIFFERENT client from the aud the hint is signed over, which rejects the hint, and a rejected
	// hint earns no redirect however good that client_id looks. The target supplied is one this
	// server would accept from a hintless request, so the case fails for the reason it names rather
	// than because the URI was unregistered.
	//
	// What makes the redirect impossible is that client_id does not survive the consent hop: the
	// confirming POST is hintless by design, so a client_id carried forward would authorize the
	// target and the detected error would become a redirect after all. The parameter is not even
	// read, which is what the AssertNotCalled below pins.
	t.Run("A rejected hint reaches the consent page without its client_id", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutGet(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodGet, url.Values{"id_token_hint": {hintedToken}}, hintedSessionId)
		rr := httptest.NewRecorder()

		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(hintedToken, true)
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("another_client", true)
		tokenParser.On("DecodeAndValidateTokenString", hintedToken, (*rsa.PublicKey)(nil), false).
			Return(&oauth.JwtToken{TokenBase64: hintedToken, Claims: hintedClaims()}, nil)

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return(hintedRegisteredURI)
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("abc", true)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "ui_locales").Return("")

		var bound map[string]interface{}
		httpHelper.On("RenderTemplate", rr, mock.Anything, "/layouts/auth_layout.html", "/logout_consent.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				bound = data
				return true
			})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "", bound["clientId"],
			"a rejected hint's client_id must not survive the consent hop, or it authorizes the redirect decision 15 denies")
		assert.Equal(t, hintedRegisteredURI, bound["postLogoutRedirectUri"],
			"the target still travels, so the signed-out page can say a return was attempted and refused")
		httpHelper.AssertNotCalled(t, "GetFromUrlQueryOrFormPost", mock.Anything, "client_id")
		database.AssertNotCalled(t, "DeleteUserSessionClient", mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
		httpHelper.AssertExpectations(t)
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

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client_id names no client")
	})

	t.Run("Not a valid JWE", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		clientSecret := "test_secret"
		clientSecretEncrypted, _ := encryption.EncryptData(clientSecret)
		client := &models.Client{ClientSecretEncrypted: clientSecretEncrypted}
		database.On("GetClientByClientIdentifier", mock.Anything, "test_client").Return(client, nil)

		_, err := decryptIDTokenHint("not.a.valid.jwe.token", "test_client", database)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to decrypt the id_token_hint")
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

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to decrypt the id_token_hint")
	})
}

// TestHandleExistingSessionOnLogout covers the per-client teardown a confirmed id_token_hint earns.
//
// The sid guard this function used to open with is gone, and so is the subtest that pinned it:
// whether the hint names the browser's session is part of whether the hint can be confirmed at all,
// and classifyIdTokenHint owns that with an exhaustive table. Deciding it here meant returning an
// error the caller turned into a 500, which is what a user whose session had merely been reaped or
// replaced saw (#109 decision 11).
func TestHandleExistingSessionOnLogout(t *testing.T) {

	// Item 4. A database error and a session that is simply not there used to be one branch returning
	// a variable that was sometimes nil to mean both, so a failing lookup completed the logout as
	// though there had been nothing to tear down. They have different answers and both are pinned.
	t.Run("The session lookup fails", func(t *testing.T) {
		r := &http.Request{}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").
			Return(nil, errors.New("lookup exploded"))

		err := handleExistingSessionOnLogout(r, "test-session", &models.Client{}, database, auditLogger, authHelper)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "lookup exploded")
		database.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log")
	})

	t.Run("Session not found", func(t *testing.T) {
		r := &http.Request{}
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)

		database.On("GetUserSessionBySessionIdentifier", mock.Anything, "test-session").Return(nil, nil)

		err := handleExistingSessionOnLogout(r, "test-session", &models.Client{}, database, auditLogger, authHelper)

		assert.NoError(t, err, "a session that is not there is nothing to tear down, not a failure")
		database.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log")
	})

	// Decision 3's first half: another client on the session means the row survives, so that client's
	// session-bound tokens keep working. #129 wrote two integration tests so this cannot change by
	// accident, and this is the unit-tier statement of the same rule.
	t.Run("Delete user session client", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
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

		err := handleExistingSessionOnLogout(r, sessionIdentifier, client, database, auditLogger, authHelper)

		assert.NoError(t, err)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Delete entire user session", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
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

		err := handleExistingSessionOnLogout(r, sessionIdentifier, client, database, auditLogger, authHelper)

		assert.NoError(t, err)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Client not found in user session", func(t *testing.T) {
		r := &http.Request{}
		sessionIdentifier := "test-session"
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

		err := handleExistingSessionOnLogout(r, sessionIdentifier, client, database, auditLogger, authHelper)

		assert.NoError(t, err) // The function should not return an error if the client is not found in the session
		database.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log")
		authHelper.AssertNotCalled(t, "GetLoggedInSubject")
	})
}

// The fixtures the hinted pipeline's cases share. A confirmed hint is one classifyIdTokenHint
// accepts, and seam 2 owns the exhaustive table of what makes it accept or refuse one, so the cases
// here need exactly one confirmed hint and one rejected one and say which they are using.
const (
	hintedIssuer        = "https://hinted-issuer.example"
	hintedClientId      = "hinted_client"
	hintedSessionId     = "hinted-session"
	hintedToken         = "a.signed.hint"
	hintedRegisteredURI = "https://example.com/out"
)

// hintedClaims is the claim set of a hint that validates. Every numeric claim is a float64 because
// claims arrive through encoding/json inside jwt.MapClaims, and GetIntClaim refuses anything else, so
// writing them as int would make the fixture unlike any real token.
func hintedClaims() map[string]interface{} {
	now := time.Now().UTC()
	return map[string]interface{}{
		"iss": hintedIssuer,
		"sub": "the-user",
		"iat": float64(now.Add(-2 * time.Minute).Unix()),
		"exp": float64(now.Add(2 * time.Minute).Unix()),
		"aud": hintedClientId,
		"sid": hintedSessionId,
	}
}

// hintedRequest builds a request for the hinted pipeline. The parameters are read through the mocked
// HttpHelper rather than off the request, so the query and body here matter for one thing only:
// ui_locales, which refineLogoutLocale reads with r.FormValue.
//
// sessionIdentifier empty means the session-identifier middleware attached nothing, which it does
// whenever the cookie names no live row.
func hintedRequest(t *testing.T, method string, form url.Values, sessionIdentifier string) *http.Request {
	t.Helper()

	var req *http.Request
	var err error
	if method == http.MethodPost {
		req, err = http.NewRequest(method, "/auth/logout", strings.NewReader(form.Encode()))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req, err = http.NewRequest(method, "/auth/logout?"+form.Encode(), nil)
		assert.NoError(t, err)
	}

	ctx := context.WithValue(req.Context(), constants.ContextKeySettings, &models.Settings{Issuer: hintedIssuer})
	if len(sessionIdentifier) > 0 {
		ctx = context.WithValue(ctx, constants.ContextKeySessionIdentifier, sessionIdentifier)
	}
	return req.WithContext(ctx)
}

// stubConfirmedHint wires everything classifyIdTokenHint reads for a hint that validates, and returns
// the client its aud names. That client pointer is the one the teardown then compares against the
// session's clients, so the cases must not build a second one.
//
// The literal false on the parse is decision 14's whole mechanism: claims validation is off, and the
// classifier checks exp by hand so it can tolerate a past one while the session lives.
func stubConfirmedHint(
	httpHelper *mocks_handlerhelpers.HttpHelper,
	database *mocks_data.Database,
	tokenParser *mocks_oauth.TokenParser,
	claims map[string]interface{},
) *models.Client {
	client := &models.Client{Id: 11, ClientIdentifier: hintedClientId}

	httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(hintedToken, true)
	httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("", false)
	tokenParser.On("DecodeAndValidateTokenString", hintedToken, (*rsa.PublicKey)(nil), false).
		Return(&oauth.JwtToken{TokenBase64: hintedToken, Claims: claims}, nil)
	database.On("GetClientByClientIdentifier", mock.Anything, hintedClientId).Return(client, nil)

	return client
}

// stubRegisteredURI gives the client one registered redirect URI, which is the set a post-logout
// target is matched against exactly.
func stubRegisteredURI(database *mocks_data.Database, client *models.Client, uri string) {
	database.On("ClientLoadRedirectURIs", mock.Anything, client).Run(func(args mock.Arguments) {
		args.Get(1).(*models.Client).RedirectURIs = []models.RedirectURI{{URI: uri}}
	}).Return(nil)
}

// stubPerClientTeardown wires the reads and writes the per-client teardown performs on a session whose
// only client is the one logging out, which is the shape that also deletes the session row.
//
// Per-client is what the assertions in the cases are really about: the hint's SIGNED aud scopes the
// teardown, and an unauthenticated client_id never does.
func stubPerClientTeardown(
	database *mocks_data.Database,
	auditLogger *mocks_audit.AuditLogger,
	authHelper *mocks_handlerhelpers.AuthHelper,
	client *models.Client,
	sessionIdentifier string,
) {
	userSession := &models.UserSession{
		Id:      42,
		UserId:  123,
		Clients: []models.UserSessionClient{{Id: 7, ClientId: client.Id, Client: *client}},
	}

	database.On("GetUserSessionBySessionIdentifier", mock.Anything, sessionIdentifier).Return(userSession, nil)
	database.On("UserSessionLoadClients", mock.Anything, userSession).Return(nil)
	database.On("UserSessionClientsLoadClients", mock.Anything, userSession.Clients).Return(nil)
	database.On("DeleteUserSessionClient", mock.Anything, int64(7)).Return(nil)
	database.On("DeleteUserSession", mock.Anything, int64(42)).Return(nil)

	authHelper.On("GetLoggedInSubject", mock.Anything).Return("user-123")
	auditLogger.On("Log", constants.AuditDeletedUserSessionClient, mock.Anything).Return()
	auditLogger.On("Log", constants.AuditLogout, mock.Anything).Return()
}

// mustParseURL fails the test rather than returning a zero URL, so an assertion on a malformed
// Location says so instead of silently comparing empty strings.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	assert.NoError(t, err)
	return parsed
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
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := withSessionIdentifier(logoutPostRequest(t, url.Values{}), "test-session")
		rr := httptest.NewRecorder()

		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
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
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := withSessionIdentifier(logoutPostRequest(t, url.Values{}), "test-session")
		rr := httptest.NewRecorder()

		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
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
				tokenParser := mocks_oauth.NewTokenParser(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

				req := withSessionIdentifier(logoutPostRequest(t, url.Values{}), "test-session")
				rr := httptest.NewRecorder()

				redirectURI := tc.redirectURI
				if redirectURI == "" {
					redirectURI = "https://example.com/out"
				}

				httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
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
				tokenParser := mocks_oauth.NewTokenParser(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

				req := withSessionIdentifier(logoutPostRequest(t, url.Values{}), "test-session")
				rr := httptest.NewRecorder()

				httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
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
				tokenParser := mocks_oauth.NewTokenParser(t)
				auditLogger := mocks_audit.NewAuditLogger(t)

				handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

				req := logoutPostRequest(t, url.Values{})
				if tc.sessionIdentifier != "" {
					req = withSessionIdentifier(req, tc.sessionIdentifier)
				}
				rr := httptest.NewRecorder()

				httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
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
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := logoutPostRequest(t, url.Values{"ui_locales": {"pt-BR"}})
		rr := httptest.NewRecorder()

		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
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
	// carrying a hint never enters the hintless branch, so the refinement has to happen above the
	// pipeline rather than inside it. Move it down and the case above still passes while every hinted
	// POST that renders anything renders it in the fallback language, which an RP posting ui_locales in
	// its body has no way to correct.
	t.Run("ui_locales in the body only reaches a hinted POST's render", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodPost, url.Values{
			"id_token_hint": {hintedToken},
			"ui_locales":    {"pt-BR"},
		}, hintedSessionId)
		rr := httptest.NewRecorder()

		client := stubConfirmedHint(httpHelper, database, tokenParser, hintedClaims())
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")
		stubPerClientTeardown(database, auditLogger, authHelper, client, hintedSessionId)

		expectCookieWipedBeforeSave(t, httpSession)
		httpHelper.On("RenderTemplate", rr, mock.MatchedBy(func(rendered *http.Request) bool {
			return i18n.T(rendered.Context(), "logged_out.title") == "Sessão encerrada"
		}), "/layouts/auth_layout.html", "/logged_out.html", mock.Anything).Return(nil)

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	// Decision 18, and the reason behind it has since changed. The CSRF exemption the POST binding
	// needs keys on the hint being PRESENT, because middleware cannot judge whether one is genuine.
	// Under gorilla/csrf the middleware returned on that skip flag before saving its cookie and
	// attaching its token, so a consent page rendered on this request carried no token while its own
	// hintless confirming POST was refused: an End-User stranded on a page they could not submit
	// while still signed in. There is no token now (#155), and a page rendered here would be a
	// document at our own origin whose confirming POST is same-origin, so that trap is gone. The 303
	// remains what decision 18 landed and what this case pins, because the shape a relying party
	// observes is part of the contract.
	//
	// The two parameters dropped are the point of the case. id_token_hint, because carrying it back
	// would put an ID token in the address bar of a top-level navigation, its history and its
	// referrers, which is the exposure the POST binding exists to avoid; client_id, because the
	// follow-up GET is the hint-absent shape, where client_id authorizes the redirect a rejected hint
	// is specifically denied (decision 15). Not to prevent a loop: the follow-up is a GET, and a
	// rejected hint on a GET renders the consent page rather than redirecting again.
	t.Run("A POST whose hint is rejected is sent to the GET binding", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := hintedRequest(t, http.MethodPost, url.Values{
			"id_token_hint": {hintedToken},
			"ui_locales":    {"pt-BR"},
		}, hintedSessionId)
		rr := httptest.NewRecorder()

		// Rejected at the client_id gate, which refuses before any lookup: the parameter names a
		// different client from the aud the hint is signed over.
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(hintedToken, true)
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("another_client", true)
		tokenParser.On("DecodeAndValidateTokenString", hintedToken, (*rsa.PublicKey)(nil), false).
			Return(&oauth.JwtToken{TokenBase64: hintedToken, Claims: hintedClaims()}, nil)

		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return(hintedRegisteredURI)
		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return("aB+cd/efgh==#&x=1", true)
		httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "ui_locales").Return("pt-BR")

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusSeeOther, rr.Code,
			"303, so the End-User ends on a GET and a reload does not resubmit the failed POST")
		location := mustParseURL(t, rr.Header().Get("Location"))
		assert.Equal(t, "/auth/logout", location.Path)
		assert.Equal(t, hintedRegisteredURI, location.Query().Get("post_logout_redirect_uri"))
		assert.Equal(t, "aB+cd/efgh==#&x=1", location.Query().Get("state"),
			"state survives the hop byte-identical, escaped rather than concatenated")
		assert.Equal(t, "pt-BR", location.Query().Get("ui_locales"),
			"the locale survives, or the consent page comes back in a different language from the one asked for")
		_, hintCarried := location.Query()["id_token_hint"]
		assert.False(t, hintCarried,
			"carrying the hint back would put an ID token in the address bar, its history and its referrers")
		_, clientIdCarried := location.Query()["client_id"]
		assert.False(t, clientIdCarried,
			"a rejected hint's client_id must not survive, or it authorizes the redirect decision 15 denies")

		database.AssertNotCalled(t, "DeleteUserSessionClient", mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "DeleteUserSession", mock.Anything, mock.Anything)
		httpSession.AssertNotCalled(t, "Save", mock.Anything, mock.Anything, mock.Anything)
		httpHelper.AssertExpectations(t)
	})

	// The 303 keeps decision 16's contract too, which an unconditional query would quietly break: an
	// RP that sent no state must not have one invented for it on the way to the consent page, and one
	// that sent "state=" must still get "state=" back at the end. Neither row catches the mutation
	// alone, since an unconditional parameter passes the empty row and no parameter at all passes the
	// absent row.
	t.Run("The 303 carries state only when the request did", func(t *testing.T) {
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

				handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

				req := hintedRequest(t, http.MethodPost, url.Values{"id_token_hint": {hintedToken}}, hintedSessionId)
				rr := httptest.NewRecorder()

				httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return(hintedToken, true)
				httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "client_id").Return("another_client", true)
				tokenParser.On("DecodeAndValidateTokenString", hintedToken, (*rsa.PublicKey)(nil), false).
					Return(&oauth.JwtToken{TokenBase64: hintedToken, Claims: hintedClaims()}, nil)

				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "post_logout_redirect_uri").Return("")
				httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "state").Return(tc.value, tc.present)
				httpHelper.On("GetFromUrlQueryOrFormPost", mock.Anything, "ui_locales").Return("")

				handler.ServeHTTP(rr, req)

				assert.Equal(t, http.StatusSeeOther, rr.Code)
				location := mustParseURL(t, rr.Header().Get("Location"))
				values, present := location.Query()["state"]
				assert.Equal(t, tc.present, present, "raw query: %q", location.RawQuery)
				if tc.present {
					assert.Equal(t, []string{tc.value}, values)
				}
			})
		}
	})

	t.Run("Session store error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		httpSession := mocks_sessionstore.NewStore(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		database := mocks_data.NewDatabase(t)
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := logoutPostRequest(t, url.Values{})
		rr := httptest.NewRecorder()

		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
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
		tokenParser := mocks_oauth.NewTokenParser(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAccountLogoutPost(httpHelper, httpSession, authHelper, database, tokenParser, auditLogger)

		req := logoutPostRequest(t, url.Values{})
		rr := httptest.NewRecorder()

		httpHelper.On("LookupFromUrlQueryOrFormPost", mock.Anything, "id_token_hint").Return("", false)
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
