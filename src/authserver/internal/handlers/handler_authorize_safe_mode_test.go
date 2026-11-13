package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
)

// goiabada_safe_mode=true on an authorization request draws that sign-in in safe mode (#816
// decision 3). Only true turns it on: any other value is read as absent and never refuses the
// sign-in, as a ui_locales naming no language is not.

// authorizeSafeModeTarget is an authorization request of test-client, with goiabada_safe_mode set
// to each of values, or left out when values is nil.
func authorizeSafeModeTarget(values []string) string {
	params := url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"https://example.com"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	if values != nil {
		params["goiabada_safe_mode"] = values
	}
	return "/authorize?" + params.Encode()
}

// The sign-in the request starts is stored with safe mode on for true alone, and goes on to sign in
// whatever the value.
func TestHandleAuthorizeGet_KeepsSafeModeOnTheSignInForTrueAlone(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   bool
	}{
		{"true", []string{"true"}, true},
		{"absent", nil, false},
		{"empty", []string{""}, false},
		{"false", []string{"false"}, false},
		{"TRUE", []string{"TRUE"}, false},
		{"True", []string{"True"}, false},
		{"1", []string{"1"}, false},
		{"yes", []string{"yes"}, false},
		{"true with a space", []string{"true "}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			stubRegisteredRedirectURI(database, "https://example.com")
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			handler := buildAuthorizeGet(authorizeGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      ceremonyStore,
				userSessionManager: userSessionManager,
				database:           database,
				authorizeValidator: authorizeValidator,
				auditLogger:        handlersmocks.NewAuditLogger(t),
				permissionChecker:  handlersmocks.NewPermissionChecker(t),
				tokenParser:        handlersmocks.NewTokenParser(t),
			})

			req := httptest.NewRequest(http.MethodGet, authorizeSafeModeTarget(tc.values), nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
			rr := httptest.NewRecorder()

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).Return(nil)
			client := &record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1}
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(client, nil)
			authorizeValidator.On("ValidateRequest", mock.Anything).Return(nil)
			authorizeValidator.On("ValidateScopes", mock.Anything, "openid").Return(nil)
			authorizeValidator.On("ValidatePrompt", "").Return("", nil)
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
			database.On("UserSessionLoadUser", mock.Anything, mock.Anything, (*record.UserSession)(nil)).Return(nil)
			userSessionManager.On("HasValidUserSession", (*record.UserSession)(nil), mock.AnythingOfType("int"),
				mock.AnythingOfType("int"), mock.Anything).Return(false)

			var saved *ceremony.AuthContext
			ceremonyStore.On("AddAuthContext", rr, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				saved = args.Get(2).(*ceremony.AuthContext)
			}).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code, "the sign-in goes on whatever the value")
			assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1")
			require.NotNil(t, saved)
			assert.Equal(t, tc.want, saved.SafeMode)
		})
	}
}

// A refusal page the authorization endpoint draws is drawn in safe mode when the request asks for
// it, and as usual when it does not: safe mode is honored from the first page, before any sign-in is
// stored.
func TestHandleAuthorizeGet_DrawsTheRefusalPageInSafeMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []string
		want   bool
	}{
		{"asked for", []string{"true"}, true},
		{"not asked for", nil, false},
		{"another value", []string{"on"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			handler := buildAuthorizeGet(authorizeGetDeps{
				pageRenderer:       pageRenderer,
				ceremonyStore:      handlersmocks.NewCeremonyStore(t),
				userSessionManager: handlersmocks.NewUserSessionManager(t),
				database:           datamocks.NewDatabase(t),
				authorizeValidator: authorizeValidator,
				auditLogger:        handlersmocks.NewAuditLogger(t),
				permissionChecker:  handlersmocks.NewPermissionChecker(t),
				tokenParser:        handlersmocks.NewTokenParser(t),
			})

			req := httptest.NewRequest(http.MethodGet, authorizeSafeModeTarget(tc.values), nil)
			ctx := reqctx.WithSettings(req.Context(), &record.Settings{})
			req = req.WithContext(reqctx.WithPageClient(ctx, &reqctx.PageClient{}))
			rr := httptest.NewRecorder()

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).
				Return(i18n.NewLocalizedError(i18n.ErrCodeAuthorizeClientNotFound, nil))

			var drawnSafe, drawn bool
			pageRenderer.On("RenderTemplate", rr, mock.Anything, "/layouts/no_menu_layout.html", "/auth_error.html", mock.Anything).
				Run(func(args mock.Arguments) {
					drawn = true
					drawnSafe = reqctx.PageSafeMode(args.Get(1).(*http.Request).Context())
				}).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			require.True(t, drawn, "the refusal page is drawn")
			assert.Equal(t, tc.want, drawnSafe)
		})
	}
}
