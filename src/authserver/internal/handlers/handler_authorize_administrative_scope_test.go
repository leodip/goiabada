package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
)

// administrativeScopeRefusedDescription is the refusal's description, byte for byte, as #499
// decision 7 words it.
const administrativeScopeRefusedDescription = "The client is not allowed to request the administrative scope 'authserver:manage'."

// administrativeScopeWarnMessage is the Warn record a refusal leaves when nobody can be named.
const administrativeScopeWarnMessage = "refused an administrative scope the client may not request, with no signed-in user to record it against"

// An administrative scope from a client that may not request one is a validation failure like any
// other, so it reaches the client the way #213 and #108 deliver one: at once to a browser holding a
// valid session and to prompt=none, after the sign-in to a browser without one, and on the refusal
// page to a self-registered client. It is recorded as administrative_scope_refused only when it is
// answered at once to a browser holding a valid session; otherwise it leaves a Warn record (#499
// decisions 7 and 9).
func TestHandleAuthorizeGet_AnAdministrativeScopeTheClientMayNotRequest(t *testing.T) {
	const (
		answerClient = "answer the client with invalid_scope now"
		deferToLogin = "park invalid_scope and go to /auth/level1"
		blockedPage  = "render the refusal interstitial"
	)
	const redirectURI = "https://legit.example/cb"
	const sessionUserId = int64(77)

	for _, tc := range []struct {
		name       string
		rawPrompt  string
		hasSession bool
		createdVia bool
		want       string
		audited    bool
	}{
		{name: "a signed-in browser", hasSession: true, want: answerClient, audited: true},
		{name: "prompt=none, a signed-in browser", rawPrompt: "none", hasSession: true, want: answerClient, audited: true},
		{name: "prompt=none, no valid session", rawPrompt: "none", want: answerClient},
		{name: "a signed-out browser", want: deferToLogin},
		{name: "prompt=login, a signed-in browser", rawPrompt: "login", hasSession: true, want: deferToLogin},
		{name: "a self-registered client, a signed-in browser", hasSession: true, createdVia: true, want: blockedPage, audited: true},
		{name: "a self-registered client, a signed-out browser", createdVia: true, want: blockedPage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			permissionChecker := handlersmocks.NewPermissionChecker(t)
			tokenParser := handlersmocks.NewTokenParser(t)
			logs := logtest.CaptureSlog(t)

			handler := HandleAuthorizeGet(pageRenderer, ceremonyStore, userSessionManager, database, nil,
				authorizeValidator, auditLogger, permissionChecker, tokenParser, testBaseURL)

			target := "/authorize?client_id=test-client&redirect_uri=" + url.QueryEscape(redirectURI) +
				"&response_type=code&state=s1&scope=" + url.QueryEscape("openid authserver:manage")
			if tc.rawPrompt != "" {
				target += "&prompt=" + url.QueryEscape(tc.rawPrompt)
			}
			req := httptest.NewRequest("GET", target, nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
			rr := httptest.NewRecorder()

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, "test-client").Return(
				&record.Client{Id: 1, ClientIdentifier: "test-client", CreatedViaDCR: tc.createdVia}, nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).Return(nil)
			authorizeValidator.On("ValidateRequest", mock.Anything).Return(nil)
			// The scope exists and is well formed: what refuses it is who asked for it.
			authorizeValidator.On("ValidateScopes", mock.Anything, "openid authserver:manage").Return(nil)
			// Maybe, because a self-registered client's redirect is withheld before the registration
			// is read.
			database.On("GetRedirectURIsByClientId", mock.Anything, mock.Anything, mock.Anything).
				Return([]record.RedirectURI{{URI: redirectURI}}, nil).Maybe()
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).
				Return(&record.UserSession{Id: 1, UserId: sessionUserId}, nil).Maybe()
			userSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(tc.hasSession).Maybe()

			switch tc.want {
			case deferToLogin:
				ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
					return ac.AuthState == ceremony.AuthStateRequiresLevel1 &&
						ac.DeferredErrorCode == "invalid_scope" &&
						ac.DeferredErrorDescription == administrativeScopeRefusedDescription
				})).Return(nil).Once()
			case answerClient:
				ceremonyStore.On("ClearAuthContext", rr, req).Return(nil).Once()
			case blockedPage:
				ceremonyStore.On("ClearAuthContext", rr, req).Return(nil).Once()
				pageRenderer.On("RenderTemplate", rr, req, "/layouts/no_menu_layout.html",
					"/auth_redirect_blocked.html", mock.Anything).Return(nil).Once()
			}
			if tc.audited {
				auditLogger.On("Log", mock.Anything, audit.EventAdministrativeScopeRefused, map[string]interface{}{
					"client_id":         int64(1),
					"client_identifier": "test-client",
					"scopes":            []string{"authserver:manage"},
					"checkpoint":        "authorize",
					"user_id":           sessionUserId,
				}).Return().Once()
			}

			handler.ServeHTTP(rr, req)

			location := rr.Header().Get("Location")
			switch tc.want {
			case answerClient:
				assert.Equal(t, http.StatusFound, rr.Code)
				assert.True(t, strings.HasPrefix(location, redirectURI+"?"), "answered at the client, got %q", location)
				parsed, err := url.Parse(location)
				require.NoError(t, err)
				assert.Equal(t, "invalid_scope", parsed.Query().Get("error"))
				assert.Equal(t, administrativeScopeRefusedDescription, parsed.Query().Get("error_description"))
				assert.Equal(t, "s1", parsed.Query().Get("state"))
			case deferToLogin:
				assert.Equal(t, http.StatusFound, rr.Code)
				assertStepLocation(t, location, "/auth/level1")
			case blockedPage:
				assert.Empty(t, location)
			}

			var warned bool
			for _, logRecord := range logs.Records() {
				if logRecord.Message == administrativeScopeWarnMessage {
					warned = true
					assert.Equal(t, "WARN", logRecord.Level.String())
					assert.Equal(t, "test-client", logRecord.Attrs["client_identifier"])
					assert.Equal(t, []string{"authserver:manage"}, logRecord.Attrs["scopes"])
				}
			}
			if tc.audited {
				auditLogger.AssertExpectations(t)
				assert.False(t, warned, "a recorded refusal leaves no Warn record beside its row")
			} else {
				auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
				assert.True(t, warned, "an unrecorded refusal leaves a Warn record")
			}
			pageRenderer.AssertExpectations(t)
			ceremonyStore.AssertExpectations(t)
		})
	}
}

// A client allowed to request the administrative scopes is refused none of them: an operator's
// allowance, or the admin console's client whatever its row says (#499 decision 5). Neither is
// refused, so each goes on to the sign-in like any accepted request.
func TestHandleAuthorizeGet_AnAllowedClientIsNotRefusedAnAdministrativeScope(t *testing.T) {
	for _, client := range []*record.Client{
		{Id: 1, ClientIdentifier: "test-client", AdministrativeScopesAllowed: true},
		{Id: 1, ClientIdentifier: "admin-console-client"},
	} {
		t.Run(client.ClientIdentifier, func(t *testing.T) {
			pageRenderer := handlersmocks.NewPageRenderer(t)
			ceremonyStore := handlersmocks.NewCeremonyStore(t)
			userSessionManager := handlersmocks.NewUserSessionManager(t)
			database := datamocks.NewDatabase(t)
			authorizeValidator := handlersmocks.NewAuthorizeValidator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			permissionChecker := handlersmocks.NewPermissionChecker(t)
			tokenParser := handlersmocks.NewTokenParser(t)

			handler := HandleAuthorizeGet(pageRenderer, ceremonyStore, userSessionManager, database, nil,
				authorizeValidator, auditLogger, permissionChecker, tokenParser, testBaseURL)

			target := "/authorize?client_id=" + client.ClientIdentifier + "&redirect_uri=" +
				url.QueryEscape("https://legit.example/cb") +
				"&response_type=code&scope=" + url.QueryEscape("openid authserver:manage")
			req := httptest.NewRequest("GET", target, nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
			rr := httptest.NewRecorder()

			authorizeValidator.On("ValidateClientAndRedirectURI", mock.Anything, mock.Anything).Return(nil)
			database.On("GetClientByClientIdentifier", mock.Anything, mock.Anything, client.ClientIdentifier).Return(client, nil)
			authorizeValidator.On("ValidateUnsupportedRequestParameters", mock.Anything).Return(nil)
			authorizeValidator.On("ValidateRequest", mock.Anything).Return(nil)
			authorizeValidator.On("ValidateScopes", mock.Anything, "openid authserver:manage").Return(nil)
			authorizeValidator.On("ValidatePrompt", "").Return("", nil)
			stubRegisteredRedirectURI(database, "https://legit.example/cb")
			database.On("GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything).
				Return(nil, nil)
			database.On("UserSessionLoadUser", mock.Anything, mock.Anything, (*record.UserSession)(nil)).Return(nil)
			userSessionManager.On("HasValidUserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				Return(false)
			ceremonyStore.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *ceremony.AuthContext) bool {
				return ac.AuthState == ceremony.AuthStateRequiresLevel1 && ac.DeferredErrorCode == "" &&
					ac.Scope == "openid authserver:manage"
			})).Return(nil).Once()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code)
			assertStepLocation(t, rr.Header().Get("Location"), "/auth/level1")
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
			ceremonyStore.AssertExpectations(t)
		})
	}
}
