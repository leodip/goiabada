package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
)

// authorizeFaultEndpoint is GET /auth/authorize built from fresh doubles, with the address check
// passed, for the cases below, each of which fails one read authflow.Authorization makes.
type authorizeFaultEndpoint struct {
	handler            http.HandlerFunc
	pageRenderer       *handlersmocks.PageRenderer
	ceremonyStore      *handlersmocks.CeremonyStore
	userSessionManager *handlersmocks.UserSessionManager
	database           *datamocks.Database
	authorizeValidator *handlersmocks.AuthorizeValidator
	auditLogger        *handlersmocks.AuditLogger
	rr                 *httptest.ResponseRecorder
	req                *http.Request
}

func newAuthorizeFaultEndpoint(t *testing.T, query string) *authorizeFaultEndpoint {
	t.Helper()
	e := &authorizeFaultEndpoint{
		pageRenderer:       handlersmocks.NewPageRenderer(t),
		ceremonyStore:      handlersmocks.NewCeremonyStore(t),
		userSessionManager: handlersmocks.NewUserSessionManager(t),
		database:           datamocks.NewDatabase(t),
		authorizeValidator: handlersmocks.NewAuthorizeValidator(t),
		auditLogger:        handlersmocks.NewAuditLogger(t),
	}
	e.handler = buildAuthorizeGet(authorizeGetDeps{
		pageRenderer:       e.pageRenderer,
		ceremonyStore:      e.ceremonyStore,
		userSessionManager: e.userSessionManager,
		database:           e.database,
		authorizeValidator: e.authorizeValidator,
		auditLogger:        e.auditLogger,
		permissionChecker:  handlersmocks.NewPermissionChecker(t),
		tokenParser:        handlersmocks.NewTokenParser(t),
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/authorize?client_id=test-client"+
		"&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&response_type=code&"+query, nil)
	ctx := reqctx.WithSettings(req.Context(), &record.Settings{Issuer: "https://test-issuer.com"})
	ctx = reqctx.WithSessionIdentifier(ctx, "session-1")
	ctx = context.WithValue(ctx, chimiddleware.RequestIDKey, propagatedRequestId)
	e.req = req.WithContext(ctx)
	e.rr = httptest.NewRecorder()

	e.authorizeValidator.On("ValidateClientAndRedirectURI", theRequestsContext(),
		mock.AnythingOfType("*protocolvalidation.ValidateClientAndRedirectURIInput")).Return(nil).Once()
	return e
}

// expect500 expects the 500 page carrying the error matched, and nothing else written.
func (e *authorizeFaultEndpoint) expect500(err interface{}) {
	e.pageRenderer.On("InternalServerError", e.rr, e.req, err).Return().Once()
}

func (e *authorizeFaultEndpoint) assertNothingAnswered(t *testing.T) {
	t.Helper()
	e.pageRenderer.AssertExpectations(t)
	assert.Empty(t, e.rr.Header().Get("Location"), "a fault answers nobody")
	e.ceremonyStore.AssertNotCalled(t, "ReplaceAuthContext", mock.Anything, mock.Anything, mock.Anything)
	e.auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The client is loaded after the address check accepted it, so a fault there, and a client gone
// between the two reads, is a 500: no ceremony is saved and the client is not answered, since there
// is no client row to decide where an answer may go.
func TestHandleAuthorizeGet_AFaultLoadingTheClientIsA500(t *testing.T) {
	t.Run("a failed read", func(t *testing.T) {
		e := newAuthorizeFaultEndpoint(t, "scope=openid")
		fault := errors.New("the database is unavailable")
		e.database.On("GetClientByClientIdentifier", theRequestsContext(), mock.Anything, "test-client").
			Return(nil, fault).Once()
		e.expect500(fault)

		e.handler.ServeHTTP(e.rr, e.req)

		e.assertNothingAnswered(t)
		e.database.AssertNotCalled(t, "GetRedirectURIsByClientId", mock.Anything, mock.Anything, mock.Anything)
		e.database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a client deleted since the address check", func(t *testing.T) {
		e := newAuthorizeFaultEndpoint(t, "scope=openid")
		e.database.On("GetClientByClientIdentifier", theRequestsContext(), mock.Anything, "test-client").
			Return(nil, nil).Once()
		e.expect500(mock.MatchedBy(func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "client test-client not found")
		}))

		e.handler.ServeHTTP(e.rr, e.req)

		e.assertNothingAnswered(t)
		e.database.AssertNotCalled(t, "GetRedirectURIsByClientId", mock.Anything, mock.Anything, mock.Anything)
		e.database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
	})
}

// A validator that fails, rather than refusing, is a fault and not a refusal: the request is
// answered 500, never with an error response, and nothing is saved.
func TestHandleAuthorizeGet_AValidatorFaultIsA500NotARefusal(t *testing.T) {
	e := newAuthorizeFaultEndpoint(t, "scope=openid&prompt=none")
	e.database.On("GetClientByClientIdentifier", theRequestsContext(), mock.Anything, "test-client").
		Return(&record.Client{Id: 1, ClientIdentifier: "test-client"}, nil).Once()
	fault := errors.New("the database is unavailable")
	e.authorizeValidator.On("ValidateUnsupportedRequestParameters",
		mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil).Once()
	e.authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).
		Return(nil).Once()
	e.authorizeValidator.On("ValidateScopes", theRequestsContext(), "openid").Return(fault).Once()
	e.expect500(fault)

	e.handler.ServeHTTP(e.rr, e.req)

	e.assertNothingAnswered(t)
	e.authorizeValidator.AssertNotCalled(t, "ValidatePrompt", mock.Anything)
	e.database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier", mock.Anything, mock.Anything, mock.Anything)
}

// The session's user is read only once the request is accepted and the route turns on who is
// signed in; a fault reading it is a 500, never "no session", which would send a signed-in user to
// the login page on a transient fault.
func TestHandleAuthorizeGet_AFaultLoadingTheSessionsUserIsA500(t *testing.T) {
	e := newAuthorizeFaultEndpoint(t, "scope=openid")
	e.database.On("GetClientByClientIdentifier", theRequestsContext(), mock.Anything, "test-client").
		Return(&record.Client{Id: 1, ClientIdentifier: "test-client", DefaultAcrLevel: record.AcrLevel1}, nil).Once()
	stubRegisteredRedirectURI(e.database, "https://example.com/cb")
	userSession := &record.UserSession{Id: 1, UserId: 7, SessionIdentifier: "session-1"}
	e.database.On("GetUserSessionBySessionIdentifier", theRequestsContext(), mock.Anything, "session-1").
		Return(userSession, nil).Once()
	e.userSessionManager.On("HasValidUserSession", userSession, mock.AnythingOfType("int"),
		mock.AnythingOfType("int"), mock.AnythingOfType("*int64")).Return(true).Once()
	e.authorizeValidator.On("ValidateUnsupportedRequestParameters",
		mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil).Once()
	e.authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).
		Return(nil).Once()
	e.authorizeValidator.On("ValidateScopes", theRequestsContext(), "openid").Return(nil).Once()
	e.authorizeValidator.On("ValidatePrompt", "").Return("", nil).Once()
	fault := errors.New("the database is unavailable")
	e.database.On("UserSessionLoadUser", theRequestsContext(), mock.Anything, userSession).Return(fault).Once()
	e.expect500(fault)

	e.handler.ServeHTTP(e.rr, e.req)

	e.assertNothingAnswered(t)
}

// A silent request refused for an administrative scope is answered at once, and the refusal is
// recorded against the user when the browser holds a valid session, which the silent route has not
// read; it is read for that record alone. A fault in that read is a 500: the client is not answered
// and nothing is recorded.
func TestHandleAuthorizeGet_AFaultReadingTheSessionForAnAdministrativeRefusalIsA500(t *testing.T) {
	e := newAuthorizeFaultEndpoint(t, "scope="+url.QueryEscape("openid authserver:manage")+"&prompt=none")
	e.database.On("GetClientByClientIdentifier", theRequestsContext(), mock.Anything, "test-client").
		Return(&record.Client{Id: 1, ClientIdentifier: "test-client"}, nil).Once()
	e.authorizeValidator.On("ValidateUnsupportedRequestParameters",
		mock.AnythingOfType("*protocolvalidation.ValidateUnsupportedRequestParametersInput")).Return(nil).Once()
	e.authorizeValidator.On("ValidateRequest", mock.AnythingOfType("*protocolvalidation.ValidateRequestInput")).
		Return(nil).Once()
	e.authorizeValidator.On("ValidateScopes", theRequestsContext(), "openid authserver:manage").Return(nil).Once()
	fault := errors.New("the database is unavailable")
	e.database.On("GetUserSessionBySessionIdentifier", theRequestsContext(), mock.Anything, "session-1").
		Return(nil, fault).Once()
	e.expect500(fault)

	e.handler.ServeHTTP(e.rr, e.req)

	e.assertNothingAnswered(t)
	e.authorizeValidator.AssertNotCalled(t, "ValidatePrompt", mock.Anything)
	e.userSessionManager.AssertNotCalled(t, "HasValidUserSession", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything)
	require.NotEqual(t, http.StatusFound, e.rr.Code)
}
