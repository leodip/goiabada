package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/authserver/internal/handlerhelpers/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	mocks_test "github.com/leodip/goiabada/core/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386, and deliberately thin. What a query does with a context belongs to the data
// tier and what RunInTransaction does with it belongs to the scripted driver; all a handler can
// show is that the context it handed down was the REQUEST's and not one it invented. Repeating
// either of the other two here would break on every refactor while proving nothing.
//
// The matcher is what makes a failure name its cause. chi's request id is on the request's
// context and on no other, so a handler that passed context.Background() -- the exact defect the
// acceptance criterion forbids below a request boundary -- matches nothing, and the strict mock
// reports an unexpected call rather than letting the case pass.

const propagatedRequestId = "goiabada/req-propagation-1"

// requestCarryingId returns a request whose context holds an id nothing else can produce.
func requestCarryingId(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	return req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, propagatedRequestId))
}

// theRequestsContext matches only the context belonging to the request under test.
func theRequestsContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return chimiddleware.GetReqID(ctx) == propagatedRequestId
	})
}

// withURLParam binds a chi route parameter, which HandleProfilePictureGet reads before it reads
// anything else.
func withURLParam(req *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

// TestHandleProfilePictureGet_ConsultsTheDatabaseUnderTheRequestsContext is the accept arm: both
// reads the handler makes carry the request's own context, one of them on a value derived from
// the other, which is the ordinary two-hop shape across this package.
func TestHandleProfilePictureGet_ConsultsTheDatabaseUnderTheRequestsContext(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	req := withURLParam(requestCarryingId(t, http.MethodGet, "/userinfo/picture/sub-1"), "subject", "sub-1")
	rr := httptest.NewRecorder()

	user := &models.User{Id: 7, Subject: "sub-1"}
	database.On("GetUserBySubject", theRequestsContext(), mock.Anything, "sub-1").Return(user, nil).Once()
	database.On("GetUserProfilePictureByUserId", theRequestsContext(), mock.Anything, int64(7)).
		Return(&models.UserProfilePicture{UserId: 7, ContentType: "image/png", Picture: []byte{1, 2, 3}}, nil).Once()

	HandleProfilePictureGet(httpHelper, database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "image/png", rr.Header().Get("Content-Type"))
	database.AssertExpectations(t)
}

// TestHandleProfilePictureGet_RefusedBeforeAnyQuery is the reject arm: a request the handler
// turns away reaches no port at all, so there is no context to get wrong. Without it the accept
// arm would also pass on a handler that queried unconditionally.
func TestHandleProfilePictureGet_RefusedBeforeAnyQuery(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)

	req := withURLParam(requestCarryingId(t, http.MethodGet, "/userinfo/picture/"), "subject", "")
	rr := httptest.NewRecorder()

	HandleProfilePictureGet(httpHelper, database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
	database.AssertNotCalled(t, "GetUserBySubject", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "GetUserProfilePictureByUserId", mock.Anything, mock.Anything, mock.Anything)
}

// Stage 6 adds the session, token and code half. Two places in this package now change a context
// hands that did not before: /auth/issue hands the request's own context to the code issuer's
// port, and the session lookup every ceremony makes is issued under it.

// issueRequestCarryingId is requestWithSessionIdentifier plus the chi request id, so a
// CreateAuthCode called with anything but this request's context matches nothing.
func issueRequestCarryingId(t *testing.T, sessionIdentifier string) *http.Request {
	t.Helper()
	req := requestWithSessionIdentifier(t, sessionIdentifier)
	return req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, propagatedRequestId))
}

// The accept arm, and the one that matters most in this stage: CreateAuthCode is the port whose
// signature moved, and the insert it makes is the statement #139 orders against a concurrent
// termination. Both the acquisition and the insert are matched on the request's context, so a
// transaction opened on a context nobody can cancel fails here rather than in production.
func TestHandleIssueGet_IssuesUnderTheRequestsContext(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	authHelper := mocks_handlers.NewAuthHelper(t)
	templateFS := &mocks_test.TestFS{}
	codeIssuer := mocks_handlers.NewCodeIssuer(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	permissionChecker := mocks_handlers.NewPermissionChecker(t)

	req := issueRequestCarryingId(t, liveSessionIdentifier)
	rr := httptest.NewRecorder()

	authContext := &ceremony.AuthContext{
		AuthState:    ceremony.AuthStateReadyToIssueCode,
		Scope:        "openid profile",
		ClientId:     "test-client",
		UserId:       123,
		ResponseMode: "query",
		ResponseType: "code",
		RedirectURI:  "https://example.com/callback",
	}
	authHelper.On("GetAuthContext", req).Return(authContext, nil)

	// The session read, the acquisition and the insert, each matched on THIS request's context.
	database.On("GetUserSessionBySessionIdentifier", theRequestsContext(), (*sql.Tx)(nil), liveSessionIdentifier).
		Return(&models.UserSession{Id: 55, SessionIdentifier: liveSessionIdentifier, UserId: 123}, nil)
	mocks_data.ExpectRunInTransaction(database, issuanceTx)
	database.On("AcquireUserSessionRow", theRequestsContext(), issuanceTx, liveSessionIdentifier).Return(true, nil).Once()
	codeIssuer.On("CreateAuthCode", theRequestsContext(), issuanceTx, mock.Anything).
		Return(&models.Code{Id: 1, Code: "test-code", ClientId: 1, RedirectURI: "https://example.com/callback"}, nil)

	auditLogger.On("Log", mock.Anything, audit.AuditCreatedAuthCode, mock.Anything).Return()
	authHelper.On("ClearAuthContext", rr, req).Return(nil)
	armIssueGate(database, userSessionManager, permissionChecker, authContext.RedirectURI)

	HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger,
		userSessionManager, permissionChecker).ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code)
	database.AssertExpectations(t)
	codeIssuer.AssertExpectations(t)
}

// The reject arm: a ceremony whose bound session is gone restarts at level 1, so the transaction
// is never opened and the issuer is never reached. Without it the accept arm would also pass on a
// handler that issued unconditionally.
func TestHandleIssueGet_UnusableSessionReachesNoIssuer(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	authHelper := mocks_handlers.NewAuthHelper(t)
	templateFS := &mocks_test.TestFS{}
	codeIssuer := mocks_handlers.NewCodeIssuer(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)
	userSessionManager := mocks_handlers.NewUserSessionManager(t)
	permissionChecker := mocks_handlers.NewPermissionChecker(t)

	req := issueRequestCarryingId(t, liveSessionIdentifier)
	rr := httptest.NewRecorder()

	authContext := &ceremony.AuthContext{
		AuthState:    ceremony.AuthStateReadyToIssueCode,
		Scope:        "openid profile",
		ClientId:     "test-client",
		UserId:       123,
		ResponseMode: "query",
		ResponseType: "code",
		RedirectURI:  "https://example.com/callback",
	}
	authHelper.On("GetAuthContext", req).Return(authContext, nil)

	// The row is gone, which is the shape refuseIssuanceUnusableSession answers.
	database.On("GetUserSessionBySessionIdentifier", theRequestsContext(), (*sql.Tx)(nil), liveSessionIdentifier).
		Return(nil, nil)
	authHelper.On("SaveAuthContext", rr, req, mock.Anything).Return(nil)
	armIssueGate(database, userSessionManager, permissionChecker, authContext.RedirectURI)

	HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger,
		userSessionManager, permissionChecker).ServeHTTP(rr, req)

	require.Equal(t, http.StatusFound, rr.Code)
	assert.Contains(t, rr.Header().Get("Location"), "/auth/level1")
	codeIssuer.AssertNotCalled(t, "CreateAuthCode", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "AcquireUserSessionRow", mock.Anything, mock.Anything, mock.Anything)
}
