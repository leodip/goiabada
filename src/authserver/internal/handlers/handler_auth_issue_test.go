package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_test "github.com/leodip/goiabada/core/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
)

func TestHandleIssueGet(t *testing.T) {
	t.Run("Error when getting GetAuthContext", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedError := &customerrors.ErrorDetail{} // Create an appropriate error
		authHelper.On("GetAuthContext", mock.Anything).Return(nil, expectedError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == expectedError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Unexpected AuthState", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState: oauth.AuthStateInitial, // Unexpected state
		}
		authHelper.On("GetAuthContext", mock.Anything).Return(authContext, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "authContext.AuthState is not ready_to_issue_code"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})

	t.Run("Successfully issues a code", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		// The positive control for the liveness check (#129 stage 6): the ordinary ceremony,
		// with a session identifier in the context and a session row behind it. It fails
		// against a check that refuses a live session, and the compensating call it now
		// expects is what pins that the statement is issued at all.
		req := requestWithSessionIdentifier(t, liveSessionIdentifier)

		rr := httptest.NewRecorder()

		// Mock auth context - note: ResponseType "code" means authorization code flow, not implicit
		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		stubLiveSession(database, 123)

		// Mock code creation
		mockCode := &models.Code{
			Id:          1,
			Code:        "test-code",
			ClientId:    1,
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
		}
		codeIssuer.On("CreateAuthCode", mock.MatchedBy(func(input *oauth.CreateCodeInput) bool {
			return reflect.DeepEqual(input.AuthContext, *authContext) &&
				input.SessionIdentifier == liveSessionIdentifier
		})).Return(mockCode, nil)

		// The compensating revoke, keyed on the code just inserted and the session it was
		// bound to. It matches nothing here, since the session is live.
		database.On("RevokeCodeIfSessionGone", (*sql.Tx)(nil), int64(1), liveSessionIdentifier).Return(false, nil)

		// Mock audit logging
		auditLogger.On("Log", constants.AuditCreatedAuthCode, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["clientId"] == int64(1) && details["codeId"] == int64(1)
		})).Return()

		// Mock clearing auth context
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		// Execute the handler
		handler.ServeHTTP(rr, req)

		// Assertions
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "https://example.com/callback?code=test-code&state=test-state", rr.Header().Get("Location"))

		// Verify that all expected actions were performed
		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	// The liveness check from #129 decision 6's second half. The window it closes opens
	// after /auth/completed: the session was alive and was bumped there, the user then sits
	// on the consent screen, and the session is ended before the code is minted. Stage 1's
	// marker cannot reach that code, because the row does not exist when the termination
	// sweeps.
	//
	// "No code created" is enforced rather than asserted in the refusal rows below: the strict
	// mocks_oauth.CodeIssuer carries no CreateAuthCode expectation, so reaching it fails the
	// case on its own, and the audit logger is not stubbed either.
	//
	// Two outcomes, one predicate. An interactive ceremony restarts level 1 (decision 6), and
	// a prompt=none one is returned login_required (decision 16), because a request that
	// forbids UI cannot be sent to a password form.
	t.Run("No session identifier in the context, restarts level 1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		// An empty identifier is the shape the terminated ceremony actually arrives in:
		// MiddlewareSessionIdentifier finds the row gone, deletes the identifier from the
		// cookie session, and leaves it out of the request context. It is also the shape
		// grantIsOffline reads as an offline grant, so a code issued here would produce a
		// refresh token with a max lifetime and no session to check.
		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		var savedAuthContext *oauth.AuthContext
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			savedAuthContext = ac
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "/auth/level1")
		assert.NotNil(t, savedAuthContext)
		assert.Equal(t, oauth.AuthStateRequiresLevel1, savedAuthContext.AuthState)

		// No lookup either: with nothing to resolve there is no question to ask the database.
		database.AssertNotCalled(t, "GetUserSessionBySessionIdentifier")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
	})

	t.Run("Session identifier resolves to no session, restarts level 1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		// The narrower half of the same predicate: the middleware saw the session alive on
		// this very request and the termination committed immediately afterwards, so the
		// identifier is still in the context but the row is gone.
		req := requestWithSessionIdentifier(t, liveSessionIdentifier)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		database.On("GetUserSessionBySessionIdentifier", (*sql.Tx)(nil), liveSessionIdentifier).Return(nil, nil)

		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Contains(t, rr.Header().Get("Location"), "/auth/level1")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
	})

	t.Run("No session and prompt=none, returns login_required to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		// The same empty identifier as the row above, arriving from handlePromptNone rather
		// than from the consent screen: it validated and bumped the session, redirected here,
		// and the session was ended in that hop. Restarting level 1 would render a password
		// form, which this request forbids (#129 decision 16).
		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
			Prompt:       "none",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		// Asserting that ClearAuthContext was called says nothing about whether the clear
		// reaches the browser, because the real helper persists the deletion through a
		// Set-Cookie on w and a header set after the redirect has written the status line
		// is dropped. The stub writes a sentinel where the CookieStore would write that
		// cookie, so the committed response is what carries the assertion below.
		const clearedContextCookie = "cleared-auth-context"
		authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
			args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
		}).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback")
		assert.Contains(t, location, "error=login_required")
		assert.Contains(t, location, "state=test-state")
		assert.NotContains(t, location, "code=")
		assert.NotContains(t, location, "/auth/level1")

		// Result() reads the header as it was when the response was committed, which is the
		// only view that can tell the two orderings apart: rr.Header() shows the sentinel
		// either way, since the handler and the stub share one live map.
		assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
			"the auth context must be cleared before the client response is committed, or the browser keeps a ready_to_issue_code context to replay")

		// The ceremony ends here rather than being restarted, so the state the interactive
		// rows assert is never saved.
		authHelper.AssertNotCalled(t, "SaveAuthContext")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
	})

	t.Run("No session and prompt=none, failing clear - server_error to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
			Prompt:       "none",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		// This site's ordering was already correct, so what changes here is only the failure
		// branch: a failed clear writes no cookie, so the browser keeps the auth context whether
		// this answers 500 or redirects, and the client is owed its error response either way
		// (#141 decision 7). It used to get nothing at all.
		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		handler.ServeHTTP(rr, req)

		// httpHelper has no InternalServerError expectation, so the mock fails the test if the
		// handler answers with a bare 500 instead of redirecting the client.
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "https://example.com/callback")
		assert.Contains(t, location, "error=server_error")
		assert.Contains(t, location, "error_description=Internal+server+error")
		assert.NotContains(t, location, "login_required")
		assert.NotContains(t, location, "/auth/level1")

		authHelper.AssertNotCalled(t, "SaveAuthContext")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
	})

	t.Run("No session and prompt=none, failing clear and an unusable form_post template - last-resort 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		// Deliberately malformed, an unclosed action, so template.ParseFS fails and
		// redirToClientWithError returns "unable to parse template" instead of committing.
		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "form_post",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
			Prompt:       "none",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		// The clear failed and the server_error response the client is owed cannot be built
		// either, so there is nowhere left to send it and the 500 is the last resort.
		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
	})

	t.Run("No session and prompt=none, unusable form_post template - 500 when the refusal itself cannot be sent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "form_post",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
			Prompt:       "none",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		// The other half of the same family: the clear succeeds and it is the ordinary
		// login_required refusal that cannot be committed. This 500 predates #141 and is pinned
		// separately so a future edit cannot delete either copy unnoticed.
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
	})

	t.Run("Session lookup fails", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req := requestWithSessionIdentifier(t, liveSessionIdentifier)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		// A database fault must not read as a terminated session, and must not read as a
		// live one either: no code is minted and no restart is offered.
		dbError := errors.New("session lookup failed")
		database.On("GetUserSessionBySessionIdentifier", (*sql.Tx)(nil), liveSessionIdentifier).Return(nil, dbError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == dbError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		authHelper.AssertNotCalled(t, "SaveAuthContext")
	})

	t.Run("The compensating revoke fails, so no code reaches the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req := requestWithSessionIdentifier(t, liveSessionIdentifier)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "query",
			ResponseType: "code",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		stubLiveSession(database, 123)

		mockCode := &models.Code{
			Id:          1,
			Code:        "test-code",
			ClientId:    1,
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
		}
		codeIssuer.On("CreateAuthCode", mock.Anything).Return(mockCode, nil)

		// The code row exists and carries no marker at this point, so handing it over is
		// exactly the fail-open decision 12 closes. Unredeemed it expires in 60 seconds.
		revokeError := errors.New("compensating revoke failed")
		database.On("RevokeCodeIfSessionGone", (*sql.Tx)(nil), int64(1), liveSessionIdentifier).Return(false, revokeError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == revokeError
		})).Return()

		handler.ServeHTTP(rr, req)

		// Not a redirect to the client: the code was created but never delivered.
		assert.NotContains(t, rr.Header().Get("Location"), "code=test-code")

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertNotCalled(t, "Log")
		authHelper.AssertNotCalled(t, "ClearAuthContext")
	})
}

// =============================================================================
// #133: the browser's ambient session belongs to somebody else
//
// The last gate before an identifier is stamped onto a grant. User A is signed in, the cookie
// still names A's session, and user B has just authenticated through prompt=login or an
// id_token_hint. After stages 1 and 2 nothing reaches this state, which is the point of a
// backstop, so these drive the handler directly rather than through the flow.
//
// One case per issuance family, because one shared gate is only worth what its weakest branch
// is: the code flow reaches CreateAuthCode, and the three implicit response types reach
// GenerateTokenResponseForImplicit through a dispatch that used to sit ABOVE this check and
// never loaded the session at all. An implicit token is signed and handed to a resource server
// that cannot look the session up, so nothing downstream can catch it later.
//
// "Nothing was issued" is enforced rather than asserted: the strict CodeIssuer and TokenIssuer
// carry no expectations in the refusal rows, so reaching either fails the case on its own. The
// explicit AssertNotCalled lines are there to name what is being claimed.
// =============================================================================

// foreignSessionUserId owns the ambient session in the refusal rows below. It differs from
// every ceremony's UserId, which is the only thing making the gate refuse.
const foreignSessionUserId int64 = 999

func TestHandleIssueGet_ForeignAmbientSession(t *testing.T) {
	// Each row is a different issuance family reached from the same gate. ResponseMode is left
	// as the client would send it: empty on the implicit rows, which is what makes
	// redirToClientWithError default them to a fragment in the prompt=none case below.
	issuanceFamilies := []struct {
		name         string
		responseType string
		responseMode string
	}{
		{name: "code flow", responseType: "code", responseMode: "query"},
		{name: "implicit, token", responseType: "token", responseMode: ""},
		{name: "implicit, id_token", responseType: "id_token", responseMode: ""},
		{name: "implicit, id_token token", responseType: "id_token token", responseMode: ""},
	}

	for _, family := range issuanceFamilies {
		t.Run("Foreign ambient session restarts level 1: "+family.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			authHelper := mocks_handlerhelpers.NewAuthHelper(t)
			templateFS := &mocks_test.TestFS{}
			codeIssuer := mocks_oauth.NewCodeIssuer(t)
			tokenIssuer := mocks_oauth.NewTokenIssuer(t)
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

			logs := captureLogs(t)
			req := requestWithSessionIdentifier(t, liveSessionIdentifier)
			rr := httptest.NewRecorder()

			authContext := &oauth.AuthContext{
				AuthState:    oauth.AuthStateReadyToIssueCode,
				ClientId:     "test-client",
				UserId:       123,
				ResponseMode: family.responseMode,
				ResponseType: family.responseType,
				RedirectURI:  "https://example.com/callback",
				State:        "test-state",
			}
			authHelper.On("GetAuthContext", req).Return(authContext, nil)

			// The row resolves, so this is not the liveness case #129 closed. It simply
			// belongs to someone else.
			stubLiveSession(database, foreignSessionUserId)

			var savedAuthContext *oauth.AuthContext
			authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
				savedAuthContext = ac
				return ac.AuthState == oauth.AuthStateRequiresLevel1
			})).Return(nil)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code)
			assert.Contains(t, rr.Header().Get("Location"), "/auth/level1")
			assert.NotNil(t, savedAuthContext)
			assert.Equal(t, oauth.AuthStateRequiresLevel1, savedAuthContext.AuthState)

			// Nothing may be handed to the client on the way past.
			location := rr.Header().Get("Location")
			assert.NotContains(t, location, "code=")
			assert.NotContains(t, location, "access_token=")
			assert.NotContains(t, location, "id_token=")
			codeIssuer.AssertNotCalled(t, "CreateAuthCode")
			tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForImplicit")

			assertWarnedForeignSession(t, logs, authContext.UserId)

			// The ceremony is restarted rather than ended, so the context survives to be
			// rebuilt at /auth/level1.
			authHelper.AssertNotCalled(t, "ClearAuthContext")

			httpHelper.AssertExpectations(t)
			authHelper.AssertExpectations(t)
			database.AssertExpectations(t)
			codeIssuer.AssertExpectations(t)
			tokenIssuer.AssertExpectations(t)
		})
	}

	// prompt=none forbids UI, so the refusal cannot be a redirect to a password form. Two rows
	// rather than one, because the error has to reach the client in the response mode its
	// family uses: a query for the code flow, and a fragment for implicit, which
	// redirToClientWithError picks from the response type when no mode was requested (RFC 6749
	// 4.2.2.1, OIDC Core 3.2.2.5).
	promptNoneFamilies := []struct {
		name          string
		responseType  string
		responseMode  string
		wantSeparator string
	}{
		{name: "code flow, query", responseType: "code", responseMode: "query", wantSeparator: "?"},
		{name: "implicit, fragment", responseType: "id_token token", responseMode: "", wantSeparator: "#"},
	}

	for _, family := range promptNoneFamilies {
		t.Run("Foreign ambient session and prompt=none returns login_required: "+family.name, func(t *testing.T) {
			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			authHelper := mocks_handlerhelpers.NewAuthHelper(t)
			templateFS := &mocks_test.TestFS{}
			codeIssuer := mocks_oauth.NewCodeIssuer(t)
			tokenIssuer := mocks_oauth.NewTokenIssuer(t)
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

			logs := captureLogs(t)
			req := requestWithSessionIdentifier(t, liveSessionIdentifier)
			rr := httptest.NewRecorder()

			authContext := &oauth.AuthContext{
				AuthState:    oauth.AuthStateReadyToIssueCode,
				ClientId:     "test-client",
				UserId:       123,
				ResponseMode: family.responseMode,
				ResponseType: family.responseType,
				RedirectURI:  "https://example.com/callback",
				State:        "test-state",
				Prompt:       "none",
			}
			authHelper.On("GetAuthContext", req).Return(authContext, nil)

			stubLiveSession(database, foreignSessionUserId)
			stubClientProvenanceLookup(database)
			authHelper.On("ClearAuthContext", rr, req).Return(nil)

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusFound, rr.Code)
			location := rr.Header().Get("Location")
			assert.Contains(t, location, "https://example.com/callback"+family.wantSeparator)
			assert.Contains(t, location, "error=login_required")
			assert.Contains(t, location, "state=test-state")
			assert.NotContains(t, location, "/auth/level1")
			assert.NotContains(t, location, "code=")
			assert.NotContains(t, location, "access_token=")

			codeIssuer.AssertNotCalled(t, "CreateAuthCode")
			tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForImplicit")

			assertWarnedForeignSession(t, logs, authContext.UserId)

			// A silent ceremony ends here rather than restarting, so no state is saved.
			authHelper.AssertNotCalled(t, "SaveAuthContext")

			httpHelper.AssertExpectations(t)
			authHelper.AssertExpectations(t)
			database.AssertExpectations(t)
			codeIssuer.AssertExpectations(t)
			tokenIssuer.AssertExpectations(t)
		})
	}

	// The control for the implicit family. "Successfully issues a code" is the code flow's, and
	// without one here every implicit row above would pass against a gate that refused implicit
	// outright. It also pins that the identifier still reaches the token when the session is the
	// ceremony's own, which is what the whole change is careful not to break.
	t.Run("Own ambient session still issues implicit tokens carrying its identifier", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req := requestWithSessionIdentifier(t, liveSessionIdentifier)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "fragment",
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
			State:        "test-state",
			AuthMethods:  "pwd",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		stubLiveSession(database, 123)

		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").
			Return(&models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}, nil)
		database.On("GetUserById", mock.Anything, int64(123)).
			Return(&models.User{Id: 123, Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111"), Enabled: true}, nil)

		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.User.Id == int64(123) && input.SessionIdentifier == liveSessionIdentifier
		}), true, false).Return(&oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "openid",
		}, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.Anything).Return()
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.NotContains(t, location, "/auth/level1")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

// =============================================================================
// #133 stage 3: where the implicit carve-out stops.
//
// mayBind is forced true for an implicit request only when the identifier is EMPTY, meaning
// the browser carries no ambient session at all and there is nothing to cross-bind to. A
// NON-EMPTY identifier whose row has vanished is a different shape and is refused, which is the
// answer the code flow has given since #129: MiddlewareSessionIdentifier publishes the
// identifier only when the row exists, so arriving here with one that no longer resolves means
// the session was ended during this very request.
//
// The distinction is what these two rows exist to hold. Widening the carve-out to "implicit and
// no session was loaded" reads as an equivalent simplification and is not: it swallows the
// vanished-row case, and that is the shape no later backstop can reach, because an implicit
// token is signed and handed to a resource server with no way to look the session up.
// =============================================================================
func TestHandleIssueGet_ImplicitAmbientSessionVanished(t *testing.T) {
	t.Run("Implicit request whose session row has vanished restarts level 1", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		logs := captureLogs(t)
		req := requestWithSessionIdentifier(t, liveSessionIdentifier)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		// Non-empty identifier, no row. The carve-out asks about the identifier, so it does
		// not apply here, and OwnsSession(nil) is false.
		database.On("GetUserSessionBySessionIdentifier", (*sql.Tx)(nil), liveSessionIdentifier).Return(nil, nil)

		var savedAuthContext *oauth.AuthContext
		authHelper.On("SaveAuthContext", rr, req, mock.MatchedBy(func(ac *oauth.AuthContext) bool {
			savedAuthContext = ac
			return ac.AuthState == oauth.AuthStateRequiresLevel1
		})).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "/auth/level1")
		assert.NotContains(t, location, "access_token=")
		assert.NotContains(t, location, "id_token=")
		assert.NotNil(t, savedAuthContext)
		assert.Equal(t, oauth.AuthStateRequiresLevel1, savedAuthContext.AuthState)

		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForImplicit")
		// No owner to name, so this takes #129's line rather than decision 7's.
		assertWarnedSessionGone(t, logs)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
	})

	t.Run("Implicit request whose session row has vanished and prompt=none returns login_required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		logs := captureLogs(t)
		req := requestWithSessionIdentifier(t, liveSessionIdentifier)
		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "id_token token",
			RedirectURI:  "https://example.com/callback",
			State:        "test-state",
			Prompt:       "none",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		database.On("GetUserSessionBySessionIdentifier", (*sql.Tx)(nil), liveSessionIdentifier).Return(nil, nil)
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "error=login_required")
		assert.Contains(t, location, "state=test-state")
		assert.NotContains(t, location, "access_token=")
		assert.NotContains(t, location, "id_token=")

		tokenIssuer.AssertNotCalled(t, "GenerateTokenResponseForImplicit")
		authHelper.AssertNotCalled(t, "SaveAuthContext")
		assertWarnedSessionGone(t, logs)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
	})
}

// liveSessionIdentifier is the session identifier the code-flow subtests put in the request
// context. Any non-empty value does, since the liveness check asks the database rather than
// parsing it.
const liveSessionIdentifier = "session-identifier-abc"

// requestWithSessionIdentifier builds the /auth/issue request the way
// MiddlewareSessionIdentifier leaves it when the session row exists: the identifier is in the
// request context. Its absence is the terminated case, which is why the subtests that expect
// a code have to opt in (#129 stage 6).
func requestWithSessionIdentifier(t *testing.T, sessionIdentifier string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "/auth/issue", nil)
	assert.NoError(t, err)
	return req.WithContext(context.WithValue(req.Context(),
		constants.ContextKeySessionIdentifier, sessionIdentifier))
}

// stubLiveSession makes the ownership check pass, which is the precondition for reaching
// CreateAuthCode or GenerateTokenResponseForImplicit at all. Liveness alone was enough after
// #129 stage 6; #133 added the owner comparison, so the caller has to say which user the row
// belongs to and a subtest that wants the gate to pass has to name its own ceremony's user.
func stubLiveSession(database *mocks_data.Database, ownerUserId int64) {
	database.On("GetUserSessionBySessionIdentifier", (*sql.Tx)(nil), liveSessionIdentifier).
		Return(&models.UserSession{Id: 55, SessionIdentifier: liveSessionIdentifier, UserId: ownerUserId}, nil)
}

// capturedLogs holds the slog records emitted while one subtest runs. Whole records rather than
// the flattened text buffer this replaced, because two of the properties decision 7's line is
// owed cannot be seen in a buffer at all: that the record is a WARNING, and that the message and
// the two user ids sit on the SAME record. Both gaps were demonstrated against the buffer
// version: demoting slog.Warn to slog.Info, and splitting the message away from the ids into a
// second unrelated record, each left every assertion green (#133).
type capturedLogs struct {
	mu      sync.Mutex
	records []slog.Record
}

func (c *capturedLogs) add(record slog.Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record)
}

func (c *capturedLogs) all() []slog.Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]slog.Record(nil), c.records...)
}

// recordingHandler is the slog.Handler side of capturedLogs. WithAttrs is carried forward so a
// logger built through slog.With records what it would print; nothing under test opens a group,
// so WithGroup is the identity and grouped key qualification is not modelled.
type recordingHandler struct {
	logs  *capturedLogs
	attrs []slog.Attr
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	// Clone before keeping it: a Record's attributes may share backing storage with the caller's.
	kept := record.Clone()
	kept.AddAttrs(h.attrs...)
	h.logs.add(kept)
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	carried := append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &recordingHandler{logs: h.logs, attrs: carried}
}

func (h *recordingHandler) WithGroup(string) slog.Handler { return h }

// captureLogs sends the default slog logger into a recorder for one subtest and restores it
// afterwards. The refusal arms below answer a foreign session and a missing one identically
// from the client's side, deliberately, so what was logged is the only place the two can be
// told apart and the only place an assertion can reach them.
func captureLogs(t *testing.T) *capturedLogs {
	t.Helper()
	logs := &capturedLogs{}
	previous := slog.Default()
	slog.SetDefault(slog.New(&recordingHandler{logs: logs}))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return logs
}

// warningSaying returns the one WARN record whose message carries the discriminator, and fails
// when there is not exactly one. The level is asserted rather than assumed: an operator
// filtering at warning level is the reader this line was written for, so a record quietly
// demoted to Info would be invisible to them while every text assertion still passed.
func warningSaying(t *testing.T, logs *capturedLogs, discriminator string) (slog.Record, bool) {
	t.Helper()
	captured := logs.all()
	var matched []slog.Record
	for _, record := range captured {
		if record.Level == slog.LevelWarn && strings.Contains(record.Message, discriminator) {
			matched = append(matched, record)
		}
	}
	if !assert.Len(t, matched, 1,
		"want exactly one WARN record saying %q, out of %d captured", discriminator, len(captured)) {
		return slog.Record{}, false
	}
	return matched[0], true
}

// attrsOf flattens ONE record's attributes, which is the whole point of it taking a record: an
// assertion has to name where it read a value, or two unrelated records satisfy it between them.
func attrsOf(record slog.Record) map[string]any {
	attrs := make(map[string]any)
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Resolve().Any()
		return true
	})
	return attrs
}

// noRecordSays fails when any captured record carries the phrase, at any level. The two refusal
// arms are one discrimination, so the wrong sentence appearing anywhere in a refusal is the
// failure, not merely its appearance on the record examined above.
func noRecordSays(t *testing.T, logs *capturedLogs, phrase string) {
	t.Helper()
	for _, record := range logs.all() {
		assert.NotContains(t, record.Message, phrase, "no record should say %q here", phrase)
	}
}

// assertWarnedForeignSession pins decision 7's own log line. An operator looking at a refusal
// has to be able to tell "this browser's session belongs to someone else" from "this ceremony's
// session is gone", and to see the two user ids that failed to match, because those ids are the
// whole record of an account takeover attempt that got as far as issuance (#133).
func assertWarnedForeignSession(t *testing.T, logs *capturedLogs, ceremonyUserId int64) {
	t.Helper()
	record, ok := warningSaying(t, logs, "belongs to a different user")
	if !ok {
		return
	}
	attrs := attrsOf(record)
	assert.Equal(t, foreignSessionUserId, attrs["sessionUserId"],
		"the ambient session's owner, on the record that names the refusal")
	assert.Equal(t, ceremonyUserId, attrs["ceremonyUserId"],
		"the user this ceremony authenticated, on that same record")
	// #129's sentence, which is the wrong one here: the row resolved.
	noRecordSays(t, logs, "is gone")
}

// assertWarnedSessionGone is the other side of the same discrimination: a row that did not
// resolve has no owner to name, so #129's line stands verbatim and neither user id appears on
// it. An operator handed one here would be reading an owner nothing established.
func assertWarnedSessionGone(t *testing.T, logs *capturedLogs) {
	t.Helper()
	record, ok := warningSaying(t, logs, "is gone")
	if !ok {
		return
	}
	attrs := attrsOf(record)
	assert.NotContains(t, attrs, "sessionUserId")
	assert.NotContains(t, attrs, "ceremonyUserId")
	noRecordSays(t, logs, "belongs to a different user")
}

func TestIsImplicitFlow(t *testing.T) {
	tests := []struct {
		name         string
		responseType string
		expected     bool
	}{
		// Implicit flow response types (should return true)
		{
			name:         "token only",
			responseType: "token",
			expected:     true,
		},
		{
			name:         "id_token only",
			responseType: "id_token",
			expected:     true,
		},
		{
			name:         "id_token token",
			responseType: "id_token token",
			expected:     true,
		},
		{
			name:         "token id_token (reversed order)",
			responseType: "token id_token",
			expected:     true,
		},
		// Authorization code flow (should return false)
		{
			name:         "code only",
			responseType: "code",
			expected:     false,
		},
		{
			name:         "empty response type",
			responseType: "",
			expected:     false,
		},
		// Hybrid flows (contain code, should return false)
		{
			name:         "code token (hybrid)",
			responseType: "code token",
			expected:     false,
		},
		{
			name:         "code id_token (hybrid)",
			responseType: "code id_token",
			expected:     false,
		},
		{
			name:         "code id_token token (hybrid)",
			responseType: "code id_token token",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := oauth.ParseResponseType(tt.responseType).IsImplicitFlow()
			assert.Equal(t, tt.expected, result, "IsImplicitFlow(%q) = %v, want %v", tt.responseType, result, tt.expected)
		})
	}
}

func TestHandleIssueGet_ImplicitFlow(t *testing.T) {
	t.Run("Implicit flow with token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "fragment",
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
			State:        "test-state",
			Nonce:        "test-nonce",
			AcrLevel:     "urn:goiabada:pwd",
			// Nonzero so the matcher below pins that the handler carries this into
			// ImplicitGrantInput rather than leaving it at the zero value (#106
			// decision 13: implicit's only possible source is the AuthContext).
			AuthStateGeneration: 7,
			AuthMethods:         "pwd",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		// Mock client lookup
		mockClient := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Enabled:          true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		// Mock user lookup
		mockUser := &models.User{
			Id:      123,
			Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			Email:   "test@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		// Mock token generation
		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "openid",
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.Client.Id == int64(1) && input.User.Id == int64(123) && input.Scope == "openid" &&
				input.AuthStateGeneration == 7
		}), true, false).Return(tokenResponse, nil)

		// Mock audit logging
		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(123) && details["clientId"] == int64(1) && details["issueAccessToken"] == true && details["issueIdToken"] == false
		})).Return()

		// Mock clearing auth context
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.Contains(t, location, "token_type=Bearer")
		assert.Contains(t, location, "expires_in=3600")
		assert.Contains(t, location, "state=test-state")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Implicit flow with id_token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "fragment",
			ResponseType: "id_token",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
			State:        "test-state",
			Nonce:        "test-nonce",
			AcrLevel:     "urn:goiabada:pwd",
			// Nonzero so the matcher below pins that the handler carries this into
			// ImplicitGrantInput rather than leaving it at the zero value (#106
			// decision 13: implicit's only possible source is the AuthContext).
			AuthStateGeneration: 7,
			AuthMethods:         "pwd",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Enabled:          true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{
			Id:      123,
			Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			Email:   "test@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			IdToken: "id-token-123",
			Scope:   "openid",
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.Client.Id == int64(1) && input.User.Id == int64(123) && input.Nonce == "test-nonce"
		}), false, true).Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["issueAccessToken"] == false && details["issueIdToken"] == true
		})).Return()

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "id_token=id-token-123")
		assert.Contains(t, location, "state=test-state")
		assert.NotContains(t, location, "access_token=")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Implicit flow with id_token token response type", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseMode: "fragment",
			ResponseType: "id_token token",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
			State:        "test-state",
			Nonce:        "test-nonce",
			AcrLevel:     "urn:goiabada:pwd",
			// Nonzero so the matcher below pins that the handler carries this into
			// ImplicitGrantInput rather than leaving it at the zero value (#106
			// decision 13: implicit's only possible source is the AuthContext).
			AuthStateGeneration: 7,
			AuthMethods:         "pwd",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{
			Id:               1,
			ClientIdentifier: "test-client",
			Enabled:          true,
		}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{
			Id:      123,
			Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			Email:   "test@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IdToken:     "id-token-123",
			Scope:       "openid",
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.Client.Id == int64(1) && input.User.Id == int64(123)
		}), true, true).Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["issueAccessToken"] == true && details["issueIdToken"] == true
		})).Return()

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.Contains(t, location, "id_token=id-token-123")
		assert.Contains(t, location, "token_type=Bearer")
		assert.Contains(t, location, "expires_in=3600")
		assert.Contains(t, location, "state=test-state")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Implicit flow uses consented scope when available", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         123,
			ResponseType:   "token",
			RedirectURI:    "https://example.com/callback",
			Scope:          "openid profile email",
			ConsentedScope: "openid profile", // User consented to less
			State:          "test-state",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{Id: 123, Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111")}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "openid profile",
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.MatchedBy(func(input *oauth.ImplicitGrantInput) bool {
			return input.Scope == "openid profile" // Should use consented scope
		}), true, false).Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.Anything).Return()
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "scope=openid+profile")

		tokenIssuer.AssertExpectations(t)
	})

	t.Run("Implicit flow error - client not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "unknown-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		database.On("GetClientByClientIdentifier", mock.Anything, "unknown-client").Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "client unknown-client not found")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Implicit flow error - user not found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       999,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		database.On("GetUserById", mock.Anything, int64(999)).Return(nil, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "user 999 not found")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Implicit flow error - token generation fails", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{Id: 123, Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111")}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenError := errors.New("token generation failed")
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.Anything, true, false).Return(nil, tokenError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == tokenError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		tokenIssuer.AssertExpectations(t)
	})
}

func TestIssueImplicitTokens(t *testing.T) {
	t.Run("Access token only", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			Scope:       "openid",
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "test-state", tokenResponse)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.Contains(t, location, "token_type=Bearer")
		assert.Contains(t, location, "expires_in=3600")
		assert.Contains(t, location, "scope=openid")
		assert.Contains(t, location, "state=test-state")
		assert.NotContains(t, location, "id_token=")
	})

	t.Run("ID token only", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			IdToken: "id-token-123",
			Scope:   "openid",
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "test-state", tokenResponse)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "id_token=id-token-123")
		assert.Contains(t, location, "scope=openid")
		assert.Contains(t, location, "state=test-state")
		assert.NotContains(t, location, "access_token=")
		assert.NotContains(t, location, "token_type=")
		assert.NotContains(t, location, "expires_in=")
	})

	t.Run("Both access token and ID token", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			IdToken:     "id-token-123",
			Scope:       "openid profile",
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "test-state", tokenResponse)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.Contains(t, location, "token_type=Bearer")
		assert.Contains(t, location, "expires_in=3600")
		assert.Contains(t, location, "id_token=id-token-123")
		assert.Contains(t, location, "state=test-state")
	})

	t.Run("No state parameter", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "", tokenResponse)

		assert.NoError(t, err)
		location := w.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback#")
		assert.Contains(t, location, "access_token=access-token-123")
		assert.NotContains(t, location, "state=")
	})

	t.Run("State with whitespace only", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "   ", tokenResponse)

		assert.NoError(t, err)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "state=")
	})

	t.Run("No scope in response", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		err := issueImplicitTokens(w, r, "https://example.com/callback", "test-state", tokenResponse)

		assert.NoError(t, err)
		location := w.Header().Get("Location")
		assert.NotContains(t, location, "scope=")
	})

	// Gate 4, the last resort (#122). The stake here is higher than at issueAuthCode: this function
	// hands over the access and ID tokens themselves rather than a code still to be exchanged, so a
	// redirect URI resolving to a host nobody registered exfiltrates the credentials directly and
	// there is nothing left to expire.
	//
	// Not a validation case. The value has passed the authorization endpoint's gate by construction,
	// and the property being stated is that no emission exists which is not downstream of one.
	t.Run("A redirect URI that is not an absolute URI is refused", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			redirectURI string
			why         string
		}{
			{
				name:        "scheme-relative",
				redirectURI: "//evil.example/cb",
				why:         "the user agent resolves it against the current scheme and delivers the tokens to evil.example",
			},
			{
				name:        "https with no authority",
				redirectURI: "https:///evil.example/cb",
				why:         "decision 8's family: a valid absolute-URI that Go reads with no host and a browser reads as evil.example",
			},
			{
				name:        "relative",
				redirectURI: "/relative/cb",
				why:         "the tokens arrive back at this authorization server rather than at any client",
			},
			{
				name:        "carrying a fragment",
				redirectURI: "https://legit.example/cb#frag",
				why:         "this flow delivers in the fragment, so a registered fragment collides with the delivery itself",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				r := httptest.NewRequest("GET", "/auth/issue", nil)

				tokenResponse := &oauth.ImplicitGrantResponse{
					AccessToken: "access-token-123",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
					IdToken:     "id-token-123",
					Scope:       "openid",
				}

				err := issueImplicitTokens(w, r, tc.redirectURI, "test-state", tokenResponse)

				assert.Error(t, err, tc.why)
				assert.Empty(t, w.Header().Get("Location"), "no Location may be written for %q", tc.redirectURI)
				assert.NotContains(t, w.Body.String(), "access-token-123", "the tokens must not reach the response at all")
			})
		}
	})
}

func TestHandleIssueGet_ImplicitFlow_DatabaseErrors(t *testing.T) {
	t.Run("Implicit flow error - database error on client lookup", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		dbError := errors.New("database connection failed")
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(nil, dbError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == dbError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Implicit flow error - database error on user lookup", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		dbError := errors.New("user database error")
		database.On("GetUserById", mock.Anything, int64(123)).Return(nil, dbError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == dbError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("Implicit flow error - clear auth context fails", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		authContext := &oauth.AuthContext{
			AuthState:    oauth.AuthStateReadyToIssueCode,
			ClientId:     "test-client",
			UserId:       123,
			ResponseType: "token",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		mockClient := &models.Client{Id: 1, ClientIdentifier: "test-client", Enabled: true}
		database.On("GetClientByClientIdentifier", mock.Anything, "test-client").Return(mockClient, nil)

		mockUser := &models.User{Id: 123, Subject: uuid.MustParse("11111111-1111-1111-1111-111111111111")}
		database.On("GetUserById", mock.Anything, int64(123)).Return(mockUser, nil)

		tokenResponse := &oauth.ImplicitGrantResponse{
			AccessToken: "access-token-123",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}
		tokenIssuer.On("GenerateTokenResponseForImplicit", mock.Anything, mock.Anything, true, false).Return(tokenResponse, nil)

		auditLogger.On("Log", constants.AuditTokenIssuedImplicitResponse, mock.Anything).Return()

		clearError := errors.New("failed to clear auth context")
		authHelper.On("ClearAuthContext", rr, req).Return(clearError)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err == clearError
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
	})
}

func TestIsImplicitFlow_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		responseType string
		expected     bool
	}{
		// Edge cases
		{
			name:         "multiple spaces between tokens",
			responseType: "id_token  token",
			expected:     true,
		},
		{
			name:         "leading space",
			responseType: " token",
			expected:     true,
		},
		{
			name:         "trailing space",
			responseType: "token ",
			expected:     true,
		},
		{
			name:         "all whitespace",
			responseType: "   ",
			expected:     false,
		},
		{
			name:         "tab character",
			responseType: "token\tid_token",
			expected:     true,
		},
		{
			name:         "newline character",
			responseType: "token\nid_token",
			expected:     true,
		},
		{
			name:         "unknown response type",
			responseType: "unknown",
			expected:     false,
		},
		{
			name:         "partial match - tokens",
			responseType: "tokens",
			expected:     false,
		},
		{
			name:         "partial match - id_tokens",
			responseType: "id_tokens",
			expected:     false,
		},
		{
			name:         "case sensitivity - TOKEN",
			responseType: "TOKEN",
			expected:     false, // OAuth is case-sensitive
		},
		{
			name:         "case sensitivity - ID_TOKEN",
			responseType: "ID_TOKEN",
			expected:     false, // OAuth is case-sensitive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := oauth.ParseResponseType(tt.responseType).IsImplicitFlow()
			assert.Equal(t, tt.expected, result, "IsImplicitFlow(%q) = %v, want %v", tt.responseType, result, tt.expected)
		})
	}
}

func TestIssueAuthCode(t *testing.T) {
	t.Run("Query response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "query")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback?code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Fragment response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "fragment")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback#code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Form post response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form method="post" action="{{.redirectURI}}">
					<input type="hidden" name="code" value="{{.code}}">
					<input type="hidden" name="state" value="{{.state}}">
				</form>`,
			},
		}

		err := issueAuthCode(w, r, templateFS, code, "form_post")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), `<form method="post" action="https://example.com/callback">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="code" value="test_code">`)
		assert.Contains(t, w.Body.String(), `<input type="hidden" name="state" value="test_state">`)
	})

	t.Run("Default to query response mode", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://example.com/callback?code=test_code&state=test_state", w.Header().Get("Location"))
	})

	t.Run("Error parsing template", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "https://example.com/callback",
			State:       "test_state",
		}

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `{{.InvalidTemplate`,
			},
		}

		err := issueAuthCode(w, r, templateFS, code, "form_post")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to parse template")
	})

	// Gate 4, the last resort (#122). This function emits the stored redirect URI three different
	// ways and the guard sits above the dispatch, so every mode gets a row: a guard written inside
	// one branch would pass a table that exercised only that branch.
	//
	// These are not validation cases. Nothing here matches the value against anything, because this
	// function is downstream of every gate that does; what the table states is the property that
	// there is no way to reach an emission without having passed one, which is what a later refactor
	// moving or bypassing a gate breaks.
	t.Run("A redirect URI that is not an absolute URI is refused in every response mode", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			redirectURI string
			why         string
		}{
			{
				name:        "scheme-relative",
				redirectURI: "//evil.example/cb",
				why:         "emitted verbatim it is a protocol-relative Location, which the user agent resolves against the current scheme and delivers the code to evil.example",
			},
			{
				name:        "https with no authority",
				redirectURI: "https:///evil.example/cb",
				why:         "decision 8's family: Go parses no host, a browser reads evil.example, and the value is still a valid absolute-URI",
			},
			{
				name:        "http with a single slash",
				redirectURI: "http:/evil.example/cb",
				why:         "the same family through hier-part's path-absolute production",
			},
			{
				name:        "relative",
				redirectURI: "/relative/cb",
				why:         "the code arrives back at this authorization server rather than at any client",
			},
			{
				name:        "carrying a fragment",
				redirectURI: "https://legit.example/cb#frag",
				why:         "the host is legitimate and the callback still breaks: the code arrives at /cb%23frag rather than at /cb",
			},
		} {
			for _, mode := range []struct{ name, value string }{
				{"query", "query"},
				{"fragment", "fragment"},
				{"form_post", "form_post"},
				{"unset, which defaults to query", ""},
			} {
				t.Run(tc.name+", response_mode "+mode.name, func(t *testing.T) {
					w := httptest.NewRecorder()
					r := httptest.NewRequest("GET", "/auth/issue", nil)
					code := &models.Code{
						Code:        "test_code",
						RedirectURI: tc.redirectURI,
						State:       "test_state",
					}

					// A form_post template that renders cleanly, so that a build with the guard
					// removed produces a form action to assert against rather than dying on a
					// missing template and passing for the wrong reason.
					templateFS := &mocks_test.TestFS{
						FileContents: map[string]string{
							"form_post.html": `<form method="post" action="{{.redirectURI}}"></form>`,
						},
					}

					err := issueAuthCode(w, r, templateFS, code, mode.value)

					assert.Error(t, err, tc.why)
					assert.Empty(t, w.Header().Get("Location"), "no Location may be written for %q", tc.redirectURI)
					assert.Empty(t, w.Body.String(), "no form action may be written for %q", tc.redirectURI)
				})
			}
		}
	})

	// RFC 6749 section 3.1.2: "The endpoint URI MAY include an "application/x-www-form-urlencoded"
	// formatted query component, which MUST be retained when adding additional query parameters."
	//
	// Every other case in this test uses a query-less redirect URI, so nothing watched the retention
	// path, and the query mode is the only one that rewrites the URI rather than appending to it: it
	// parses, reads Query(), adds code and state, and re-encodes. A change to that sequence which
	// dropped or reordered the registered query would break a real client and no test would notice.
	// Encode sorts by key, which is why the expectation below is written out in full rather than
	// assembled (#122).
	t.Run("A registered query survives the addition of code and state", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/auth/issue", nil)
		code := &models.Code{
			Code:        "test_code",
			RedirectURI: "http://127.0.0.1/cb?a=1",
			State:       "test_state",
		}

		err := issueAuthCode(w, r, nil, code, "query")

		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "http://127.0.0.1/cb?a=1&code=test_code&state=test_state", w.Header().Get("Location"))
	})
}

func TestHandleIssueGet_IdTokenHintSubMatching(t *testing.T) {
	// Test cases for id_token_hint sub enforcement at issuance time (the critical safety net)

	t.Run("IdTokenHintSub set matching user - issues code successfully", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		// A live session, since this subtest reaches code creation (#129 stage 6).
		req := requestWithSessionIdentifier(t, liveSessionIdentifier)

		rr := httptest.NewRecorder()

		// Create authContext with IdTokenHintSub matching the user's subject
		userSubject := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         1,
			ResponseMode:   "query",
			ResponseType:   "code",
			RedirectURI:    "https://example.com/callback",
			State:          "test-state",
			IdTokenHintSub: userSubject.String(),
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		// Mock user lookup - subject matches IdTokenHintSub
		mockUser := &models.User{
			Id:      1,
			Subject: userSubject,
			Email:   "test@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(mockUser, nil)

		stubLiveSession(database, 1)

		// Mock code creation
		mockCode := &models.Code{
			Id:          1,
			Code:        "test-code",
			ClientId:    1,
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
		}
		codeIssuer.On("CreateAuthCode", mock.MatchedBy(func(input *oauth.CreateCodeInput) bool {
			return reflect.DeepEqual(input.AuthContext, *authContext)
		})).Return(mockCode, nil)

		database.On("RevokeCodeIfSessionGone", (*sql.Tx)(nil), int64(1), liveSessionIdentifier).Return(false, nil)

		// Mock audit logging
		auditLogger.On("Log", constants.AuditCreatedAuthCode, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(1) && details["clientId"] == int64(1) && details["codeId"] == int64(1)
		})).Return()

		// Mock clearing auth context
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		// Execute the handler
		handler.ServeHTTP(rr, req)

		// Assertions - code should be issued successfully
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "https://example.com/callback?code=test-code&state=test-state", rr.Header().Get("Location"))

		// Verify all expectations
		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("IdTokenHintSub set different user - returns login_required", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		// Create authContext with IdTokenHintSub for user A
		userASubject := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		userBSubject := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         1,
			ResponseMode:   "query",
			ResponseType:   "code",
			RedirectURI:    "https://example.com/callback",
			State:          "test-state",
			IdTokenHintSub: userASubject.String(), // Hint says user A
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		// Mock user lookup - authenticated user is user B (DIFFERENT)
		mockUser := &models.User{
			Id:      1,
			Subject: userBSubject,
			Email:   "userb@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(1)).Return(mockUser, nil)

		// The clear has to reach the browser, so it must run before the response is committed.
		// This refusal is the one that leaves the context in ready_to_issue_code, so a browser
		// keeping it can replay this endpoint. The stub writes a sentinel where the CookieStore
		// would write its cookie: rr.Header() is the live map the handler and the stub share and
		// shows it under either ordering, while rr.Result() reads the snapshot taken when the
		// status line was written.
		const clearedContextCookie = "cleared-auth-context"
		authHelper.On("ClearAuthContext", rr, req).Run(func(args mock.Arguments) {
			args.Get(0).(http.ResponseWriter).Header().Set("Set-Cookie", clearedContextCookie)
		}).Return(nil)

		// Execute the handler
		handler.ServeHTTP(rr, req)

		// Assertions - should redirect to client with login_required error
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback")
		assert.Contains(t, location, "error=login_required")
		assert.Contains(t, location, "error_description=")
		assert.Contains(t, location, "state=test-state")

		assert.Equal(t, clearedContextCookie, rr.Result().Header.Get("Set-Cookie"),
			"the auth context must be cleared before the client response is committed, or the browser keeps a ready_to_issue_code context to replay")

		// Verify CreateAuthCode was NEVER called
		codeIssuer.AssertNotCalled(t, "CreateAuthCode")

		// Verify all other expectations
		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("IdTokenHintSub set different user, failing clear - server_error to the client", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		userASubject := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		userBSubject := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         1,
			ResponseMode:   "query",
			ResponseType:   "code",
			RedirectURI:    "https://example.com/callback",
			State:          "test-state",
			IdTokenHintSub: userASubject.String(),
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		database.On("GetUserById", mock.Anything, int64(1)).Return(&models.User{
			Id:      1,
			Subject: userBSubject,
			Email:   "userb@example.com",
			Enabled: true,
		}, nil)

		// A failed clear writes no cookie, so the browser keeps the auth context whatever the
		// handler does next. The client is still owed its error response, and server_error is
		// the code RFC 6749 4.1.2.1 mints for a fault that cannot travel as a 500.
		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		handler.ServeHTTP(rr, req)

		// httpHelper has no InternalServerError expectation, so the mock fails the test if the
		// handler answers with a bare 500 instead of redirecting the client.
		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Result().Header.Get("Location")
		assert.Contains(t, location, "https://example.com/callback")
		assert.Contains(t, location, "error=server_error")
		assert.Contains(t, location, "error_description=Internal+server+error")
		assert.NotContains(t, location, "login_required")
		assert.NotContains(t, location, "code=")

		codeIssuer.AssertNotCalled(t, "CreateAuthCode")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("IdTokenHintSub set different user, failing clear and an unusable form_post template - last-resort 500", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		// Deliberately malformed, an unclosed action, so template.ParseFS fails and
		// redirToClientWithError returns "unable to parse template" instead of committing.
		// form_post is the only response mode whose arm can fail after the redirect URI has
		// been validated, so it is how this branch is reached at all.
		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		userASubject := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		userBSubject := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         1,
			ResponseMode:   "form_post",
			ResponseType:   "code",
			RedirectURI:    "https://example.com/callback",
			State:          "test-state",
			IdTokenHintSub: userASubject.String(),
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		database.On("GetUserById", mock.Anything, int64(1)).Return(&models.User{
			Id:      1,
			Subject: userBSubject,
			Email:   "userb@example.com",
			Enabled: true,
		}, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(errors.New("the session store is unreachable"))

		// The clear failed and the server_error response the client is owed cannot be built
		// either, so there is nowhere left to send it and the 500 is the last resort. Without
		// this expectation the handler would answer nothing at all.
		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		// Nothing reached the client: the form_post arm fails before it writes, and the 500 is
		// the mock's, so no redirect is committed.
		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("IdTokenHintSub set different user, unusable form_post template - 500 when the refusal itself cannot be sent", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		templateFS := &mocks_test.TestFS{
			FileContents: map[string]string{
				"form_post.html": `<form action="{{ .redirectURI`,
			},
		}

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		userASubject := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		userBSubject := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         1,
			ResponseMode:   "form_post",
			ResponseType:   "code",
			RedirectURI:    "https://example.com/callback",
			State:          "test-state",
			IdTokenHintSub: userASubject.String(),
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)
		stubClientProvenanceLookup(database)

		database.On("GetUserById", mock.Anything, int64(1)).Return(&models.User{
			Id:      1,
			Subject: userBSubject,
			Email:   "userb@example.com",
			Enabled: true,
		}, nil)

		// The other half of the same family: here the clear succeeds and it is the ordinary
		// login_required refusal that cannot be committed. This is the site's second and
		// pre-existing 500, pinned separately so a future edit cannot delete either copy
		// unnoticed.
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "unable to parse template")
		})).Once()

		handler.ServeHTTP(rr, req)

		assert.Empty(t, rr.Result().Header.Get("Location"))

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("IdTokenHintSub empty - proceeds normally without check", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		// A live session, since this subtest reaches code creation (#129 stage 6).
		req := requestWithSessionIdentifier(t, liveSessionIdentifier)

		rr := httptest.NewRecorder()

		// Create authContext with empty IdTokenHintSub (no hint provided)
		authContext := &oauth.AuthContext{
			AuthState:      oauth.AuthStateReadyToIssueCode,
			ClientId:       "test-client",
			UserId:         1,
			ResponseMode:   "query",
			ResponseType:   "code",
			RedirectURI:    "https://example.com/callback",
			State:          "test-state",
			IdTokenHintSub: "", // Empty - no hint
		}
		authHelper.On("GetAuthContext", req).Return(authContext, nil)

		// Do NOT mock database.GetUserById - it should not be called when IdTokenHintSub is empty

		stubLiveSession(database, 1)

		// Mock code creation
		mockCode := &models.Code{
			Id:          1,
			Code:        "test-code",
			ClientId:    1,
			RedirectURI: "https://example.com/callback",
			State:       "test-state",
		}
		codeIssuer.On("CreateAuthCode", mock.MatchedBy(func(input *oauth.CreateCodeInput) bool {
			return reflect.DeepEqual(input.AuthContext, *authContext)
		})).Return(mockCode, nil)

		database.On("RevokeCodeIfSessionGone", (*sql.Tx)(nil), int64(1), liveSessionIdentifier).Return(false, nil)

		// Mock audit logging
		auditLogger.On("Log", constants.AuditCreatedAuthCode, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == int64(1) && details["clientId"] == int64(1) && details["codeId"] == int64(1)
		})).Return()

		// Mock clearing auth context
		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		// Execute the handler
		handler.ServeHTTP(rr, req)

		// Assertions - code should be issued successfully
		assert.Equal(t, http.StatusFound, rr.Code)
		assert.Equal(t, "https://example.com/callback?code=test-code&state=test-state", rr.Header().Get("Location"))

		// Verify GetUserById was NOT called (no need to check when no hint provided)
		database.AssertNotCalled(t, "GetUserById")

		// Verify all other expectations
		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		codeIssuer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("End-to-end: prompt=login with mismatched id_token_hint - blocks at issuance", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		authHelper := mocks_handlerhelpers.NewAuthHelper(t)
		templateFS := &mocks_test.TestFS{}
		codeIssuer := mocks_oauth.NewCodeIssuer(t)
		tokenIssuer := mocks_oauth.NewTokenIssuer(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleIssueGet(httpHelper, authHelper, templateFS, codeIssuer, tokenIssuer, database, auditLogger)

		req, err := http.NewRequest("GET", "/auth/issue", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		userASubject := uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		userBSubject := uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

		var savedAuthContext *oauth.AuthContext

		authHelper.On("GetAuthContext", req).Run(func(args mock.Arguments) {
			stubClientProvenanceLookup(database)
			savedAuthContext = &oauth.AuthContext{
				AuthState:      oauth.AuthStateReadyToIssueCode,
				ClientId:       "test-client",
				UserId:         99,
				ResponseMode:   "query",
				ResponseType:   "code",
				RedirectURI:    "https://example.com/callback",
				State:          "test-state",
				IdTokenHintSub: userASubject.String(),
				Prompt:         "login",
			}
		}).Return(func(r *http.Request) *oauth.AuthContext {
			return savedAuthContext
		}, nil)

		mockUserB := &models.User{
			Id:      99,
			Subject: userBSubject,
			Email:   "userb@example.com",
			Enabled: true,
		}
		database.On("GetUserById", mock.Anything, int64(99)).Return(mockUserB, nil)

		authHelper.On("ClearAuthContext", rr, req).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusFound, rr.Code)
		location := rr.Header().Get("Location")
		assert.Contains(t, location, "https://example.com/callback")
		assert.Contains(t, location, "error=login_required")
		assert.Contains(t, location, "error_description=")
		assert.Contains(t, location, "state=test-state")

		assert.NotNil(t, savedAuthContext, "AuthContext should have been created")
		assert.Equal(t, userASubject.String(), savedAuthContext.IdTokenHintSub, "IdTokenHintSub should persist from authorize request")
		assert.Equal(t, int64(99), savedAuthContext.UserId, "UserId should be set to authenticated user (user B)")

		codeIssuer.AssertNotCalled(t, "CreateAuthCode")

		httpHelper.AssertExpectations(t)
		authHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}
