package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
	mocks_oauth "github.com/leodip/goiabada/core/oauth/mocks"
	mocks_users "github.com/leodip/goiabada/core/user/mocks"
	mocks_validators "github.com/leodip/goiabada/core/validators/mocks"
)

// Seam 5 at the token endpoint, which routes on two of the four wire types and used to read only
// the outermost error value at every one of those decisions. Nothing in this tree wraps a
// validator's result today, which is why the bare assertions worked; that is an unwritten rule
// rather than a property anything checks, and these rows are what turn it into one. Each hands the
// handler exactly the error the validator returns, wrapped once, and asserts the decision is still
// taken (#279 decision 6). Each fails against the assertion form this stage replaced: a wrap sent
// all three to the generic arm, so the audit row was never written and the client got a 500 whose
// description is the generic server-error sentence.

// wrappedTokenRequest wires a token handler whose validator answers failure, and returns the parts
// a case needs to drive one authorization_code request through it.
func wrappedTokenRequest(t *testing.T, failure error) (
	*mocks_handlerhelpers.HttpHelper, *mocks_audit.AuditLogger, *mocks_data.Database,
	*httptest.ResponseRecorder, *http.Request, http.Handler,
) {
	t.Helper()

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	userSessionManager := mocks_users.NewUserSessionManager(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_oauth.NewTokenIssuer(t)
	tokenValidator := mocks_validators.NewTokenValidator(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	handler := HandleTokenPost(httpHelper, userSessionManager, database, tokenIssuer, tokenValidator,
		auditLogger, noCredentialFailures{})

	formData := "grant_type=authorization_code&code=abc&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	tokenValidator.On("ValidateTokenRequest", mock.Anything,
		mock.AnythingOfType("*validators.ValidateTokenRequestInput")).Return(nil, failure)

	return httpHelper, auditLogger, database, rr, req, handler
}

// expectJsonErrorWithDetail registers the one JsonError call and captures what it was handed.
func expectJsonErrorWithDetail(httpHelper *mocks_handlerhelpers.HttpHelper) *error {
	var captured error
	httpHelper.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured, _ = args.Get(2).(error)
		}).Return().Once()
	return &captured
}

// A wrapped ErrUserDisabled still writes the audit row and still answers with the validator's own
// 400 and sentence, rather than the generic server error a lost match produces.
func TestHandleTokenPost_WrappedUserDisabledStillAudits(t *testing.T) {
	// Equal by value to the sentinel rather than the sentinel itself, which is how the token
	// validator returns it: ErrorDetail.Is is what makes errors.Is match this copy.
	disabled := customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
		"The user account is disabled.", http.StatusBadRequest)
	require.ErrorIs(t, disabled, customerrors.ErrUserDisabled)

	httpHelper, auditLogger, _, rr, req, handler := wrappedTokenRequest(t,
		errs.Wrap(disabled, "unable to validate the token request"))

	auditLogger.On("Log", mock.Anything, constants.AuditUserDisabled, mock.Anything).Return().Once()
	captured := expectJsonErrorWithDetail(httpHelper)

	handler.ServeHTTP(rr, req)

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
	assert.Equal(t, "The user account is disabled.", detail.GetDescription())
	httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
}

// The same for the deregistered-redirect-URI sentinel, the other by-value comparison this handler
// makes. Its audit row is the only record that a redemption was refused for that reason, so losing
// the match makes the refusal indistinguishable from any other server fault in the log.
func TestHandleTokenPost_WrappedDeregisteredRedirectUriStillAudits(t *testing.T) {
	refusal := customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant",
		"The redirect URI recorded on this authorization code is no longer registered on the client, so the code can no longer be redeemed.",
		http.StatusBadRequest)
	require.ErrorIs(t, refusal, customerrors.ErrCodeRedirectURIDeregistered)

	httpHelper, auditLogger, _, rr, req, handler := wrappedTokenRequest(t,
		errs.Wrap(refusal, "unable to validate the token request"))

	auditLogger.On("Log", mock.Anything, constants.AuditRedemptionRefusedRedirectURI, mock.Anything).Return().Once()
	captured := expectJsonErrorWithDetail(httpHelper)

	handler.ServeHTTP(rr, req)

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, http.StatusBadRequest, detail.GetHttpStatusCode())
	httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
}

// A wrapped *AuthCodeReusedError still reaches the revocation branch, which is asserted from the far
// side of it: the transaction the generic arm never opens, and the reuse audit row RFC 6749 4.1.2's
// SHOULD is discharged by. The wrapper is seen through by errors.As because AuthCodeReusedError now
// unwraps to its Detail as well.
func TestHandleTokenPost_WrappedAuthCodeReuseStillRevokes(t *testing.T) {
	reuse := &customerrors.AuthCodeReusedError{
		Detail: customerrors.NewErrorDetailWithHttpStatusCode("invalid_grant", "Code is invalid.",
			http.StatusBadRequest),
		Code: &models.Code{Id: 7, ClientId: 3, UserId: 11, SessionIdentifier: "sid-reused"},
	}

	httpHelper, auditLogger, database, rr, req, handler := wrappedTokenRequest(t,
		errs.Wrap(reuse, "unable to validate the token request"))

	expectRunInTransaction(database, (*sql.Tx)(nil))
	database.EXPECT().AcquireUserSessionRow(mock.Anything, "sid-reused").Return(true, nil).Once()
	database.EXPECT().GetRefreshTokensBySessionIdentifier(mock.Anything, "sid-reused").
		Return(nil, nil).Once()

	var auditedCodeId int64
	auditLogger.On("Log", mock.Anything, constants.AuditAuthCodeReuseDetected, mock.Anything).
		Run(func(args mock.Arguments) {
			details, _ := args.Get(2).(map[string]interface{})
			auditedCodeId, _ = details["codeId"].(int64)
		}).Return().Once()
	captured := expectJsonErrorWithDetail(httpHelper)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, int64(7), auditedCodeId, "the reuse row must name the replayed code")
	// Equal rather than the same pointer: jsonErrorConformed rebuilds the detail through
	// WithDescription so the sentence is conformed before it reaches the wire (#213).
	answered, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, http.StatusBadRequest, answered.GetHttpStatusCode())
	assert.Equal(t, "invalid_grant", answered.GetCode())
	assert.Equal(t, "Code is invalid.", answered.GetDescription())
	database.AssertExpectations(t)
	httpHelper.AssertNotCalled(t, "InternalServerError", mock.Anything, mock.Anything, mock.Anything)
}

// jsonErrorConformed is the third 500 writer and the only one outside core, so decision 9's line is
// owed here too: an operator filtering on request_id has to be able to join a client's report to it,
// and the stack has to ride on the error attribute rather than be glued into the message.
func TestJsonErrorConformed_LogsStructuredOnTheGenericBranch(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	req := httptest.NewRequest("POST", "/token", nil)
	// The id goes on the context, where chi's RequestID middleware puts it in the running
	// server, because that is the only place the writer can read it from now: the call site
	// stopped naming request_id and the installed handler injects it (#320 decision 2).
	req = req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, "req-token-500"))
	rr := httptest.NewRecorder()
	captured := expectJsonErrorWithDetail(httpHelper)

	jsonErrorConformed(httpHelper, rr, req, errs.New("the key store is unreachable"))

	var errorRecords []testutil.CapturedRecord
	for _, record := range logs.Records() {
		if record.Level == slog.LevelError {
			errorRecords = append(errorRecords, record)
		}
	}
	require.Len(t, errorRecords, 1, "the generic branch logs exactly once")
	assert.Equal(t, "internal server error", errorRecords[0].Message)

	attrs := errorRecords[0].Attrs
	logged, ok := attrs["error"].(error)
	require.True(t, ok, "the error travels as an error value, not as text: got %T", attrs["error"])
	assert.Contains(t, logged.Error(), "the key store is unreachable")
	assert.Equal(t, "req-token-500", attrs["request_id"],
		"injected by the handler from the request's context, with no call site naming it")

	detail, ok := (*captured).(*customerrors.ErrorDetail)
	require.True(t, ok, "expected an *customerrors.ErrorDetail, got %T", *captured)
	assert.Equal(t, http.StatusInternalServerError, detail.GetHttpStatusCode())
	assert.Equal(t, "server_error", detail.GetCode())
}
