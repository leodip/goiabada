package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlers "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/protocolvalidation"
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
	*mocks_handlers.JSONWriter, *mocks_handlers.AuditLogger, *mocks_data.Database,
	*httptest.ResponseRecorder, *http.Request, http.Handler,
) {
	t.Helper()

	jsonWriter := mocks_handlers.NewJSONWriter(t)
	database := mocks_data.NewDatabase(t)
	tokenIssuer := mocks_handlers.NewTokenIssuer(t)
	tokenValidator := mocks_handlers.NewTokenValidator(t)
	auditLogger := mocks_handlers.NewAuditLogger(t)

	handler := HandleTokenPost(jsonWriter, database, tokenIssuer, tokenValidator,
		auditLogger, noCredentialFailures{})

	formData := "grant_type=authorization_code&code=abc&redirect_uri=http://example.com&client_id=test_client"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
	req = withSettings(req, &models.Settings{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	tokenValidator.On("ValidateTokenRequest", mock.Anything, mock.Anything,
		mock.AnythingOfType("*protocolvalidation.ValidateTokenRequestInput")).Return(nil, failure)

	return jsonWriter, auditLogger, database, rr, req, handler
}

// expectJsonErrorWithDetail registers the one JsonError call and captures what it was handed.
func expectJsonErrorWithDetail(jsonWriter *mocks_handlers.JSONWriter) *error {
	var captured error
	jsonWriter.On("JsonError", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured, _ = args.Get(2).(error)
		}).Return().Once()
	return &captured
}

// A wrapped UserDisabledError still writes the audit row and still answers with the validator's own
// 400 and sentence, rather than the generic server error a lost match produces. One row per
// wording the validator gives it: the code and refresh grants' generic refusals, which name
// nothing about the account (#137), and the password grant's plain one.
func TestHandleTokenPost_WrappedUserDisabledStillAudits(t *testing.T) {
	for _, description := range []string{
		"Code is invalid.",
		"The refresh token is invalid.",
		"The user account is disabled.",
	} {
		t.Run(description, func(t *testing.T) {
			disabled := &protocolvalidation.UserDisabledError{Detail: oauth.NewErrorDetailWithHTTPStatus(
				"invalid_grant", description, http.StatusBadRequest)}

			jsonWriter, auditLogger, _, rr, req, handler := wrappedTokenRequest(t,
				errs.Wrap(disabled, "unable to validate the token request"))

			auditLogger.On("Log", mock.Anything, audit.EventUserDisabled, map[string]interface{}{
				"clientId": "test_client",
			}).Return().Once()
			captured := expectJsonErrorWithDetail(jsonWriter)

			handler.ServeHTTP(rr, req)

			// The handler hands the wrapped error through as it arrived; the writer reads the
			// detail out of it with errors.As, which is how it reaches the wire (#435).
			var detail *oauth.ErrorDetail
			require.ErrorAs(t, *captured, &detail)
			assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
			assert.Equal(t, description, detail.Description())
		})
	}
}

// The negative control: the same generic refusals, arriving as plain details as the validator
// returns them for a superseded generation, a revoked code or a missing row, write no
// user_disabled row. A match by value, which the handler made until #137, would write one for all
// of them. The audit logger has no expectation, so any row fails the case.
func TestHandleTokenPost_GenericRefusalWritesNoUserDisabledRow(t *testing.T) {
	for _, description := range []string{
		"Code is invalid.",
		"The refresh token is invalid.",
	} {
		t.Run(description, func(t *testing.T) {
			refusal := oauth.NewErrorDetailWithHTTPStatus("invalid_grant", description,
				http.StatusBadRequest)

			jsonWriter, auditLogger, _, rr, req, handler := wrappedTokenRequest(t, refusal)
			captured := expectJsonErrorWithDetail(jsonWriter)

			handler.ServeHTTP(rr, req)

			auditLogger.AssertNotCalled(t, "Log", mock.Anything, audit.EventUserDisabled, mock.Anything)
			assert.Same(t, refusal, *captured)
		})
	}
}

// The same for the deregistered-redirect-URI sentinel, the other by-value comparison this handler
// makes. Its audit row is the only record that a redemption was refused for that reason, so losing
// the match makes the refusal indistinguishable from any other server fault in the log.
func TestHandleTokenPost_WrappedDeregisteredRedirectUriStillAudits(t *testing.T) {
	refusal := oauth.NewErrorDetailWithHTTPStatus("invalid_grant",
		"The redirect URI recorded on this authorization code is no longer registered on the client, so the code can no longer be redeemed.",
		http.StatusBadRequest)
	require.ErrorIs(t, refusal, protocolvalidation.ErrCodeRedirectURIDeregistered)

	jsonWriter, auditLogger, _, rr, req, handler := wrappedTokenRequest(t,
		errs.Wrap(refusal, "unable to validate the token request"))

	auditLogger.On("Log", mock.Anything, audit.EventRedemptionRefusedRedirectURI, mock.Anything).Return().Once()
	captured := expectJsonErrorWithDetail(jsonWriter)

	handler.ServeHTTP(rr, req)

	var detail *oauth.ErrorDetail
	require.ErrorAs(t, *captured, &detail)
	assert.Equal(t, http.StatusBadRequest, detail.HTTPStatus())
}

// A wrapped *AuthCodeReusedError still reaches the revocation branch, which is asserted from the far
// side of it: the transaction the generic arm never opens, and the reuse audit row RFC 6749 4.1.2's
// SHOULD is discharged by. The wrapper is seen through by errors.As because AuthCodeReusedError now
// unwraps to its Detail as well.
func TestHandleTokenPost_WrappedAuthCodeReuseStillRevokes(t *testing.T) {
	reuse := &protocolvalidation.AuthCodeReusedError{
		Detail: oauth.NewErrorDetailWithHTTPStatus("invalid_grant", "Code is invalid.",
			http.StatusBadRequest),
		Code: &models.Code{Id: 7, ClientId: 3, UserId: 11, SessionIdentifier: "sid-reused"},
	}

	jsonWriter, auditLogger, database, rr, req, handler := wrappedTokenRequest(t,
		errs.Wrap(reuse, "unable to validate the token request"))

	mocks_data.ExpectRunInTransaction(database, revokeTx)
	database.EXPECT().AcquireUserSessionRow(mock.Anything, revokeTx, "sid-reused").Return(true, nil).Once()
	database.EXPECT().GetRefreshTokensBySessionIdentifier(mock.Anything, revokeTx, "sid-reused").
		Return(nil, nil).Once()

	var auditedCodeId int64
	auditLogger.On("Log", mock.Anything, audit.EventAuthCodeReuseDetected, mock.Anything).
		Run(func(args mock.Arguments) {
			details, _ := args.Get(2).(map[string]interface{})
			auditedCodeId, _ = details["codeId"].(int64)
		}).Return().Once()
	captured := expectJsonErrorWithDetail(jsonWriter)

	handler.ServeHTTP(rr, req)

	assert.Equal(t, int64(7), auditedCodeId, "the reuse row must name the replayed code")
	// The same pointer: the handler hands the validator's own detail through unrebuilt, and the
	// writer conforms the sentence on its way to the wire (#213, #435).
	answered, ok := (*captured).(*oauth.ErrorDetail)
	require.True(t, ok, "expected an *oauth.ErrorDetail, got %T", *captured)
	assert.Same(t, reuse.Detail, answered)
	assert.Equal(t, http.StatusBadRequest, answered.HTTPStatus())
	assert.Equal(t, "invalid_grant", answered.Code())
	assert.Equal(t, "Code is invalid.", answered.Description())
	database.AssertExpectations(t)
}
