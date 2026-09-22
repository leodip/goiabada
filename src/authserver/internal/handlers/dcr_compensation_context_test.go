package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	"github.com/leodip/goiabada/authserver/internal/constants"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/authserver/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The third member of the family #386's final review round 1 finding 9 opened, found by sweeping
// the production writes that follow a durable outcome rather than by being handed this one.
//
// Dynamic client registration commits the client row and then writes its redirect URIs, and there
// is no transaction across the two: the redirect URI write failing leaves a registered client the
// requester never learned the identifier of, so the handler compensates by deleting it. Before
// this, that compensation ran on the request's context -- and a cancelled request is one of the
// things that makes the redirect URI write fail in the first place, so the compensation was least
// likely to run in exactly the case it was written for.
//
// What survives is a client row with a secret and no redirect URI, which no ceremony can complete
// against and which nothing ever cleans up. That it is inert is not the point: it is durable
// state the server created and then failed to withdraw, and the withdrawal is not the request's
// to cancel.

// aLiveHandlerContext matches only a context that is not done, so a compensation issued on the
// cancelled request's context matches nothing and the strict mock reports it.
func aLiveHandlerContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool { return ctx.Err() == nil })
}

func dcrRequest(t *testing.T) (*http.Request, context.CancelFunc) {
	t.Helper()
	body := `{"redirect_uris":["https://example.com/callback"],"client_name":"probe"}`
	req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(context.WithValue(req.Context(),
		constants.ContextKeySettings, &models.Settings{DynamicClientRegistrationEnabled: true}))
	return req.WithContext(ctx), cancel
}

func TestHandleDynamicClientRegistrationPost_TheRollbackDeleteSurvivesACancelledRequest(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	req, cancel := dcrRequest(t)
	rr := httptest.NewRecorder()

	database.On("CreateClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	// The cancellation lands where a real one would: the client is committed, and the write that
	// was to follow it is the one the vanished caller breaks.
	database.On("CreateRedirectURI", mock.Anything, mock.Anything, mock.Anything).
		Run(func(mock.Arguments) { cancel() }).
		Return(errs.New("the client went away")).Once()
	database.On("DeleteClient", aLiveHandlerContext(), mock.Anything, mock.Anything).Return(nil).Once()

	HandleDynamicClientRegistrationPost(httpHelper, database, auditLogger).ServeHTTP(rr, req)

	require.Error(t, req.Context().Err(), "the request really was cancelled before the compensation ran")
	assert.Equal(t, http.StatusInternalServerError, rr.Code, "the caller is still told the registration failed")
	database.AssertExpectations(t)
	auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
}

// The control: with nothing cancelled the compensation is unchanged, so the case above is
// attributable to the cancellation and not to the rollback merely being reached.
func TestHandleDynamicClientRegistrationPost_TheRollbackDeleteRunsOnAnUncancelledRequestToo(t *testing.T) {
	httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
	database := mocks_data.NewDatabase(t)
	auditLogger := mocks_audit.NewAuditLogger(t)

	req, cancel := dcrRequest(t)
	defer cancel()
	rr := httptest.NewRecorder()

	database.On("CreateClient", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	database.On("CreateRedirectURI", mock.Anything, mock.Anything, mock.Anything).
		Return(errs.New("the unique index refused it")).Once()
	database.On("DeleteClient", aLiveHandlerContext(), mock.Anything, mock.Anything).Return(nil).Once()

	HandleDynamicClientRegistrationPost(httpHelper, database, auditLogger).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	database.AssertExpectations(t)
}
