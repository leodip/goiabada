package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the settings middleware, and thin for the reason section 5 gives: what the
// read does with a context belongs to the data tier.
//
// This is the first database call of almost every request the auth server serves -- the settings
// row the error page's own layout needs -- so it is the one read that a browser gone away leaves
// running on every path at once. chi's request id is on this request's context and on no other,
// so a middleware that passed context.Background() matches nothing and the strict mock reports an
// unexpected call.

const settingsPropagatedRequestId = "goiabada/req-settings-propagation-1"

func settingsRequestCarryingId() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	return req.WithContext(context.WithValue(req.Context(), chimiddleware.RequestIDKey, settingsPropagatedRequestId))
}

func theSettingsRequestsContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return chimiddleware.GetReqID(ctx) == settingsPropagatedRequestId
	})
}

// The accept arm: the settings read is issued on behalf of the request that triggered it.
func TestMiddlewareSettings_ReadsSettingsUnderTheRequestsContext(t *testing.T) {
	db := mocks_data.NewDatabase(t)
	db.On("GetSettingsById", theSettingsRequestsContext(), mock.Anything, int64(1)).
		Return(&models.Settings{Id: 1, AppName: "TestApp"}, nil).Once()

	reached := false
	handler := MiddlewareSettings(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, settingsRequestCarryingId())

	require.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, reached, "the next handler runs once the settings are on the context")
	db.AssertExpectations(t)
}
