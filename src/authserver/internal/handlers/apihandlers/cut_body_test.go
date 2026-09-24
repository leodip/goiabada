package apihandlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/validators"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A request body the request-body limit cut short reaches a handler as a failed read, and the API
// answers it the way it answers any body that will not decode: 400 INVALID_REQUEST_BODY in the flat
// error shape rest-api.mdx documents (#426 decision 6). The limit's own boundary through the real
// root chain is server/body_limit_test.go's; what is claimed here is the handler's answer.

// cutBody is body behind a limit of limit bytes, as the root's MiddlewareBodyLimit leaves it.
func cutBody(w http.ResponseWriter, body string, limit int) io.ReadCloser {
	return http.MaxBytesReader(w, io.NopCloser(strings.NewReader(body)), int64(limit))
}

func assertInvalidRequestBody(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var envelope api.ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	assert.Equal(t, "INVALID_REQUEST_BODY", envelope.ErrorCode)
	assert.Equal(t, "Invalid request body", envelope.ErrorDescription)
}

// The account phone PUT, one bearer-authenticated JSON handler standing for the 45 that decode a
// body the same way. The same body is read whole under a limit equal to its length and refused
// one byte short of it.
func TestCutBody_TheAccountPhonePut(t *testing.T) {
	const body = `{"phoneCountryUniqueId":"US_0","phoneNumber":"5551234567"}`

	serve := func(t *testing.T, limit int, database *mocks_data.Database) *httptest.ResponseRecorder {
		handler := HandleAPIAccountPhonePut(database, accountvalidation.NewPhoneValidator(), mocks_audit.NewAuditLogger(t))
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/account/phone", nil)
		req.Body = cutBody(rr, body, limit)
		handler.ServeHTTP(rr, setTokenContext(req, "a-subject"))
		return rr
	}

	t.Run("at exactly the limit the body is read and the user looked up", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.On("GetUserBySubject", mock.Anything, mock.Anything, "a-subject").Return(nil, nil).Once()

		rr := serve(t, len(body), database)

		assert.Equal(t, http.StatusNotFound, rr.Code, "past the decode, to the lookup the stub answers")
	})

	t.Run("one byte short it is refused before anything is looked up", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		rr := serve(t, len(body)-1, database)

		assertInvalidRequestBody(t, rr)
		database.AssertNotCalled(t, "GetUserBySubject", mock.Anything, mock.Anything, mock.Anything)
	})
}

// The four permission PUTs answered VALIDATION_ERROR to a body that would not decode, where every
// other decoder on this surface answers INVALID_REQUEST_BODY, the code rest-api.mdx gives a
// malformed body and the one api_error_code_lint_test.go reserves for it (#426).
func TestCutBody_ThePermissionPutsAnswerInvalidRequestBody(t *testing.T) {
	const body = `{"permissionIds":[1,2,3]}`

	tests := []struct {
		name    string
		param   string
		stub    func(database *mocks_data.Database)
		handler func(database *mocks_data.Database, t *testing.T) http.HandlerFunc
	}{
		{
			name:  "client permissions",
			param: "id",
			stub: func(database *mocks_data.Database) {
				database.On("GetClientById", mock.Anything, mock.Anything, int64(1)).Return(&models.Client{Id: 1}, nil).Once()
			},
			handler: func(database *mocks_data.Database, t *testing.T) http.HandlerFunc {
				return HandleAPIClientPermissionsPut(database, mocks_audit.NewAuditLogger(t))
			},
		},
		{
			name:  "group permissions",
			param: "id",
			stub: func(database *mocks_data.Database) {
				database.On("GetGroupById", mock.Anything, mock.Anything, int64(1)).Return(&models.Group{Id: 1}, nil).Once()
			},
			handler: func(database *mocks_data.Database, t *testing.T) http.HandlerFunc {
				return HandleAPIGroupPermissionsPut(database, mocks_audit.NewAuditLogger(t))
			},
		},
		{
			name:  "user permissions",
			param: "id",
			stub: func(database *mocks_data.Database) {
				database.On("GetUserById", mock.Anything, mock.Anything, int64(1)).Return(&models.User{Id: 1}, nil).Once()
			},
			handler: func(database *mocks_data.Database, t *testing.T) http.HandlerFunc {
				return HandleAPIUserPermissionsPut(database, mocks_audit.NewAuditLogger(t))
			},
		},
		{
			name:  "resource permissions",
			param: "resourceId",
			stub: func(database *mocks_data.Database) {
				database.On("GetResourceById", mock.Anything, mock.Anything, int64(1)).Return(&models.Resource{Id: 1}, nil).Once()
			},
			handler: func(database *mocks_data.Database, t *testing.T) http.HandlerFunc {
				return HandleAPIResourcePermissionsPut(database, validators.NewIdentifierValidator(), mocks_audit.NewAuditLogger(t))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			test.stub(database)

			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/", nil)
			req.Body = cutBody(rr, body, len(body)-1)
			routeContext := chi.NewRouteContext()
			routeContext.URLParams.Add(test.param, "1")
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))

			test.handler(database, t).ServeHTTP(rr, req)

			assertInvalidRequestBody(t, rr)
		})
	}
}
