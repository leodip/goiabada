package apihandlers

// The three API paths that set a password hold it to the nist policy with the words each has: the
// user they load, or the email in the request, and the app name from the request's settings (#550
// decisions 6 and 10). Each runs the real validator, so what is asserted is the error code the API
// answers and that nothing is written, never how the words were passed.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// nistSettings is an installation on the nist policy, its app name Goiabada.
func nistSettings(r *http.Request) *http.Request {
	return r.WithContext(reqctx.WithSettings(r.Context(),
		&record.Settings{AppName: "Goiabada", PasswordPolicy: record.PasswordPolicyNist}))
}

// requireRefusal asserts a 400 answering code as its error_code.
func requireRefusal(t *testing.T, rr *httptest.ResponseRecorder, code string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	var refusal api.ErrorResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &refusal))
	assert.Equal(t, code, refusal.ErrorCode)
}

type nistRefusal struct {
	name     string
	password string
	code     string
}

// nistRefusals are passwords of 15 characters or more the nist policy refuses for the account
// jane.doe@example.com, username janedoe, on the app Goiabada, each with the code it answers.
var nistRefusals = []nistRefusal{
	{"a listed password", "PasswordPassword", "validator.password.too_common"},
	{"the app name padded", "goiabada2026!!!!!", "validator.password.too_close_to_account"},
}

func TestHandleUserPasswordPut_HoldsThePasswordToNist(t *testing.T) {
	refusals := slices.Concat(nistRefusals, []nistRefusal{
		{"the user's username repeated", "JaneDoeJaneDoe2026", "validator.password.too_close_to_account"},
		{"the user's email address", "jane.doe@example.com", "validator.password.too_close_to_account"},
	})
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(42)).
				Return(&record.User{Id: 42, Email: "jane.doe@example.com", Username: "janedoe", Enabled: true}, nil).Once()

			body, err := json.Marshal(map[string]string{"newPassword": tc.password})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/password", bytes.NewReader(body))
			req.SetPathValue("id", "42")
			req = setTokenContextWithClaims(nistSettings(req),
				map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject, "auth_time": float64(1)})

			rr := httptest.NewRecorder()
			HandleUserPasswordPut(database, accountvalidation.NewPasswordValidator(), handlersmocks.NewAuditLogger(t)).ServeHTTP(rr, req)

			requireRefusal(t, rr, tc.code)
			database.AssertNotCalled(t, "SetUserPasswordHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestHandleUserCreatePost_HoldsThePasswordToNist(t *testing.T) {
	refusals := slices.Concat(nistRefusals, []nistRefusal{
		{"the email's local part padded", "jane.doe2026!!!!!!", "validator.password.too_close_to_account"},
		{"the email address", "Jane.Doe@Example.com", "validator.password.too_close_to_account"},
	})
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			userCreator := accounthandlersmocks.NewUserCreator(t)
			database.On("GetUserByEmail", mock.Anything, mock.Anything, "jane.doe@example.com").Return(nil, nil)

			body, err := json.Marshal(map[string]interface{}{
				"email":           "Jane.Doe@example.com",
				"setPasswordType": "now",
				"password":        tc.password,
			})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", bytes.NewReader(body))
			req = setTokenContextWithClaims(nistSettings(req), map[string]interface{}{"sub": adminSubject})

			rr := httptest.NewRecorder()
			HandleUserCreatePost(handlersmocks.NewPageRenderer(t), database, userCreator,
				accountvalidation.NewEmailValidator(database),
				accountvalidation.NewProfileValidator(database),
				accountvalidation.NewPasswordValidator(),
				handlersmocks.NewAuditLogger(t), accounthandlersmocks.NewEmailSender(t), testDataCipher, testBaseURL).
				ServeHTTP(rr, req)

			requireRefusal(t, rr, tc.code)
			userCreator.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
		})
	}
}

func TestHandleAccountPasswordPut_HoldsThePasswordToNist(t *testing.T) {
	const currentPassword = "violet tractor umbrella"
	currentHash, err := passwordhash.Hash(currentPassword)
	require.NoError(t, err)

	refusals := slices.Concat(nistRefusals, []nistRefusal{
		{"the caller's username repeated", "JaneDoeJaneDoe2026", "validator.password.too_close_to_account"},
		{"the caller's local part padded", "jane.doe2026!!!!!!", "validator.password.too_close_to_account"},
	})
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "the-subject").
				Return(&record.User{Id: 42, Email: "jane.doe@example.com", Username: "janedoe", Enabled: true, PasswordHash: currentHash}, nil).Once()

			body, err := json.Marshal(map[string]string{"currentPassword": currentPassword, "newPassword": tc.password})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPut, "/api/v1/account/password", bytes.NewReader(body))
			req = setTokenContextWithClaims(nistSettings(req), map[string]interface{}{"sub": "the-subject"})

			rr := httptest.NewRecorder()
			HandleAccountPasswordPut(database, accountvalidation.NewPasswordValidator(), handlersmocks.NewAuditLogger(t), unlimitedCredentials{}).
				ServeHTTP(rr, req)

			requireRefusal(t, rr, tc.code)
			database.AssertNotCalled(t, "SetUserPasswordHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
