package apihandlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The gender a profile PUT accepts and the value it stores (#443 decision 13). GET returns the
// word, so a PUT takes the word as well as the digit the admin console's forms post, and stores
// the word either way; anything else is refused as it always was. The stored words are literals,
// the strings the OIDC gender claim carries.

// genderAccepted is each spelling a profile PUT takes, and the value it stores for it.
var genderAccepted = []struct {
	sent   string
	stored string
}{
	{"0", "female"},
	{"1", "male"},
	{"2", "other"},
	{"female", "female"},
	{"male", "male"},
	{"other", "other"},
	{"", ""},
}

// genderRefused is a spelling no gender has: a capital, a digit past the range, a stray letter.
var genderRefused = []string{"Male", "3", "x"}

const profileTestUserId = int64(42)

func adminProfilePutRequest(t *testing.T, gender string) *http.Request {
	t.Helper()
	body, err := json.Marshal(api.UpdateUserProfileRequest{GivenName: "Ada", FamilyName: "Lovelace", Gender: gender})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/profile", bytes.NewReader(body))
	req = setChiURLParam(req, "id", "42")
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": adminSubject})
}

// requireGenderRefused asserts the 400 and the error code a gender no profile can carry has
// always been answered with.
func requireGenderRefused(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, i18n.ErrCodeProfileGenderInvalid, body["error_code"])
	assert.Equal(t, "Gender is invalid.", body["error_description"])
}

func TestHandleUserProfilePut_StoresTheGenderWordForEitherSpelling(t *testing.T) {
	for _, tc := range genderAccepted {
		t.Run("sent "+tc.sent, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			// The row starts with a gender, so the empty row shows the PUT clearing it.
			database.On("GetUserById", mock.Anything, mock.Anything, profileTestUserId).
				Return(&record.User{Id: profileTestUserId, Subject: "sub-42", Gender: "other"}, nil).Once()
			var stored *record.User
			database.On("UpdateUser", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { stored = args.Get(2).(*record.User) }).
				Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserProfile, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleUserProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
				ServeHTTP(rr, adminProfilePutRequest(t, tc.sent))

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored)
			assert.Equal(t, tc.stored, stored.Gender)

			var body api.UpdateUserResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, tc.stored, body.User.Gender)
		})
	}
}

func TestHandleUserProfilePut_RefusesAnyOtherGender(t *testing.T) {
	for _, sent := range genderRefused {
		t.Run("sent "+sent, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			// No UpdateUser and no audit record are stubbed: the mocks fail the test on either.
			database.On("GetUserById", mock.Anything, mock.Anything, profileTestUserId).
				Return(&record.User{Id: profileTestUserId, Subject: "sub-42", Gender: "other"}, nil).Once()

			rr := httptest.NewRecorder()
			HandleUserProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
				ServeHTTP(rr, adminProfilePutRequest(t, sent))

			requireGenderRefused(t, rr)
		})
	}
}
