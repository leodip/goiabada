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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The self-service twin of handler_api_users_profile_test.go's gender cases, over the same tables.

const profileTestSubject = "sub-42"

func accountProfilePutRequest(t *testing.T, gender string) *http.Request {
	t.Helper()
	body, err := json.Marshal(api.UpdateUserProfileRequest{GivenName: "Ada", FamilyName: "Lovelace", Gender: gender})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/account/profile", bytes.NewReader(body))
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": profileTestSubject})
}

func TestHandleAccountProfilePut_StoresTheGenderWordForEitherSpelling(t *testing.T) {
	for _, tc := range genderAccepted {
		t.Run("sent "+tc.sent, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			// The row starts with a gender, so the empty row shows the PUT clearing it.
			database.On("GetUserBySubject", mock.Anything, mock.Anything, profileTestSubject).
				Return(&record.User{Id: profileTestUserId, Subject: profileTestSubject, Gender: "other"}, nil).Once()
			var stored *record.User
			database.On("SetUserProfile", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { stored = args.Get(2).(*record.User) }).
				Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedOwnProfile, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleAccountProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
				ServeHTTP(rr, accountProfilePutRequest(t, tc.sent))

			require.Equal(t, http.StatusOK, rr.Code)
			require.NotNil(t, stored)
			assert.Equal(t, tc.stored, stored.Gender)

			var body api.UpdateUserResponse
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, tc.stored, body.User.Gender)
		})
	}
}

func TestHandleAccountProfilePut_RefusesAnyOtherGender(t *testing.T) {
	for _, sent := range genderRefused {
		t.Run("sent "+sent, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			// No write and no audit record are stubbed: the mocks fail the test on either.
			database.On("GetUserBySubject", mock.Anything, mock.Anything, profileTestSubject).
				Return(&record.User{Id: profileTestUserId, Subject: profileTestSubject, Gender: "other"}, nil).Once()

			rr := httptest.NewRecorder()
			HandleAccountProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
				ServeHTTP(rr, accountProfilePutRequest(t, sent))

			requireGenderRefused(t, rr)
		})
	}
}
