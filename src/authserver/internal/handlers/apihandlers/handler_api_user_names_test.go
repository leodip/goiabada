package apihandlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// One spelling per name (#669 decisions 2 and 6). The admin API's user create, its profile update
// and the account's own profile update each trim a name, normalize it to NFC, check it and store
// it, so what is checked is exactly what is stored and answered. Each row is sent in all three name
// fields at once, so a field one path forgets fails its row. The stored spellings are literals,
// written composed by hand rather than computed.

// nameStored is a name as sent and the one spelling it is stored and answered in.
var nameStored = []struct {
	name   string
	sent   string
	stored string
}{
	{"a decomposed name is stored composed", "José", "José"},
	{"a hangul name typed in jamo is stored as its syllable", "가", "가"},
	// The two costs decision 2 names: NFC writes these two apart from how they were typed.
	{"a devanagari nukta letter is stored as its letter and nukta", "क़मल", "क़मल"},
	{"a cjk compatibility ideograph is stored as its unified one", "神", "神"},
	// NFC and not NFKC: fullwidth letters are what was typed, and NFKC would rewrite them.
	{"fullwidth letters are stored as typed", "Ｊｏｓｅ", "Ｊｏｓｅ"},
	// 60 code points decomposed, 30 composed: refused if the bound were checked before NFC.
	{"a decomposed name past 48 code points is checked as the 30 it is stored in",
		strings.Repeat("é", 30), strings.Repeat("é", 30)},
	{"48 letters with a space around them are stored as the 48",
		" " + strings.Repeat("a", 48) + " ", strings.Repeat("a", 48)},
}

// nameRefused is a name each path refuses with that field's code, and so never stores. A `<`
// followed by U+0338 composes to ≮ (U+226E), which the name rule refuses, so #275's refusal of
// `<` holds on the stored value as on the sent one.
var nameRefused = []struct {
	name string
	req  api.UpdateUserProfileRequest
	code string
}{
	{"a less-than with a combining long solidus in the given name",
		api.UpdateUserProfileRequest{GivenName: "Ann≮e"}, i18n.ErrCodeProfileGivenNameInvalid},
	{"a less-than with a combining long solidus in the middle name",
		api.UpdateUserProfileRequest{MiddleName: "Ann≮e"}, i18n.ErrCodeProfileMiddleNameInvalid},
	{"a less-than with a combining long solidus in the family name",
		api.UpdateUserProfileRequest{FamilyName: "Ann≮e"}, i18n.ErrCodeProfileFamilyNameInvalid},
}

func namesProfileRequest(t *testing.T, method, target string, req api.UpdateUserProfileRequest, claims map[string]interface{}) *http.Request {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	return setTokenContextWithClaims(r, claims)
}

func allThreeNames(name string) api.UpdateUserProfileRequest {
	return api.UpdateUserProfileRequest{GivenName: name, MiddleName: name, FamilyName: name}
}

// requireNamesStored asserts the record handed to the database and the answer both carry the
// stored spelling in all three fields.
func requireNamesStored(t *testing.T, rr *httptest.ResponseRecorder, wantStatus int, stored *record.User, want string) {
	t.Helper()
	require.Equal(t, wantStatus, rr.Code, rr.Body.String())
	require.NotNil(t, stored)
	assert.Equal(t, want, stored.GivenName)
	assert.Equal(t, want, stored.MiddleName)
	assert.Equal(t, want, stored.FamilyName)

	var body struct {
		User api.UserResponse `json:"user"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, want, body.User.GivenName)
	assert.Equal(t, want, body.User.MiddleName)
	assert.Equal(t, want, body.User.FamilyName)
}

func requireNameRefused(t *testing.T, rr *httptest.ResponseRecorder, code string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, code, body["error_code"])
}

var adminProfileClaims = map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject}

func adminNamesRequest(t *testing.T, req api.UpdateUserProfileRequest) *http.Request {
	t.Helper()
	r := namesProfileRequest(t, http.MethodPut, "/api/v1/admin/users/42/profile", req, adminProfileClaims)
	r.SetPathValue("id", "42")
	return r
}

func TestHandleUserProfilePut_StoresAndAnswersOneSpellingPerName(t *testing.T) {
	for _, tc := range nameStored {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			database.On("GetUserById", mock.Anything, mock.Anything, profileTestUserId).
				Return(&record.User{Id: profileTestUserId, Subject: "sub-42"}, nil).Once()
			var stored *record.User
			database.On("SetUserProfile", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { stored = args.Get(2).(*record.User) }).
				Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserProfile, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleUserProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
				ServeHTTP(rr, adminNamesRequest(t, allThreeNames(tc.sent)))

			requireNamesStored(t, rr, http.StatusOK, stored, tc.stored)
		})
	}
}

func TestHandleUserProfilePut_RefusesANameThatComposesToARefusedOne(t *testing.T) {
	for _, tc := range nameRefused {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			// No write and no audit record are stubbed: the mocks fail the test on either.
			database.On("GetUserById", mock.Anything, mock.Anything, profileTestUserId).
				Return(&record.User{Id: profileTestUserId, Subject: "sub-42"}, nil).Once()

			rr := httptest.NewRecorder()
			HandleUserProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
				ServeHTTP(rr, adminNamesRequest(t, tc.req))

			requireNameRefused(t, rr, tc.code)
		})
	}
}

func accountNamesRequest(t *testing.T, req api.UpdateUserProfileRequest) *http.Request {
	t.Helper()
	return namesProfileRequest(t, http.MethodPut, "/api/v1/account/profile", req,
		map[string]interface{}{"sub": profileTestSubject})
}

func TestHandleAccountProfilePut_StoresAndAnswersOneSpellingPerName(t *testing.T) {
	for _, tc := range nameStored {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			database.On("GetUserBySubject", mock.Anything, mock.Anything, profileTestSubject).
				Return(&record.User{Id: profileTestUserId, Subject: profileTestSubject}, nil).Once()
			var stored *record.User
			database.On("SetUserProfile", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) { stored = args.Get(2).(*record.User) }).
				Return(nil).Once()
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedOwnProfile, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleAccountProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
				ServeHTTP(rr, accountNamesRequest(t, allThreeNames(tc.sent)))

			requireNamesStored(t, rr, http.StatusOK, stored, tc.stored)
		})
	}
}

func TestHandleAccountProfilePut_RefusesANameThatComposesToARefusedOne(t *testing.T) {
	for _, tc := range nameRefused {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			// No write and no audit record are stubbed: the mocks fail the test on either.
			database.On("GetUserBySubject", mock.Anything, mock.Anything, profileTestSubject).
				Return(&record.User{Id: profileTestUserId, Subject: profileTestSubject}, nil).Once()

			rr := httptest.NewRecorder()
			HandleAccountProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
				ServeHTTP(rr, accountNamesRequest(t, tc.req))

			requireNameRefused(t, rr, tc.code)
		})
	}
}

// createNamesRequest is a create that sets its password now, carrying the names of req.
func createNamesRequest(t *testing.T, req api.UpdateUserProfileRequest) *http.Request {
	t.Helper()
	body, err := json.Marshal(api.CreateUserAdminRequest{
		Email:           "names@example.com",
		SetPasswordType: api.SetPasswordTypeNow,
		Password:        "a-long-enough-password-1",
		GivenName:       req.GivenName,
		MiddleName:      req.MiddleName,
		FamilyName:      req.FamilyName,
	})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r = setTokenContextWithClaims(r, map[string]interface{}{"sub": adminSubject})
	return r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{AppName: "TestApp"}))
}

func TestHandleUserCreatePost_StoresAndAnswersOneSpellingPerName(t *testing.T) {
	for _, tc := range nameStored {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			userCreator := accounthandlersmocks.NewUserCreator(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			database.On("GetUserByEmail", mock.Anything, mock.Anything, "names@example.com").Return(nil, nil).Once()
			// The created row is the input the handler hands over, as the real creator stores it.
			var stored *record.User
			userCreator.EXPECT().CreateUser(mock.Anything, mock.Anything).
				RunAndReturn(func(_ context.Context, input *usercreation.Input) (*record.User, error) {
					stored = &record.User{Id: 7, Email: input.Email, GivenName: input.GivenName,
						MiddleName: input.MiddleName, FamilyName: input.FamilyName}
					return stored, nil
				}).Once()
			auditLogger.On("Log", mock.Anything, audit.EventCreatedUser, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleUserCreatePost(handlersmocks.NewPageRenderer(t), database, userCreator,
				accountvalidation.NewEmailValidator(database),
				accountvalidation.NewProfileValidator(database),
				accountvalidation.NewPasswordValidator(),
				auditLogger, accounthandlersmocks.NewEmailSender(t), testDataCipher, testBaseURL).
				ServeHTTP(rr, createNamesRequest(t, allThreeNames(tc.sent)))

			requireNamesStored(t, rr, http.StatusCreated, stored, tc.stored)
		})
	}
}

func TestHandleUserCreatePost_RefusesANameThatComposesToARefusedOne(t *testing.T) {
	for _, tc := range nameRefused {
		t.Run(tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			// No create and no audit record are stubbed: the mocks fail the test on either.
			database.On("GetUserByEmail", mock.Anything, mock.Anything, "names@example.com").Return(nil, nil).Once()

			rr := httptest.NewRecorder()
			HandleUserCreatePost(handlersmocks.NewPageRenderer(t), database, accounthandlersmocks.NewUserCreator(t),
				accountvalidation.NewEmailValidator(database),
				accountvalidation.NewProfileValidator(database),
				accountvalidation.NewPasswordValidator(),
				handlersmocks.NewAuditLogger(t), accounthandlersmocks.NewEmailSender(t), testDataCipher, testBaseURL).
				ServeHTTP(rr, createNamesRequest(t, tc.req))

			requireNameRefused(t, rr, tc.code)
		})
	}
}
