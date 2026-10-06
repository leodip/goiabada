package apihandlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

// The profile, address and phone saves, self-service and administrator alike, store through the
// narrow write of their column group and never through UpdateUser, which wrote back the row the
// request read at its start and so undid a disable, a password change or an OTP change made while
// it was in flight (#471). What each write leaves untouched is the data tier's to show
// (tests/data/user_column_group_writes_test.go); here, each route hands its write the columns the
// request asked for, and answers with them as it always has.

const (
	columnGroupUserId  = int64(61)
	columnGroupSubject = "sub-61"
)

// columnGroupStoredUser is the row as each request reads it: every group holding a value the
// requests below replace, and the columns no save may write set to something to undo.
func columnGroupStoredUser() *record.User {
	return &record.User{
		Id:                            columnGroupUserId,
		Subject:                       columnGroupSubject,
		Enabled:                       true,
		PasswordHash:                  "the-hash-as-read",
		OTPEnabled:                    true,
		Username:                      "before",
		GivenName:                     "Before",
		FamilyName:                    "Before",
		Gender:                        "other",
		BirthDate:                     sql.NullTime{Time: time.Date(1990, time.January, 2, 0, 0, 0, 0, time.UTC), Valid: true},
		ZoneInfoCountryName:           "Brazil",
		ZoneInfo:                      "America/Sao_Paulo",
		Locale:                        "pt-BR",
		AddressLine1:                  "1 Before Road",
		AddressCountry:                "BR",
		PhoneNumberCountryUniqueId:    "BRA_0",
		PhoneNumberCountryCallingCode: "+55",
		PhoneNumber:                   "11 98765 4321",
		PhoneNumberVerified:           true,
	}
}

func columnGroupSelfServiceRequest(t *testing.T, path string, body any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(encoded))
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": columnGroupSubject})
}

func columnGroupAdminRequest(t *testing.T, path string, body any) *http.Request {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(encoded))
	req = setChiURLParam(req, "id", "61")
	return setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject})
}

// expectNarrowSave stubs the one write the route may make and returns where it records the user
// it was handed.
func expectNarrowSave(database *datamocks.Database, method string) **record.User {
	var saved *record.User
	database.On(method, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { saved = args.Get(2).(*record.User) }).
		Return(nil).Once()
	return &saved
}

func requireSavedNarrowly(t *testing.T, database *datamocks.Database, rr *httptest.ResponseRecorder, saved *record.User) api.UserResponse {
	t.Helper()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	database.AssertNotCalled(t, "UpdateUser", mock.Anything, mock.Anything, mock.Anything)
	require.NotNil(t, saved, "the narrow write was not reached")
	assert.Equal(t, columnGroupUserId, saved.Id)
	var body api.UpdateUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	return body.User
}

var columnGroupProfileRequest = api.UpdateUserProfileRequest{
	Username:            "ada_lovelace",
	GivenName:           "Ada",
	MiddleName:          "King",
	FamilyName:          "Lovelace",
	Nickname:            "countess",
	Website:             "https://ada.example.com",
	Gender:              "female",
	DateOfBirth:         "1815-12-10",
	ZoneInfoCountryName: "Portugal",
	ZoneInfo:            "Europe/Lisbon",
	Locale:              "pt-PT",
}

func assertProfileSaved(t *testing.T, saved *record.User, resp api.UserResponse) {
	t.Helper()
	assert.Equal(t, "ada_lovelace", saved.Username)
	assert.Equal(t, "Ada", saved.GivenName)
	assert.Equal(t, "King", saved.MiddleName)
	assert.Equal(t, "Lovelace", saved.FamilyName)
	assert.Equal(t, "countess", saved.Nickname)
	assert.Equal(t, "https://ada.example.com", saved.Website)
	assert.Equal(t, "female", saved.Gender)
	assert.Equal(t, sql.NullTime{Time: time.Date(1815, time.December, 10, 0, 0, 0, 0, time.UTC), Valid: true}, saved.BirthDate)
	assert.Equal(t, "Portugal", saved.ZoneInfoCountryName)
	assert.Equal(t, "Europe/Lisbon", saved.ZoneInfo)
	assert.Equal(t, "pt-PT", saved.Locale)

	assert.Equal(t, "ada_lovelace", resp.Username)
	assert.Equal(t, "Lovelace", resp.FamilyName)
	assert.Equal(t, "Europe/Lisbon", resp.ZoneInfo)
}

func expectProfileValidatorReads(database *datamocks.Database, stored *record.User) {
	database.On("GetUserBySubject", mock.Anything, mock.Anything, columnGroupSubject).Return(stored, nil)
	database.On("GetUserByUsername", mock.Anything, mock.Anything, "ada_lovelace").Return(nil, nil).Once()
}

func TestHandleAccountProfilePut_SavesTheProfileColumnsNarrowly(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	expectProfileValidatorReads(database, columnGroupStoredUser())
	saved := expectNarrowSave(database, "SetUserProfile")
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedOwnProfile, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleAccountProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
		ServeHTTP(rr, columnGroupSelfServiceRequest(t, "/api/v1/account/profile", columnGroupProfileRequest))

	resp := requireSavedNarrowly(t, database, rr, *saved)
	assertProfileSaved(t, *saved, resp)
}

func TestHandleUserProfilePut_SavesTheProfileColumnsNarrowly(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	database.On("GetUserById", mock.Anything, mock.Anything, columnGroupUserId).Return(columnGroupStoredUser(), nil).Once()
	expectProfileValidatorReads(database, columnGroupStoredUser())
	saved := expectNarrowSave(database, "SetUserProfile")
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserProfile, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleUserProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger).
		ServeHTTP(rr, columnGroupAdminRequest(t, "/api/v1/admin/users/61/profile", columnGroupProfileRequest))

	resp := requireSavedNarrowly(t, database, rr, *saved)
	assertProfileSaved(t, *saved, resp)
}

var columnGroupAddressRequest = api.UpdateUserAddressRequest{
	AddressLine1:      "10 Rua Augusta",
	AddressLine2:      "3 Esq",
	AddressLocality:   "Lisboa",
	AddressRegion:     "Lisboa",
	AddressPostalCode: "1100-053",
	AddressCountry:    "PT",
}

func assertAddressSaved(t *testing.T, saved *record.User, resp api.UserResponse) {
	t.Helper()
	assert.Equal(t, "10 Rua Augusta", saved.AddressLine1)
	assert.Equal(t, "3 Esq", saved.AddressLine2)
	assert.Equal(t, "Lisboa", saved.AddressLocality)
	assert.Equal(t, "Lisboa", saved.AddressRegion)
	assert.Equal(t, "1100-053", saved.AddressPostalCode)
	assert.Equal(t, "PT", saved.AddressCountry)

	assert.Equal(t, "10 Rua Augusta", resp.AddressLine1)
	assert.Equal(t, "PT", resp.AddressCountry)
}

func TestHandleAccountAddressPut_SavesTheAddressColumnsNarrowly(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	database.On("GetUserBySubject", mock.Anything, mock.Anything, columnGroupSubject).Return(columnGroupStoredUser(), nil).Once()
	saved := expectNarrowSave(database, "SetUserAddress")
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedOwnAddress, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleAccountAddressPut(database, accountvalidation.NewAddressValidator(), auditLogger).
		ServeHTTP(rr, columnGroupSelfServiceRequest(t, "/api/v1/account/address", columnGroupAddressRequest))

	resp := requireSavedNarrowly(t, database, rr, *saved)
	assertAddressSaved(t, *saved, resp)
}

func TestHandleUserAddressPut_SavesTheAddressColumnsNarrowly(t *testing.T) {
	database := datamocks.NewDatabase(t)
	auditLogger := handlersmocks.NewAuditLogger(t)

	database.On("GetUserById", mock.Anything, mock.Anything, columnGroupUserId).Return(columnGroupStoredUser(), nil).Once()
	saved := expectNarrowSave(database, "SetUserAddress")
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserAddress, mock.Anything).Return().Once()

	rr := httptest.NewRecorder()
	HandleUserAddressPut(database, accountvalidation.NewAddressValidator(), auditLogger).
		ServeHTTP(rr, columnGroupAdminRequest(t, "/api/v1/admin/users/61/address", columnGroupAddressRequest))

	resp := requireSavedNarrowly(t, database, rr, *saved)
	assertAddressSaved(t, *saved, resp)
}

// The self-service phone save always unverifies, whatever the row held; the administrator's keeps
// the flag the administrator sends, except on a cleared number. Both as today.
func TestPhonePuts_SaveThePhoneColumnsNarrowly(t *testing.T) {
	type phoneCase struct {
		name         string
		number       string
		countryId    string
		sendVerified bool
		wantCalling  string
		wantVerified bool
	}
	selfService := []phoneCase{
		{name: "a number, previously verified", number: "912 345 678", countryId: "PRT_0", wantCalling: "+351"},
		{name: "a cleared number", number: "", countryId: ""},
	}
	administrator := []phoneCase{
		{name: "a number sent verified", number: "912 345 678", countryId: "PRT_0", sendVerified: true, wantCalling: "+351", wantVerified: true},
		{name: "a number sent unverified", number: "912 345 678", countryId: "PRT_0", wantCalling: "+351"},
		{name: "a cleared number sent verified", number: "", countryId: "", sendVerified: true},
	}

	assertPhoneSaved := func(t *testing.T, tc phoneCase, saved *record.User, resp api.UserResponse) {
		t.Helper()
		assert.Equal(t, tc.countryId, saved.PhoneNumberCountryUniqueId)
		assert.Equal(t, tc.wantCalling, saved.PhoneNumberCountryCallingCode)
		assert.Equal(t, tc.number, saved.PhoneNumber)
		assert.Equal(t, tc.wantVerified, saved.PhoneNumberVerified)
		assert.Equal(t, tc.number, resp.PhoneNumber)
		assert.Equal(t, tc.wantVerified, resp.PhoneNumberVerified)
	}

	for _, tc := range selfService {
		t.Run("self-service, "+tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			database.On("GetUserBySubject", mock.Anything, mock.Anything, columnGroupSubject).Return(columnGroupStoredUser(), nil).Once()
			saved := expectNarrowSave(database, "SetUserPhone")
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedOwnPhone, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleAccountPhonePut(database, accountvalidation.NewPhoneValidator(), auditLogger).
				ServeHTTP(rr, columnGroupSelfServiceRequest(t, "/api/v1/account/phone",
					api.UpdateAccountPhoneRequest{PhoneCountryUniqueId: tc.countryId, PhoneNumber: tc.number}))

			resp := requireSavedNarrowly(t, database, rr, *saved)
			assertPhoneSaved(t, tc, *saved, resp)
		})
	}

	for _, tc := range administrator {
		t.Run("administrator, "+tc.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			database.On("GetUserById", mock.Anything, mock.Anything, columnGroupUserId).Return(columnGroupStoredUser(), nil).Once()
			saved := expectNarrowSave(database, "SetUserPhone")
			auditLogger.On("Log", mock.Anything, audit.EventUpdatedUserPhone, mock.Anything).Return().Once()

			rr := httptest.NewRecorder()
			HandleUserPhonePut(database, accountvalidation.NewPhoneValidator(), auditLogger).
				ServeHTTP(rr, columnGroupAdminRequest(t, "/api/v1/admin/users/61/phone", api.UpdateUserPhoneRequest{
					PhoneCountryUniqueId: tc.countryId, PhoneNumber: tc.number, PhoneNumberVerified: tc.sendVerified,
				}))

			resp := requireSavedNarrowly(t, database, rr, *saved)
			assertPhoneSaved(t, tc, *saved, resp)
		})
	}
}
