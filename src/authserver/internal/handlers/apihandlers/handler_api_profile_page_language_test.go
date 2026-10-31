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

// The page language on the two profile saves, self-service and administrator alike (#631 decisions
// 3, 8 and 9). The field is optional: left out, the stored page language stays, so an application
// written before the field existed does not reset its users to Automatic; "" sets Automatic; a
// catalog's tag sets that language; anything else is refused before anything is written.

// pageLanguageStored is the page language every user here starts with, so a save that leaves it
// alone and one that writes it are told apart.
const pageLanguageStored = "pt-BR"

// profilePageLanguageRoute is one of the two profile PUTs, with the reads it makes and the audit
// event it records.
type profilePageLanguageRoute struct {
	name       string
	handler    func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler
	expectRead func(database *datamocks.Database, stored *record.User)
	request    func(t *testing.T, body []byte) *http.Request
	event      string
}

func profilePageLanguageRoutes() []profilePageLanguageRoute {
	return []profilePageLanguageRoute{
		{
			name: "account",
			handler: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
				return HandleAccountProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger)
			},
			expectRead: func(database *datamocks.Database, stored *record.User) {
				database.On("GetUserBySubject", mock.Anything, mock.Anything, profileTestSubject).Return(stored, nil).Once()
			},
			request: func(t *testing.T, body []byte) *http.Request {
				req := httptest.NewRequest(http.MethodPut, "/api/v1/account/profile", bytes.NewReader(body))
				return setTokenContextWithClaims(req, map[string]interface{}{"sub": profileTestSubject})
			},
			event: audit.EventUpdatedOwnProfile,
		},
		{
			name: "admin",
			handler: func(database *datamocks.Database, auditLogger *handlersmocks.AuditLogger) http.Handler {
				return HandleUserProfilePut(database, accountvalidation.NewProfileValidator(database), auditLogger)
			},
			expectRead: func(database *datamocks.Database, stored *record.User) {
				database.On("GetUserById", mock.Anything, mock.Anything, profileTestUserId).Return(stored, nil).Once()
			},
			request: func(t *testing.T, body []byte) *http.Request {
				req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/users/42/profile", bytes.NewReader(body))
				req.SetPathValue("id", "42")
				return setTokenContextWithClaims(req, map[string]interface{}{"scope": "authserver:manage", "sub": adminSubject})
			},
			event: audit.EventUpdatedUserProfile,
		},
	}
}

func pageLanguageStoredUser() *record.User {
	return &record.User{Id: profileTestUserId, Subject: profileTestSubject, GivenName: "Ada", PageLanguage: pageLanguageStored}
}

// pageLanguageBody is a profile PUT's body as an application sends it: the profile fields, and
// pageLanguage only when sent is not nil. It is written out rather than marshalled from
// api.UpdateUserProfileRequest, so that what "left out" means on the wire is stated here and not
// inherited from the struct's tags.
func pageLanguageBody(t *testing.T, sent *string) []byte {
	t.Helper()
	body := map[string]any{"givenName": "Ada", "familyName": "Lovelace"}
	if sent != nil {
		body["pageLanguage"] = *sent
	}
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	return encoded
}

func TestProfilePuts_ApplyThePageLanguage(t *testing.T) {
	sent := func(s string) *string { return &s }
	cases := []struct {
		name   string
		sent   *string
		stored string
	}{
		{"left out keeps the stored page language", nil, "pt-BR"},
		{"empty sets Automatic", sent(""), ""},
		{"a catalog's tag sets that language", sent("es"), "es"},
		{"English is a choice, not Automatic", sent("en"), "en"},
	}

	for _, route := range profilePageLanguageRoutes() {
		for _, tc := range cases {
			t.Run(route.name+", "+tc.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)

				route.expectRead(database, pageLanguageStoredUser())
				saved := expectNarrowSave(database, "SetUserProfile")
				auditLogger.On("Log", mock.Anything, route.event, mock.Anything).Return().Once()

				rr := httptest.NewRecorder()
				route.handler(database, auditLogger).ServeHTTP(rr, route.request(t, pageLanguageBody(t, tc.sent)))

				require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
				require.NotNil(t, *saved, "the narrow write was not reached")
				assert.Equal(t, tc.stored, (*saved).PageLanguage, "the page language handed to the write")
				assert.Equal(t, "Lovelace", (*saved).FamilyName, "the rest of the profile is saved alongside")

				var body map[string]map[string]any
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
				assert.Equal(t, tc.stored, body["user"]["pageLanguage"], "the response carries the page language")
			})
		}
	}
}

func TestProfilePuts_RefuseAPageLanguageNotInTheList(t *testing.T) {
	for _, route := range profilePageLanguageRoutes() {
		for _, sent := range []string{"ja", "pt-br", "fr-CA", "pt"} {
			t.Run(route.name+", sent "+sent, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)

				// No write and no audit record are stubbed: the mocks fail the test on either.
				route.expectRead(database, pageLanguageStoredUser())

				rr := httptest.NewRecorder()
				route.handler(database, auditLogger).ServeHTTP(rr, route.request(t, pageLanguageBody(t, &sent)))

				require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
				var body map[string]any
				require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
				assert.Equal(t, "validator.profile.page_language_invalid", body["error_code"])
				assert.Equal(t, "Choose a language from the list.", body["error_description"])
			})
		}
	}
}

// The refusal is in the language the request asks for, as every Account and admin API refusal is
// (#631 decision 5): the console asks in its page's language.
func TestProfilePuts_RefuseInTheRequestsLanguage(t *testing.T) {
	for _, route := range profilePageLanguageRoutes() {
		t.Run(route.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			route.expectRead(database, pageLanguageStoredUser())

			sent := "ja"
			req := route.request(t, pageLanguageBody(t, &sent))
			req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))

			rr := httptest.NewRecorder()
			route.handler(database, auditLogger).ServeHTTP(rr, req)

			require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
			var body map[string]any
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, "Escolha um idioma da lista.", body["error_description"])
		})
	}
}

// A user's page language is in every user response, the account's own read among them.
func TestHandleAccountProfileGet_CarriesThePageLanguage(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetUserBySubject", mock.Anything, mock.Anything, profileTestSubject).Return(pageLanguageStoredUser(), nil).Once()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/profile", nil)
	req = setTokenContextWithClaims(req, map[string]interface{}{"sub": profileTestSubject})
	rr := httptest.NewRecorder()
	HandleAccountProfileGet(database).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var body api.GetUserResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, "pt-BR", body.User.PageLanguage)
}
