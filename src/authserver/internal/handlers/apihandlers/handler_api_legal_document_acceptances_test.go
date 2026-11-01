package apihandlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A user's acceptances of legal documents (#622 decision 10), read by the user and by an
// administrator.

var (
	acceptancesPublished = time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	acceptancesFirst     = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	acceptancesSecond    = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
)

// expectTwoAcceptances sets up user 42's acceptances: version 1 of "terms" (document 7), then
// version 1 of "house" (document 8), which is retired. Document 9 comes after both and is never
// read: every version the user accepted is found by then.
func expectTwoAcceptances(database *datamocks.Database) {
	database.On("GetLegalDocumentAcceptancesByUserId", mock.Anything, (*sql.Tx)(nil), int64(42)).
		Return([]record.LegalDocumentAcceptance{
			{Id: 1, AcceptedAt: acceptancesFirst, UserId: 42, LegalDocumentVersionId: 71},
			{Id: 2, AcceptedAt: acceptancesSecond, UserId: 42, LegalDocumentVersionId: 81},
		}, nil).Once()
	database.On("GetAllLegalDocuments", mock.Anything, (*sql.Tx)(nil)).Return([]record.LegalDocument{
		{Id: 7, ShortName: "terms", Kind: record.LegalDocumentKindMustAccept},
		{Id: 8, ShortName: "house", Kind: record.LegalDocumentKindMustAccept, RetiredAt: sql.NullTime{Time: acceptancesSecond, Valid: true}},
		{Id: 9, ShortName: "later", Kind: record.LegalDocumentKindMustAccept},
	}, nil).Once()
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, (*sql.Tx)(nil), int64(7)).
		Return([]record.LegalDocumentVersion{
			{Id: 71, PublishedAt: acceptancesPublished, LegalDocumentId: 7, VersionNumber: 1, Title: "Terms"},
			{Id: 72, PublishedAt: acceptancesPublished, LegalDocumentId: 7, VersionNumber: 2, Title: "Terms, revised"},
		}, nil).Once()
	database.On("GetLegalDocumentVersionsByLegalDocumentId", mock.Anything, (*sql.Tx)(nil), int64(8)).
		Return([]record.LegalDocumentVersion{
			{Id: 81, PublishedAt: acceptancesPublished, LegalDocumentId: 8, VersionNumber: 1, Title: "House rules"},
		}, nil).Once()
}

const twoAcceptancesJSON = `{"acceptances":[` +
	`{"id":2,"acceptedAt":"2026-10-02T09:00:00Z","legalDocumentId":8,"shortName":"house","version":1,` +
	`"title":"House rules","publishedAt":"2026-09-01T09:00:00Z","retired":true,"url":null},` +
	`{"id":1,"acceptedAt":"2026-10-01T09:00:00Z","legalDocumentId":7,"shortName":"terms","version":1,` +
	`"title":"Terms","publishedAt":"2026-09-01T09:00:00Z","retired":false,"url":"https://auth.example/legal/terms/versions/1"}]}`

func accountAcceptancesRequest(subject string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/legal-document-acceptances", nil)
	return setTokenContextWithClaims(req, map[string]interface{}{"sub": subject})
}

func userAcceptancesRequest(id string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/"+id+"/legal-document-acceptances", nil)
	req.SetPathValue("id", id)
	return req
}

func TestHandleAccountLegalDocumentAcceptancesGet_TheCallersAcceptancesTheLatestFirst(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "the-user").
		Return(&record.User{Id: 42, Enabled: true}, nil).Once()
	expectTwoAcceptances(database)

	rr := httptest.NewRecorder()
	HandleAccountLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, accountAcceptancesRequest("the-user"))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, twoAcceptancesJSON, rr.Body.String())
}

func TestHandleAccountLegalDocumentAcceptancesGet_NoAcceptancesReadsNoDocuments(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "the-user").
		Return(&record.User{Id: 42, Enabled: true}, nil).Once()
	database.On("GetLegalDocumentAcceptancesByUserId", mock.Anything, (*sql.Tx)(nil), int64(42)).
		Return([]record.LegalDocumentAcceptance{}, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, accountAcceptancesRequest("the-user"))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, `{"acceptances":[]}`, rr.Body.String())
}

func TestHandleAccountLegalDocumentAcceptancesGet_AnUnknownSubjectIsNotFound(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "gone").Return(nil, nil).Once()

	rr := httptest.NewRecorder()
	HandleAccountLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, accountAcceptancesRequest("gone"))

	assert.Equal(t, http.StatusNotFound, rr.Code)
	var response map[string]any
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	assert.Equal(t, "NOT_FOUND", response["error_code"])
}

func TestHandleAccountLegalDocumentAcceptancesGet_AReadFailureIsA500(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetUserBySubject", mock.Anything, (*sql.Tx)(nil), "the-user").
		Return(&record.User{Id: 42, Enabled: true}, nil).Once()
	database.On("GetLegalDocumentAcceptancesByUserId", mock.Anything, (*sql.Tx)(nil), int64(42)).
		Return(nil, assert.AnError).Once()

	rr := httptest.NewRecorder()
	HandleAccountLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, accountAcceptancesRequest("the-user"))

	assertJSONInternalServerError(t, rr)
}

func TestHandleUserLegalDocumentAcceptancesGet_TheUsersAcceptancesTheLatestFirst(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(42)).Return(&record.User{Id: 42}, nil).Once()
	expectTwoAcceptances(database)

	rr := httptest.NewRecorder()
	HandleUserLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, userAcceptancesRequest("42"))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.JSONEq(t, twoAcceptancesJSON, rr.Body.String())
}

func TestHandleUserLegalDocumentAcceptancesGet_Refusals(t *testing.T) {
	t.Run("an id that is not a number", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		rr := httptest.NewRecorder()
		HandleUserLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, userAcceptancesRequest("abc"))
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("a user that does not exist", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(nil, nil).Once()
		rr := httptest.NewRecorder()
		HandleUserLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, userAcceptancesRequest("5"))
		assert.Equal(t, http.StatusNotFound, rr.Code)
	})
	t.Run("the user read fails", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(nil, assert.AnError).Once()
		rr := httptest.NewRecorder()
		HandleUserLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, userAcceptancesRequest("5"))
		assertJSONInternalServerError(t, rr)
	})
	t.Run("an accepted version no document has", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetUserById", mock.Anything, (*sql.Tx)(nil), int64(42)).Return(&record.User{Id: 42}, nil).Once()
		database.On("GetLegalDocumentAcceptancesByUserId", mock.Anything, (*sql.Tx)(nil), int64(42)).
			Return([]record.LegalDocumentAcceptance{{Id: 1, AcceptedAt: acceptancesFirst, UserId: 42, LegalDocumentVersionId: 99}}, nil).Once()
		database.On("GetAllLegalDocuments", mock.Anything, (*sql.Tx)(nil)).Return([]record.LegalDocument{}, nil).Once()
		rr := httptest.NewRecorder()
		HandleUserLegalDocumentAcceptancesGet(database, "https://auth.example").ServeHTTP(rr, userAcceptancesRequest("42"))
		assertJSONInternalServerError(t, rr)
	})
}
