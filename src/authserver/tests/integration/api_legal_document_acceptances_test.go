package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A user's acceptances of legal documents, read by the user through the account API and by an
// administrator through the admin API, with the users-read scopes (#622 decisions 6 and 10). Each
// lists every version the user accepted, the latest acceptance first, with the document's short name,
// the version's number, title and publish date, when it was accepted, and the address of the
// version's public page, which a retired document has none of.
//
// Every document here applies to selected apps with a client of the test's own, and is retired when
// the test ends, so no other test's sign-in owes it.

const accountLegalDocumentAcceptancesPath = "/api/v1/account/legal-document-acceptances"

func userLegalDocumentAcceptancesPath(userId int64) string {
	return fmt.Sprintf("/api/v1/admin/users/%d/legal-document-acceptances", userId)
}

// acceptancesFixture is a user who accepted three versions: version 1 and version 2 of "Terms of
// use", and version 1 of "House rules", which was retired after. Another user accepted version 1 of
// "Terms of use" too, which is not the first user's.
type acceptancesFixture struct {
	termsShort    string
	termsId       int64
	houseShort    string
	houseId       int64
	termsV1At     time.Time
	termsV2At     time.Time
	houseV1At     time.Time
	otherUserId   int64
	adminToken    string
	termsVersion1 int64
}

func newAcceptancesFixture(t *testing.T, user *record.User) *acceptancesFixture {
	t.Helper()
	adminToken, _ := createAdminClientWithToken(t)
	app := appForLegalDocuments(t)
	f := &acceptancesFixture{adminToken: adminToken}

	publishFor := func(prefix, title string) (int64, string) {
		shortName := legalShortName(prefix)
		id := createLegalDocumentOverAPI(t, adminToken, "must_accept", shortName, title, "Be nice: "+title+".")
		status, body := setApps(t, adminToken, id, "selected_apps", []int64{app.Id}, []int64{})
		require.Equal(t, http.StatusOK, status, "apps: %v", body)
		status, body, _ = legalCall(t, adminToken, http.MethodPost, legalPath(id, "/publish"), nil)
		require.Equal(t, http.StatusOK, status, "publish: %v", body)
		return id, shortName
	}
	accept := func(userId, versionId int64, at time.Time) {
		require.NoError(t, database.CreateLegalDocumentAcceptance(context.Background(), nil,
			&record.LegalDocumentAcceptance{AcceptedAt: at, UserId: userId, LegalDocumentVersionId: versionId}))
	}

	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	f.termsV1At, f.termsV2At, f.houseV1At = base, base.Add(time.Hour), base.Add(2*time.Hour)

	f.termsId, f.termsShort = publishFor("acceptances-terms", "Terms of use")
	f.termsVersion1 = versionId(t, f.termsId, 1)
	accept(user.Id, f.termsVersion1, f.termsV1At)

	status, body, _ := legalCall(t, adminToken, http.MethodPut, legalPath(f.termsId, "/draft"), map[string]any{
		"title": "Terms of use, revised", "markdown": "Be nicer.",
	})
	require.Equal(t, http.StatusOK, status, "draft: %v", body)
	status, body, _ = legalCall(t, adminToken, http.MethodPost, legalPath(f.termsId, "/publish"), nil)
	require.Equal(t, http.StatusOK, status, "publish version 2: %v", body)
	accept(user.Id, versionId(t, f.termsId, 2), f.termsV2At)

	f.houseId, f.houseShort = publishFor("acceptances-house", "House rules")
	accept(user.Id, versionId(t, f.houseId, 1), f.houseV1At)
	status, body, _ = legalCall(t, adminToken, http.MethodPost, legalPath(f.houseId, "/retire"), nil)
	require.Equal(t, http.StatusOK, status, "retire: %v", body)

	other, _ := newLegalAcceptanceUser(t)
	f.otherUserId = other.Id
	accept(other.Id, f.termsVersion1, f.termsV1At)
	return f
}

// assertTheFixturesAcceptances holds an answer to the fixture user's three acceptances, the latest
// first.
func (f *acceptancesFixture) assertTheFixturesAcceptances(t *testing.T, got []api.LegalDocumentAcceptanceResponse) {
	t.Helper()
	require.Len(t, got, 3, "%+v", got)
	baseURL := appConfig.AuthServer.BaseURL

	type want struct {
		documentId int64
		shortName  string
		version    int
		title      string
		acceptedAt time.Time
		retired    bool
		url        string
	}
	for i, w := range []want{
		{f.houseId, f.houseShort, 1, "House rules", f.houseV1At, true, ""},
		{f.termsId, f.termsShort, 2, "Terms of use, revised", f.termsV2At, false, baseURL + "/legal/" + f.termsShort + "/versions/2"},
		{f.termsId, f.termsShort, 1, "Terms of use", f.termsV1At, false, baseURL + "/legal/" + f.termsShort + "/versions/1"},
	} {
		a := got[i]
		assert.NotZero(t, a.Id, "acceptance %d", i)
		assert.Equal(t, w.documentId, a.LegalDocumentId, "acceptance %d", i)
		assert.Equal(t, w.shortName, a.ShortName, "acceptance %d", i)
		assert.Equal(t, w.version, a.Version, "acceptance %d", i)
		assert.Equal(t, w.title, a.Title, "acceptance %d", i)
		if assert.NotNil(t, a.AcceptedAt, "acceptance %d", i) {
			assert.WithinDuration(t, w.acceptedAt, *a.AcceptedAt, time.Second, "acceptance %d", i)
		}
		assert.NotNil(t, a.PublishedAt, "acceptance %d", i)
		assert.Equal(t, w.retired, a.Retired, "acceptance %d", i)
		if w.url == "" {
			assert.Nil(t, a.URL, "a retired document's pages all answer not found, so acceptance %d has no address", i)
		} else if assert.NotNil(t, a.URL, "acceptance %d", i) {
			assert.Equal(t, w.url, *a.URL, "acceptance %d", i)
		}
	}
}

func decodeAcceptances(t *testing.T, resp *http.Response) []api.LegalDocumentAcceptanceResponse {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var answer api.GetLegalDocumentAcceptancesResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	return answer.Acceptances
}

func TestAPIAccountLegalDocumentAcceptances_ListsWhatTheUserAccepted(t *testing.T) {
	accessToken, u := getUserAccessTokenWithAccountScope(t)
	f := newAcceptancesFixture(t, u)

	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+accountLegalDocumentAcceptancesPath, accessToken, nil)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	f.assertTheFixturesAcceptances(t, decodeAcceptances(t, resp))
}

func TestAPIAccountLegalDocumentAcceptances_AUserWhoAcceptedNothingGetsAnEmptyList(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+accountLegalDocumentAcceptancesPath, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"acceptances":[]}`, string(body))
}

func TestAPIAccountLegalDocumentAcceptances_RefusesATokenWithoutTheAccountScope(t *testing.T) {
	accessToken, _ := createUserAccessTokenWithScope(t, "openid profile email")

	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+accountLegalDocumentAcceptancesPath, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestAPIUserLegalDocumentAcceptances_ListsWhatTheUserAccepted(t *testing.T) {
	user, _ := newLegalAcceptanceUser(t)
	f := newAcceptancesFixture(t, user)

	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+userLegalDocumentAcceptancesPath(user.Id), f.adminToken, nil)
	f.assertTheFixturesAcceptances(t, decodeAcceptances(t, resp))

	resp = makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+userLegalDocumentAcceptancesPath(f.otherUserId), f.adminToken, nil)
	others := decodeAcceptances(t, resp)
	require.Len(t, others, 1, "the other user accepted version 1 of the terms alone: %+v", others)
	assert.Equal(t, f.termsShort, others[0].ShortName)
	assert.Equal(t, 1, others[0].Version)
}

func TestAPIUserLegalDocumentAcceptances_Refusals(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

	status, body, _ := legalCall(t, adminToken, http.MethodGet, userLegalDocumentAcceptancesPath(999999999), nil)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "NOT_FOUND", body["error_code"])

	status, body, _ = legalCall(t, adminToken, http.MethodGet, "/api/v1/admin/users/abc/legal-document-acceptances", nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "VALIDATION_ERROR", body["error_code"])
}

// The route is read as part of the user, with the users-read scopes (decision 6).
func TestAPIUserLegalDocumentAcceptances_TheUsersReadScopes(t *testing.T) {
	user, _ := newLegalAcceptanceUser(t)

	for _, c := range []struct {
		permission string
		status     int
	}{
		{builtin.AdminReadPermissionIdentifier, http.StatusOK},
		{builtin.ManageUsersPermissionIdentifier, http.StatusOK},
		{builtin.ManagePermissionIdentifier, http.StatusOK},
		{builtin.ManageClientsPermissionIdentifier, http.StatusForbidden},
		{builtin.ManageSettingsPermissionIdentifier, http.StatusForbidden},
	} {
		t.Run(c.permission, func(t *testing.T) {
			token, client := createClientWithGranularScope(t, c.permission)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

			status, body, _ := legalCall(t, token, http.MethodGet, userLegalDocumentAcceptancesPath(user.Id), nil)
			assert.Equal(t, c.status, status, "%v", body)
		})
	}
}
