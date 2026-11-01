package accounthandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/sessionstore"
)

// accountProfileRecorder answers the profile read with a fresh copy of the stored profile on every
// call, so an echo written onto one call's answer cannot leak into the next, and records every
// update the handler forwards.
type accountProfileRecorder struct {
	// pageLanguage is the stored page language every read answers, and an update that leaves the
	// field out keeps.
	pageLanguage string
	updateErr    error
	updates      []*api.UpdateUserProfileRequest
	tokens       []string
}

func storedAccountProfile() *api.UserResponse {
	birthDate := time.Date(1970, time.January, 2, 0, 0, 0, 0, time.UTC)
	return &api.UserResponse{
		Id:                  7,
		Email:               "stored@example.com",
		Username:            "stored-username",
		GivenName:           "Stored",
		MiddleName:          "S",
		FamilyName:          "Profile",
		Nickname:            "stored",
		Website:             "https://stored.example",
		Gender:              "female",
		BirthDate:           &birthDate,
		ZoneInfoCountryName: "Portugal",
		ZoneInfo:            "Europe/Lisbon",
		Locale:              "en-US",
	}
}

func (c *accountProfileRecorder) GetAccountProfile(_ context.Context, _ string) (*api.UserResponse, error) {
	profile := storedAccountProfile()
	profile.PageLanguage = c.pageLanguage
	return profile, nil
}

func (c *accountProfileRecorder) UpdateAccountProfile(_ context.Context, accessToken string,
	request *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	c.tokens = append(c.tokens, accessToken)
	c.updates = append(c.updates, request)
	if c.updateErr != nil {
		return nil, c.updateErr
	}
	saved := storedAccountProfile()
	saved.PageLanguage = c.pageLanguage
	if request.PageLanguage != nil {
		saved.PageLanguage = *request.PageLanguage
	}
	return saved, nil
}

// submittedAccountProfile is every field the profile form posts, each different from the stored
// profile, so a value that came from the store rather than from the form is told apart.
var submittedAccountProfile = url.Values{
	"username":     {" jane-doe "},
	"givenName":    {"Jane"},
	"middleName":   {"Q"},
	"familyName":   {"Doe"},
	"nickname":     {"JD"},
	"website":      {"https://jane.example"},
	"gender":       {"1"},
	"dateOfBirth":  {"1990-05-17"},
	"zoneInfo":     {"Brazil___America/Sao_Paulo"},
	"locale":       {"pt-BR"},
	"pageLanguage": {"fr"},
}

// A refusal from the API redraws the account profile page with what the user typed rather than what
// is stored, and the API's sentence, so nothing the user entered is lost (#440 decision 7).
func TestHandleProfilePost_ARefusalRedrawsThePageWithTheSubmittedValues(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_profile.html").Once()

	apiClient := &accountProfileRecorder{updateErr: &apiclient.APIError{
		Code: "INVALID_WEBSITE", Message: "The website is not valid.", StatusCode: http.StatusBadRequest,
	}}

	rr := httptest.NewRecorder()
	HandleProfilePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(http.MethodPost,
		"/account/profile", handlertest.WithAccessToken(), handlertest.WithForm(submittedAccountProfile)))

	require.Len(t, apiClient.updates, 1)
	assert.Equal(t, []string{handlertest.AccessToken}, apiClient.tokens)
	assert.Equal(t, &api.UpdateUserProfileRequest{
		Username:            "jane-doe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "https://jane.example",
		Gender:              "1",
		DateOfBirth:         "1990-05-17",
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
		PageLanguage:        ptr("fr"),
	}, apiClient.updates[0])

	bind := handlertest.Bind(t, httpHelper)
	storedBirthDate := time.Date(1970, time.January, 2, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, &api.UserResponse{
		Id:                  7,
		Email:               "stored@example.com",
		Username:            "jane-doe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "https://jane.example",
		Gender:              "male",
		BirthDate:           &storedBirthDate,
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
		PageLanguage:        "fr",
	}, bind["user"], "the page redraws what is stored instead of what the user typed")
	submittedDateOfBirth := "1990-05-17"
	assert.Equal(t, &submittedDateOfBirth, bind["submittedDateOfBirth"],
		"the date of birth as typed, beside the user, which keeps the stored date (#562 decision 3)")
	assert.Equal(t, "The website is not valid.", bind["error"])
	assert.NotEmpty(t, bind["timezones"])
	assert.NotEmpty(t, bind["locales"])
	assert.Equal(t, "fr", bind["pageLanguage"], "the Page language select keeps the submitted choice")
}

// The time-zone select only ever posts a country and a zone joined once by ___. Anything else is a
// hand-edited request, which keeps today's 500 and forwards nothing (#440 decision 7).
func TestHandleProfilePost_AMalformedZoneAnswers500AndUpdatesNothing(t *testing.T) {
	for _, zoneInfo := range []string{"America/Sao_Paulo", "Brazil___America___Sao_Paulo"} {
		t.Run(zoneInfo, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			apiClient := &accountProfileRecorder{}
			form := url.Values{"username": {"jane-doe"}, "zoneInfo": {zoneInfo}}

			rr := httptest.NewRecorder()
			HandleProfilePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(http.MethodPost,
				"/account/profile", handlertest.WithAccessToken(), handlertest.WithForm(form)))

			assert.Empty(t, apiClient.updates, "a malformed zone reached the API")
			httpHelper.AssertNotCalled(t, "RenderTemplate",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func ptr(s string) *string { return &s }

// seedAccountSession stores values as the signed-in user's console session and returns a jar
// holding its cookie, as the browser holds it.
func seedAccountSession(t *testing.T, store *sessionstore.ServerSideStore, values map[string]any) *cookieJar {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, err := store.Get(req, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	for k, v := range values {
		sess.Values[k] = v
	}
	rr := httptest.NewRecorder()
	require.NoError(t, store.Save(req, rr, sess))
	jar := newCookieJar()
	jar.keep(rr)
	return jar
}

// readAccountSession loads the session the jar names, as the browser's next request would.
func readAccountSession(t *testing.T, store *sessionstore.ServerSideStore, jar *cookieJar) *sessionstore.Session {
	t.Helper()
	sess, err := store.Get(jar.send(httptest.NewRequest(http.MethodGet, "/", nil)), builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	return sess
}

// Opening the profile page refreshes the session's copy of the page language from the profile it
// fetched, so a choice made elsewhere (another browser, an administrator, an API client) reaches
// this session's next page (#631 decision 7). Each row's copy differs from the profile's, and the
// Automatic row is the twin that clears a stale choice.
func TestHandleProfileGet_CopiesTheFetchedPageLanguageIntoTheSession(t *testing.T) {
	for _, tc := range []struct {
		name, copied, stored string
	}{
		{"a choice made elsewhere", "pt-BR", "fr"},
		{"Automatic chosen elsewhere", "pt-BR", ""},
		{"a session signed in before the copy existed", "", "es"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFlashTestStore()
			values := map[string]any{"unrelated": "kept"}
			if tc.copied != "" {
				values[sessionkeys.PageLanguage] = tc.copied
			}
			jar := seedAccountSession(t, store, values)
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_profile.html").Once()

			rr := httptest.NewRecorder()
			HandleProfileGet(httpHelper, store, &accountProfileRecorder{pageLanguage: tc.stored}).ServeHTTP(rr,
				jar.send(handlertest.Request(http.MethodGet, "/account/profile", handlertest.WithAccessToken())))
			jar.keep(rr)

			sess := readAccountSession(t, store, jar)
			assert.Equal(t, tc.stored, sess.Values[sessionkeys.PageLanguage])
			assert.Equal(t, "kept", sess.Values["unrelated"])
			assert.Equal(t, tc.stored, handlertest.Bind(t, httpHelper)["pageLanguage"])
		})
	}
}

// The Page language select lists Automatic and every catalog the console has loaded, in the order
// core/i18n loads them, English first, and a stored tag whose catalog has gone shows Automatic selected, so the
// next save writes Automatic (#631 decision 3).
func TestHandleProfileGet_OffersTheLoadedCatalogsAndAVanishedOneIsAutomatic(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_profile.html").Once()

	HandleProfileGet(httpHelper, newFlashTestStore(), &accountProfileRecorder{pageLanguage: "ja"}).ServeHTTP(
		httptest.NewRecorder(), handlertest.Request(http.MethodGet, "/account/profile", handlertest.WithAccessToken()))

	bind := handlertest.Bind(t, httpHelper)
	selected, bound := bind["pageLanguage"].(string)
	require.True(t, bound, "the selected page language is bound")
	assert.Empty(t, selected, "Automatic is selected")
	assert.Equal(t, []render.PageLanguageOption{
		{Tag: "en", Name: "English"},
		{Tag: "de", Name: "German"},
		{Tag: "es", Name: "Spanish"},
		{Tag: "fr", Name: "French"},
		{Tag: "it", Name: "Italian"},
		{Tag: "pt-BR", Name: "Portuguese (Brazil)"},
	}, bind["pageLanguages"])
}

// Saving the profile sends the Page language the form posted, "" for Automatic, and copies the one
// the API saved into the session, so the redirect's page, the user's next, is drawn in it (#631
// decision 7). A form without the field, the administrator's user Profile page's today, sends none,
// which leaves the stored value unchanged (decision 8), and the copy follows what the API answered.
func TestHandleProfilePost_SendsThePageLanguageAndCopiesTheSavedOne(t *testing.T) {
	for _, tc := range []struct {
		name        string
		form        url.Values
		wantRequest *string
		wantCopy    string
	}{
		{"a language chosen", url.Values{"username": {"jane-doe"}, "pageLanguage": {"es"}}, ptr("es"), "es"},
		{"Automatic chosen", url.Values{"username": {"jane-doe"}, "pageLanguage": {""}}, ptr(""), ""},
		{"no field posted", url.Values{"username": {"jane-doe"}}, nil, "it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFlashTestStore()
			jar := seedAccountSession(t, store, map[string]any{sessionkeys.PageLanguage: "pt-BR"})
			apiClient := &accountProfileRecorder{pageLanguage: "it"}
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)

			rr := httptest.NewRecorder()
			HandleProfilePost(httpHelper, store, apiClient, consoleBaseURL).ServeHTTP(rr, jar.send(handlertest.Request(
				http.MethodPost, "/account/profile", handlertest.WithAccessToken(), handlertest.WithForm(tc.form))))
			jar.keep(rr)

			require.Equal(t, http.StatusFound, rr.Code)
			require.Len(t, apiClient.updates, 1)
			assert.Equal(t, tc.wantRequest, apiClient.updates[0].PageLanguage)
			assert.Equal(t, tc.wantCopy, readAccountSession(t, store, jar).Values[sessionkeys.PageLanguage])
		})
	}
}

// A Page language posted in the address rather than the form is not the form's: it is not sent.
func TestHandleProfilePost_APageLanguageInTheQueryIsNotSent(t *testing.T) {
	apiClient := &accountProfileRecorder{}
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	HandleProfilePost(httpHelper, newFlashTestStore(), apiClient, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/account/profile?pageLanguage=de", handlertest.WithAccessToken(),
			handlertest.WithForm(url.Values{"username": {"jane-doe"}})))

	require.Len(t, apiClient.updates, 1)
	assert.Nil(t, apiClient.updates[0].PageLanguage)
}
