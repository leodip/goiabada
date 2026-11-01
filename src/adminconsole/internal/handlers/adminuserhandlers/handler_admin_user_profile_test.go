package adminuserhandlers

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
	"github.com/leodip/goiabada/adminconsole/internal/oauthclient"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/sessionstore"
)

// userProfileRecorder answers the user read with a fresh copy of the stored user on every call, so
// an echo written onto one call's answer cannot leak into the next, and records every update the
// handler forwards and every user it reads.
type userProfileRecorder struct {
	// pageLanguage is the stored page language every read answers, and an update that leaves the
	// field out keeps.
	pageLanguage string
	// subject is the subject of the user an update saves.
	subject   string
	updateErr error
	updates   []*api.UpdateUserProfileRequest
	updateIds []int64
	reads     []int64
	tokens    []string
}

func storedUserProfile(userId int64) *api.UserResponse {
	birthDate := time.Date(1970, time.January, 2, 0, 0, 0, 0, time.UTC)
	return &api.UserResponse{
		Id:                  userId,
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

func (c *userProfileRecorder) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	c.reads = append(c.reads, userId)
	user := storedUserProfile(userId)
	user.PageLanguage = c.pageLanguage
	return user, nil
}

func (c *userProfileRecorder) UpdateUserProfile(_ context.Context, accessToken string, userId int64,
	request *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	c.tokens = append(c.tokens, accessToken)
	c.updateIds = append(c.updateIds, userId)
	c.updates = append(c.updates, request)
	if c.updateErr != nil {
		return nil, c.updateErr
	}
	saved := storedUserProfile(userId)
	saved.Subject = c.subject
	saved.PageLanguage = c.pageLanguage
	if request.PageLanguage != nil {
		saved.PageLanguage = *request.PageLanguage
	}
	return saved, nil
}

// A refusal from the API redraws the admin user profile page with what the administrator typed
// rather than what is stored, the API's sentence, and the list position the page was opened from
// (#440 decision 7).
func TestHandleProfilePost_ARefusalRedrawsThePageWithTheSubmittedValues(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_profile.html").Once()

	apiClient := &userProfileRecorder{updateErr: &apiclient.APIError{
		Code: "INVALID_WEBSITE", Message: "The website is not valid.", StatusCode: http.StatusBadRequest,
	}}
	form := url.Values{
		"username":     {" jane-doe "},
		"givenName":    {"Jane"},
		"middleName":   {"Q"},
		"familyName":   {"Doe"},
		"nickname":     {"JD"},
		"website":      {"https://jane.example"},
		"gender":       {"2"},
		"dateOfBirth":  {"1990-05-17"},
		"zoneInfo":     {"Brazil___America/Sao_Paulo"},
		"locale":       {"pt-BR"},
		"pageLanguage": {"fr"},
	}

	rr := httptest.NewRecorder()
	HandleProfilePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(http.MethodPost,
		"/admin/users/7/profile?page=3&query=jane", handlertest.WithAccessToken(),
		handlertest.WithPathValue("userId", "7"), handlertest.WithForm(form)))

	require.Len(t, apiClient.updates, 1)
	assert.Equal(t, []string{handlertest.AccessToken}, apiClient.tokens)
	assert.Equal(t, []int64{7}, apiClient.updateIds)
	assert.Equal(t, &api.UpdateUserProfileRequest{
		Username:            "jane-doe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "https://jane.example",
		Gender:              "2",
		DateOfBirth:         "1990-05-17",
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
		PageLanguage:        ptr("fr"),
	}, apiClient.updates[0])
	assert.Equal(t, []int64{7}, apiClient.reads, "the page is redrawn over the user the URL names")

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
		Gender:              "other",
		BirthDate:           &storedBirthDate,
		ZoneInfoCountryName: "Brazil",
		ZoneInfo:            "America/Sao_Paulo",
		Locale:              "pt-BR",
		PageLanguage:        "fr",
	}, bind["user"], "the page redraws what is stored instead of what the administrator typed")
	submittedDateOfBirth := "1990-05-17"
	assert.Equal(t, &submittedDateOfBirth, bind["submittedDateOfBirth"],
		"the date of birth as typed, beside the user, which keeps the stored date (#562 decision 3)")
	assert.Equal(t, "The website is not valid.", bind["error"])
	assert.Equal(t, "3", bind["page"])
	assert.Equal(t, "jane", bind["query"])
	assert.NotEmpty(t, bind["timezones"])
	assert.NotEmpty(t, bind["locales"])
	assert.Equal(t, "fr", bind["pageLanguage"], "the Page language select keeps the submitted choice")
}

// The time-zone select only ever posts a country and a zone joined once by ___. Anything else is a
// hand-edited request, which keeps today's 500 and neither reads nor updates the user (#440
// decision 7).
func TestHandleProfilePost_AMalformedZoneAnswers500AndUpdatesNothing(t *testing.T) {
	for _, zoneInfo := range []string{"America/Sao_Paulo", "Brazil___America___Sao_Paulo"} {
		t.Run(zoneInfo, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Return().Once()

			apiClient := &userProfileRecorder{}
			form := url.Values{"username": {"jane-doe"}, "zoneInfo": {zoneInfo}}

			rr := httptest.NewRecorder()
			HandleProfilePost(httpHelper, nil, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(http.MethodPost,
				"/admin/users/7/profile", handlertest.WithAccessToken(),
				handlertest.WithPathValue("userId", "7"), handlertest.WithForm(form)))

			assert.Empty(t, apiClient.updates, "a malformed zone reached the API")
			assert.Empty(t, apiClient.reads)
			httpHelper.AssertNotCalled(t, "RenderTemplate",
				mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func ptr(s string) *string { return &s }

// The administrator's Page language select lists Automatic and every catalog the console has
// loaded, in the order core/i18n loads them, English first, and selects the user's stored choice; a
// stored tag whose catalog has gone shows Automatic selected, so the next save writes Automatic
// (#631 decisions 3 and 9).
func TestHandleProfileGet_OffersTheLoadedCatalogsAndSelectsTheStoredPageLanguage(t *testing.T) {
	for _, tc := range []struct {
		name, stored, selected string
	}{
		{"a language chosen", "es", "es"},
		{"Automatic", "", ""},
		{"a catalog that has gone", "ja", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_profile.html").Once()
			store := newFlashTestStore()

			HandleProfileGet(httpHelper, store, &userProfileRecorder{pageLanguage: tc.stored}).ServeHTTP(
				httptest.NewRecorder(), handlertest.Request(http.MethodGet, "/admin/users/7/profile",
					handlertest.WithAccessToken(), handlertest.WithPathValue("userId", "7")))

			bind := handlertest.Bind(t, httpHelper)
			selected, bound := bind["pageLanguage"].(string)
			require.True(t, bound, "the selected page language is bound")
			assert.Equal(t, tc.selected, selected)
			assert.Equal(t, []render.PageLanguageOption{
				{Tag: "en", Name: "English"},
				{Tag: "de", Name: "German"},
				{Tag: "es", Name: "Spanish"},
				{Tag: "fr", Name: "French"},
				{Tag: "it", Name: "Italian"},
				{Tag: "pt-BR", Name: "Portuguese (Brazil)"},
			}, bind["pageLanguages"])
		})
	}
}

// Saving the user's profile sends the Page language the form posted to the admin profile update,
// "" for Automatic, for the user the address names (#631 decision 9). A post without the field sends
// none, which leaves the stored value unchanged (decision 8), and a page language in the query
// string alone is not sent, the field being read from the body only.
func TestHandleProfilePost_SendsThePageLanguageTheFormPosted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
		form   url.Values
		want   *string
	}{
		{"a language chosen", "/admin/users/7/profile", url.Values{"username": {"jane-doe"}, "pageLanguage": {"es"}}, ptr("es")},
		{"Automatic chosen", "/admin/users/7/profile", url.Values{"username": {"jane-doe"}, "pageLanguage": {""}}, ptr("")},
		{"no field posted", "/admin/users/7/profile", url.Values{"username": {"jane-doe"}}, nil},
		{"the field in the query only", "/admin/users/7/profile?pageLanguage=de", url.Values{"username": {"jane-doe"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			store := newFlashTestStore()
			apiClient := &userProfileRecorder{pageLanguage: "it"}

			rr := httptest.NewRecorder()
			HandleProfilePost(httpHelper, store, apiClient, consoleBaseURL).ServeHTTP(rr, handlertest.Request(
				http.MethodPost, tc.target, handlertest.WithAccessToken(),
				handlertest.WithPathValue("userId", "7"), handlertest.WithForm(tc.form)))

			require.Equal(t, http.StatusFound, rr.Code)
			assert.Equal(t, consoleBaseURL+"/admin/users/7/profile?page=&query=", rr.Header().Get("Location"))
			require.Len(t, apiClient.updates, 1)
			assert.Equal(t, []int64{7}, apiClient.updateIds)
			assert.Equal(t, tc.want, apiClient.updates[0].PageLanguage)
		})
	}
}

// An administrator who saves a page language on their own user Profile page sees the console's next
// page in it, as a save in Account > Profile does: the console's session copy follows what the API
// saved (#631 decision 7). Saving another user's profile, or a session with no ID token, leaves the
// administrator's copy as it was.
func TestHandleProfilePost_AnAdministratorsOwnSaveRefreshesTheConsoleLanguage(t *testing.T) {
	const signedIn = "admin-subject"
	for _, tc := range []struct {
		name     string
		saved    string
		idToken  *oauth.JwtToken
		form     url.Values
		wantCopy string
	}{
		{"their own user, a language chosen", signedIn, adminIdToken(signedIn),
			url.Values{"username": {"jane-doe"}, "pageLanguage": {"es"}}, "es"},
		{"their own user, Automatic chosen", signedIn, adminIdToken(signedIn),
			url.Values{"username": {"jane-doe"}, "pageLanguage": {""}}, ""},
		{"another user", "other-subject", adminIdToken(signedIn),
			url.Values{"username": {"jane-doe"}, "pageLanguage": {"es"}}, "pt-BR"},
		{"no ID token", signedIn, nil,
			url.Values{"username": {"jane-doe"}, "pageLanguage": {"es"}}, "pt-BR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			store := newFlashTestStore()
			cookie := pageLanguageInSession(t, store, "pt-BR")
			apiClient := &userProfileRecorder{pageLanguage: "it", subject: tc.saved}

			req := handlertest.Request(http.MethodPost, "/admin/users/7/profile",
				handlertest.WithJwtInfo(oauthclient.JwtInfo{
					TokenResponse: oauth.TokenResponse{AccessToken: handlertest.AccessToken},
					IdToken:       tc.idToken,
				}),
				handlertest.WithPathValue("userId", "7"), handlertest.WithForm(tc.form))
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			HandleProfilePost(httpHelper, store, apiClient, consoleBaseURL).ServeHTTP(rr, req)

			require.Equal(t, http.StatusFound, rr.Code)
			next := httptest.NewRequest(http.MethodGet, "/admin/users/7/profile", nil)
			next.AddCookie(cookie)
			for _, c := range rr.Result().Cookies() {
				next.AddCookie(c)
			}
			sess, err := store.Get(next, builtin.AdminConsoleSessionName)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCopy, sess.Values[sessionkeys.PageLanguage])
		})
	}
}

func adminIdToken(subject string) *oauth.JwtToken {
	return &oauth.JwtToken{TokenBase64: "id", Claims: map[string]any{"sub": subject}}
}

// pageLanguageInSession stores a session holding the console's copy of the page language and
// returns the cookie that names it.
func pageLanguageInSession(t *testing.T, store *sessionstore.ServerSideStore, pageLanguage string) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	rec := httptest.NewRecorder()
	sess, err := store.Get(req, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	sess.Values[sessionkeys.PageLanguage] = pageLanguage
	require.NoError(t, store.Save(req, rec, sess))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}
