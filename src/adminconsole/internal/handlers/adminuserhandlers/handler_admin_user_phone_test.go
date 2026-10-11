package adminuserhandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/phonecountries"
)

// refusedPhoneDescription is the sentence the fake refuses a phone save with.
const refusedPhoneDescription = "The phone number is not valid."

// phoneApiClient answers the user phone page: a user who saved Portugal, and a save the auth
// server refuses as a form error.
type phoneApiClient struct{}

func (phoneApiClient) GetUserById(_ context.Context, _ string, userId int64) (*api.UserResponse, error) {
	return &api.UserResponse{Id: userId, Username: "jdoe", PhoneNumberCountryUniqueId: "PRT_0",
		PhoneNumberCountryCallingCode: "+351", PhoneNumber: "912 345 678"}, nil
}

func (phoneApiClient) UpdateUserPhone(_ context.Context, _ string, _ int64, _ *api.UpdateUserPhoneRequest) (*api.UserResponse, error) {
	return nil, &apiclient.APIError{Code: "VALIDATION_ERROR", Message: refusedPhoneDescription,
		StatusCode: http.StatusBadRequest}
}

// portugal is the core list's entry for Portugal, written out rather than looked up, so the page is
// held to the ids and labels a save stores (#563 decision 1).
var portugal = phonecountries.PhoneCountry{
	UniqueId:    "PRT_0",
	Alpha2:      "PT",
	Emoji:       "🇵🇹",
	CallingCode: "+351",
	Name:        "🇵🇹 - Portugal (+351)",
}

// renderedPhoneCountries is the country list the phone page rendered with.
func renderedPhoneCountries(t *testing.T, bind map[string]interface{}) []phonecountries.PhoneCountry {
	t.Helper()
	rendered, ok := bind["phoneCountries"].([]phonecountries.PhoneCountry)
	require.True(t, ok, "the page renders the core phone country list, got %T", bind["phoneCountries"])
	return rendered
}

// The page builds its country list from core, as the account phone page does, rather than asking
// the admin API for it (#563 decision 1).
func TestHandlePhoneGet_RendersTheCorePhoneCountryList(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_phone.html").Once()

	HandlePhoneGet(httpHelper, newFlashTestStore(), phoneApiClient{}).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/users/42/phone",
			handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", "42")))

	bind := handlertest.Bind(t, httpHelper)
	rendered := renderedPhoneCountries(t, bind)
	assert.Contains(t, rendered, portugal)
	assert.Equal(t, phonecountries.All(), rendered)
	assert.Equal(t, "PRT_0", bind["selectedPhoneCountryUniqueId"])
	assert.Equal(t, "912 345 678", bind["phoneNumber"])
}

// The auth server refuses the save: the form is drawn again under its sentence, with what the
// administrator submitted and the same core list to pick from.
func TestHandlePhonePost_ARefusedSaveKeepsTheCorePhoneCountryList(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_users_phone.html").Once()

	HandlePhonePost(httpHelper, newFlashTestStore(), phoneApiClient{}, consoleBaseURL).ServeHTTP(
		httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/users/42/phone",
			handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", "42"),
			handlertest.WithForm(url.Values{
				"phoneCountryUniqueId": {"PRT_0"},
				"phoneNumber":          {" 912 345 678 "},
			})))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, refusedPhoneDescription, bind["error"])
	rendered := renderedPhoneCountries(t, bind)
	assert.Contains(t, rendered, portugal)
	assert.Equal(t, phonecountries.All(), rendered)
	assert.Equal(t, "PRT_0", bind["selectedPhoneCountryUniqueId"])
	assert.Equal(t, "912 345 678", bind["phoneNumber"])
}
