package accounthandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/phonecountries"
)

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

// A user who is not an administrator opens their phone page: it renders the core list, with the
// country they saved selected, and asks the admin API for nothing.
func TestHandlePhoneGet_RendersTheCorePhoneCountryListForAUser(t *testing.T) {
	apiClient := manageAccountAuthServer{replies: map[string]string{
		"GET /api/v1/account/profile": `{"user":{"id":7,"phoneNumberCountryUniqueId":"PRT_0",` +
			`"phoneNumberCountryCallingCode":"+351","phoneNumber":"912 345 678"}}`,
	}}.client(t)
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_phone.html").Once()

	HandlePhoneGet(httpHelper, newFlashTestStore(), apiClient).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/account/phone", handlertest.WithAccessToken()))

	bind := handlertest.Bind(t, httpHelper)
	rendered := renderedPhoneCountries(t, bind)
	assert.Contains(t, rendered, portugal)
	assert.Equal(t, phonecountries.All(), rendered)
	assert.Equal(t, "PRT_0", bind["selectedPhoneCountryUniqueId"])
	assert.Equal(t, "912 345 678", bind["phoneNumber"])
}

// The auth server refuses the save: the form is drawn again under its sentence, with what the user
// submitted and the same core list to pick from.
func TestHandlePhonePost_ARefusedSaveKeepsTheCorePhoneCountryList(t *testing.T) {
	apiClient := manageAccountAuthServer{refuseWrites: true}.client(t)
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/account_phone.html").Once()

	HandlePhonePost(httpHelper, newFlashTestStore(), apiClient, consoleBaseURL).ServeHTTP(
		httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/account/phone", handlertest.WithAccessToken(),
			handlertest.WithForm(url.Values{
				"phoneCountryUniqueId": {"PRT_0"},
				"phoneNumber":          {" 912 345 678 "},
			})))

	bind := handlertest.Bind(t, httpHelper)
	assert.Equal(t, refusedFormDescription, bind["error"])
	rendered := renderedPhoneCountries(t, bind)
	assert.Contains(t, rendered, portugal)
	assert.Equal(t, phonecountries.All(), rendered)
	assert.Equal(t, "PRT_0", bind["selectedPhoneCountryUniqueId"])
	assert.Equal(t, "912 345 678", bind["phoneNumber"])
}
