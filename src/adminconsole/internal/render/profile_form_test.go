package render

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/api"
)

func profileFormRequest(t *testing.T, form url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/account/profile", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// The account profile page and the admin user profile page post the same form. The time-zone
// select's value is the country name and the zone joined by ___, which the request carries apart,
// and the free-text fields are trimmed.
func TestParseProfileForm_BuildsTheUpdateRequest(t *testing.T) {
	r := profileFormRequest(t, url.Values{
		"username":    {"  jdoe "},
		"givenName":   {" Jane"},
		"middleName":  {"Q "},
		"familyName":  {"\tDoe\n"},
		"nickname":    {" JD "},
		"website":     {" https://jane.example "},
		"gender":      {"0"},
		"dateOfBirth": {" 1990-05-17 "},
		"zoneInfo":    {"United States___America/New_York"},
		"locale":      {"pt-BR"},
	})

	got, err := ParseProfileForm(r)

	require.NoError(t, err)
	assert.Equal(t, &api.UpdateUserProfileRequest{
		Username:            "jdoe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "https://jane.example",
		Gender:              "0",
		DateOfBirth:         "1990-05-17",
		ZoneInfoCountryName: "United States",
		ZoneInfo:            "America/New_York",
		Locale:              "pt-BR",
	}, got)
}

// No zone chosen leaves both halves empty, which the API reads as clearing it.
func TestParseProfileForm_NoZoneLeavesBothHalvesEmpty(t *testing.T) {
	got, err := ParseProfileForm(profileFormRequest(t, url.Values{"username": {"jdoe"}}))

	require.NoError(t, err)
	assert.Empty(t, got.ZoneInfoCountryName)
	assert.Empty(t, got.ZoneInfo)
	assert.Equal(t, "jdoe", got.Username)
}

// The select only ever sends a country and a zone joined once. Anything else is a hand-edited
// request, refused as an error, which both pages answer with today's 500 (#440 decision 7).
func TestParseProfileForm_RefusesAZoneValueThatIsNotTwoHalves(t *testing.T) {
	for _, value := range []string{
		"America/New_York",
		"United States___America___New_York",
	} {
		t.Run(value, func(t *testing.T) {
			got, err := ParseProfileForm(profileFormRequest(t, url.Values{"zoneInfo": {value}}))

			require.Error(t, err)
			assert.Nil(t, got)
		})
	}
}

// When the API refuses a profile, the page is rendered again with what the user typed rather than
// what is stored, so nothing they entered is lost.
func TestEchoProfileForm_ShowsTheSubmittedValues(t *testing.T) {
	stored := time.Date(1980, 1, 2, 0, 0, 0, 0, time.UTC)
	user := &api.UserResponse{
		Id:                  4,
		Email:               "jane@example.com",
		Username:            "old",
		GivenName:           "Old",
		MiddleName:          "O",
		FamilyName:          "Name",
		Nickname:            "on",
		Website:             "https://old.example",
		Gender:              "male",
		BirthDate:           &stored,
		ZoneInfoCountryName: "Portugal",
		ZoneInfo:            "Europe/Lisbon",
		Locale:              "en",
	}

	EchoProfileForm(user, &api.UpdateUserProfileRequest{
		Username:            "jdoe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "not a url",
		Gender:              "0",
		DateOfBirth:         "1990-05-17",
		ZoneInfoCountryName: "United States",
		ZoneInfo:            "America/New_York",
		Locale:              "pt-BR",
	})

	wantBirthDate := time.Date(1990, 5, 17, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, &api.UserResponse{
		Id:                  4,
		Email:               "jane@example.com",
		Username:            "jdoe",
		GivenName:           "Jane",
		MiddleName:          "Q",
		FamilyName:          "Doe",
		Nickname:            "JD",
		Website:             "not a url",
		Gender:              "female",
		BirthDate:           &wantBirthDate,
		ZoneInfoCountryName: "United States",
		ZoneInfo:            "America/New_York",
		Locale:              "pt-BR",
	}, user)
}

// An emptied gender or date of birth is shown empty, as submitted.
func TestEchoProfileForm_EmptiedGenderAndBirthDateAreShownEmpty(t *testing.T) {
	stored := time.Date(1980, 1, 2, 0, 0, 0, 0, time.UTC)
	user := &api.UserResponse{Gender: "male", BirthDate: &stored}

	EchoProfileForm(user, &api.UpdateUserProfileRequest{})

	assert.Empty(t, user.Gender)
	assert.Nil(t, user.BirthDate)
}

// A gender or date that does not parse is what the API refused; the page keeps showing the stored
// value for it rather than inventing one.
func TestEchoProfileForm_UnparseableGenderAndBirthDateKeepTheStoredValue(t *testing.T) {
	stored := time.Date(1980, 1, 2, 0, 0, 0, 0, time.UTC)
	user := &api.UserResponse{Gender: "male", BirthDate: &stored}

	EchoProfileForm(user, &api.UpdateUserProfileRequest{Gender: "x", DateOfBirth: "17/05/1990"})

	assert.Equal(t, "male", user.Gender)
	require.NotNil(t, user.BirthDate)
	assert.Equal(t, stored, *user.BirthDate)
}
