package integrationtests

import (
	"net/url"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountProfile_Get_NotLoggedIn(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/profile"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/authorize")
}

func TestAccountProfile_Get(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("input[name='username'][value='vivi1']")
	assert.Equal(t, 200, elem.Length())

	elem = doc.Find("input[name='givenName'][value='Viviane']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='middleName'][value='Moura']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='familyName'][value='Albuquerque']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='nickname'][value='Vivi']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("input[name='website'][value='https://vivianealbuquerque.com']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("select[name='gender'] option[value='0']")
	assert.Equal(t, 1, elem.Length())
	_, exists := elem.Attr("selected")
	assert.True(t, exists)

	elem = doc.Find("input[name='dateOfBirth'][value='1975-06-15']")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("select[name='zoneInfo'] option[value='Italy___Europe/Rome']")
	assert.Equal(t, 1, elem.Length())
	_, exists = elem.Attr("selected")
	assert.True(t, exists)

	elem = doc.Find("select[name='zoneInfo'] option")
	assert.Greater(t, elem.Length(), 400)

	elem = doc.Find("select[name='locale'] option[value='it-IT']")
	assert.Equal(t, 1, elem.Length())
	_, exists = elem.Attr("selected")
	assert.True(t, exists)

	elem = doc.Find("select[name='locale'] option")
	assert.Greater(t, elem.Length(), 500)
}

func TestAccountProfile_Post_ZoneInfoInvalidNumberOfParts(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome___Europe/Rome"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAccountProfile_Post_UsernameAlreadyTaken(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome"},
		"username":           {"mauro1"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"Sorry, this username is already taken\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post_InvalidUsername(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	testCases := []struct {
		testCase string
		username string
	}{
		{"Username with spaces", "vivi 1"},
		{"Username with symbol", "vivi$$1"},
		{"Username with dash", "vivi-1"},
		{"Username too long", "vivivivivivivivivivivivivivivivivivi1"},
	}

	for _, tc := range testCases {
		t.Run(tc.testCase, func(t *testing.T) {

			destUrl := lib.GetBaseUrl() + "/account/profile"

			resp, err := httpClient.Get(destUrl)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			csrf := getCsrfValue(t, resp)

			formData := url.Values{
				"zoneInfo":           {"Italy___Europe/Rome"},
				"username":           {tc.username},
				"gorilla.csrf.Token": {csrf},
			}

			resp, err = httpClient.PostForm(destUrl, formData)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			elem := doc.Find("div.text-error p:contains(\"Usernames must start with a letter and consist only of letters, numbers, and underscores\")")
			assert.Equal(t, 1, elem.Length())
		})
	}
}

func TestAccountProfile_Post_GivenNameTooLong(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome"},
		"username":           {"vivi1"},
		"givenName":          {"Long name long name long name long name long name long"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"Please enter a valid given name.\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post_MiddleNameTooLong(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome"},
		"username":           {"vivi1"},
		"givenName":          {"Viviane"},
		"middleName":         {"Long name long name long name long name long name long"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"Please enter a valid middle name.\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post_FamilyNameTooLong(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome"},
		"username":           {"vivi1"},
		"givenName":          {"Viviane"},
		"middleName":         {"Moura"},
		"familyName":         {"Long name long name long name long name long name long"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"Please enter a valid family name.\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post_InvalidNickname(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	testCases := []struct {
		testCase string
		nickname string
	}{
		{"Nickname with spaces", "vivi 1"},
		{"Nickname with symbol", "vivi$$1"},
		{"Nickname with dash", "vivi-1"},
		{"Nickname too long", "vivivivivivivivivivivivivivivivivivi1"},
	}

	for _, tc := range testCases {
		t.Run(tc.testCase, func(t *testing.T) {

			destUrl := lib.GetBaseUrl() + "/account/profile"

			resp, err := httpClient.Get(destUrl)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			csrf := getCsrfValue(t, resp)

			formData := url.Values{
				"zoneInfo":           {"Italy___Europe/Rome"},
				"username":           {"vivi1"},
				"givenName":          {"Viviane"},
				"middleName":         {"Moura"},
				"familyName":         {"Albuquerque"},
				"nickname":           {tc.nickname},
				"gorilla.csrf.Token": {csrf},
			}

			resp, err = httpClient.PostForm(destUrl, formData)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			elem := doc.Find("div.text-error p:contains(\"Nicknames must start with a letter and consist only of letters, numbers, and underscores\")")
			assert.Equal(t, 1, elem.Length())
		})
	}
}

func TestAccountProfile_Post_InvalidWebsite(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	testCases := []struct {
		testCase string
		website  string
	}{
		{"Invalid website 1", "invalid"},
		{"Invalid website 2", "example .com"},
		{"Invalid website 3", "http:\\example.com"},
		{"Invalid website 4", "htp://example.com"},
		{"Invalid website 5", "http://255.255.255.255"},
	}

	for _, tc := range testCases {
		t.Run(tc.testCase, func(t *testing.T) {

			destUrl := lib.GetBaseUrl() + "/account/profile"

			resp, err := httpClient.Get(destUrl)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			csrf := getCsrfValue(t, resp)

			formData := url.Values{
				"zoneInfo":           {"Italy___Europe/Rome"},
				"username":           {"vivi1"},
				"givenName":          {"Viviane"},
				"middleName":         {"Moura"},
				"familyName":         {"Albuquerque"},
				"nickname":           {"Vivi"},
				"website":            {tc.website},
				"gorilla.csrf.Token": {csrf},
			}

			resp, err = httpClient.PostForm(destUrl, formData)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			elem := doc.Find("div.text-error p:contains(\"Please enter a valid website URL\")")
			assert.Equal(t, 1, elem.Length())
		})
	}
}

func TestAccountProfile_Post_WebsiteTooLong(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome"},
		"username":           {"vivi1"},
		"givenName":          {"Viviane"},
		"middleName":         {"Moura"},
		"familyName":         {"Albuquerque"},
		"nickname":           {"Vivi"},
		"website":            {"https://vivianealbuquerquelonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglong.com"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"Please ensure the website URL is no longer than 96 characters\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post_GenderIsInvalid(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome"},
		"username":           {"vivi1"},
		"givenName":          {"Viviane"},
		"middleName":         {"Moura"},
		"familyName":         {"Albuquerque"},
		"nickname":           {"Vivi"},
		"website":            {"https://vivianealbuquerque.com"},
		"gender":             {"10"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"Gender is invalid\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post_InvalidDateOfBirth(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	testCases := []struct {
		testCase string
		dobStr   string
	}{
		{"Invalid date of birth 1", "invalid"},
		{"Invalid date of birth 2", "14/05/1981"},
		{"Invalid date of birth 3", "05/14/1981"},
		{"Invalid date of birth 4", "14 May 1981"},
		{"Invalid date of birth 5", "14th of May 1981"},
	}

	for _, tc := range testCases {
		t.Run(tc.testCase, func(t *testing.T) {

			destUrl := lib.GetBaseUrl() + "/account/profile"

			resp, err := httpClient.Get(destUrl)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			csrf := getCsrfValue(t, resp)

			formData := url.Values{
				"zoneInfo":           {"Italy___Europe/Rome"},
				"username":           {"vivi1"},
				"givenName":          {"Viviane"},
				"middleName":         {"Moura"},
				"familyName":         {"Albuquerque"},
				"nickname":           {"Vivi"},
				"website":            {"https://vivianealbuquerque.com"},
				"gender":             {"0"},
				"dateOfBirth":        {tc.dobStr},
				"gorilla.csrf.Token": {csrf},
			}

			resp, err = httpClient.PostForm(destUrl, formData)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			elem := doc.Find("div.text-error p:contains(\"The date of birth is invalid. Please use the format YYYY-MM-DD\")")
			assert.Equal(t, 1, elem.Length())
		})
	}
}

func TestAccountProfile_Post_DateOfBirthInTheFuture(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome"},
		"username":           {"vivi1"},
		"givenName":          {"Viviane"},
		"middleName":         {"Moura"},
		"familyName":         {"Albuquerque"},
		"nickname":           {"Vivi"},
		"website":            {"https://vivianealbuquerque.com"},
		"gender":             {"0"},
		"dateOfBirth":        {"2100-01-01"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"The date of birth can't be in the future\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post_InvalidZoneInfo(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Invalid"},
		"username":           {"vivi1"},
		"givenName":          {"Viviane"},
		"middleName":         {"Moura"},
		"familyName":         {"Albuquerque"},
		"nickname":           {"Vivi"},
		"website":            {"https://vivianealbuquerque.com"},
		"gender":             {"0"},
		"dateOfBirth":        {"1980-05-14"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"The zone info is invalid\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post_InvalidLocale(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Italy___Europe/Rome"},
		"username":           {"vivi1"},
		"givenName":          {"Viviane"},
		"middleName":         {"Moura"},
		"familyName":         {"Albuquerque"},
		"nickname":           {"Vivi"},
		"website":            {"https://vivianealbuquerque.com"},
		"gender":             {"0"},
		"dateOfBirth":        {"1980-05-14"},
		"locale":             {"Invalid"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	elem := doc.Find("div.text-error p:contains(\"The locale is invalid\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountProfile_Post(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	dob := time.Date(1975, 6, 15, 0, 0, 0, 0, time.UTC)
	user.Username = "vivi1"
	user.GivenName = "Viviane"
	user.MiddleName = "Moura"
	user.FamilyName = "Albuquerque"
	user.Nickname = "Vivi"
	user.Website = "https://vivianealbuquerque.com"
	user.Gender = enums.GenderFemale.String()
	user.BirthDate = &dob
	user.ZoneInfoCountryName = "Italy"
	user.ZoneInfo = "Europe/Rome"
	user.Locale = "it-IT"

	_, err = database.SaveUser(user)
	if err != nil {
		t.Fatal(err)
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/profile"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"zoneInfo":           {"Argentina___America/Argentina/Catamarca"},
		"username":           {"viviB"},
		"givenName":          {"VivianeB"},
		"middleName":         {"MouraB"},
		"familyName":         {"AlbuquerqueB"},
		"nickname":           {"ViviB"},
		"website":            {"https://vivianealbuquerqueB.com"},
		"gender":             {"1"},
		"dateOfBirth":        {"1980-05-15"},
		"locale":             {"pt-BR"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/account/profile")

	// reload user
	user, err = database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "viviB", user.Username)
	assert.Equal(t, "VivianeB", user.GivenName)
	assert.Equal(t, "MouraB", user.MiddleName)
	assert.Equal(t, "AlbuquerqueB", user.FamilyName)
	assert.Equal(t, "ViviB", user.Nickname)
	assert.Equal(t, "https://vivianealbuquerqueB.com", user.Website)
	assert.Equal(t, "male", user.Gender)
	assert.Equal(t, "1980-05-15", user.BirthDate.Format("2006-01-02"))
	assert.Equal(t, "America/Argentina/Catamarca", user.ZoneInfo)
	assert.Equal(t, "Argentina", user.ZoneInfoCountryName)
	assert.Equal(t, "pt-BR", user.Locale)
}
