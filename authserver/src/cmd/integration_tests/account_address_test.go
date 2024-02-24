package integrationtests

import (
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountAddress_Get_NotLoggedIn(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/address"

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

func TestAccountAddress_Get(t *testing.T) {
	setup()
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	user.AddressLine1 = "Rua Lauro Muller 125"
	user.AddressLine2 = "Apto 1001"
	user.AddressLocality = "Rio de Janeiro"
	user.AddressRegion = "RJ"
	user.AddressPostalCode = "22290-160"
	user.AddressCountry = "BRA"
	err = database.UpdateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/address"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("input[name='addressLine1']")
	assert.Equal(t, "Rua Lauro Muller 125", elem.AttrOr("value", ""))

	elem = doc.Find("input[name='addressLine2']")
	assert.Equal(t, "Apto 1001", elem.AttrOr("value", ""))

	elem = doc.Find("input[name='addressLocality']")
	assert.Equal(t, "Rio de Janeiro", elem.AttrOr("value", ""))

	elem = doc.Find("input[name='addressRegion']")
	assert.Equal(t, "RJ", elem.AttrOr("value", ""))

	elem = doc.Find("input[name='addressPostalCode']")
	assert.Equal(t, "22290-160", elem.AttrOr("value", ""))

	elem = doc.Find("select[name='addressCountry'] option[selected='']")
	assert.Equal(t, "BRA", elem.AttrOr("value", ""))

	elem = doc.Find("select[name='addressCountry'] option")
	assert.Greater(t, elem.Length(), 250) // number of countries in dropdown
}

func TestAccountAddress_Post_MaxLength(t *testing.T) {
	setup()
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/address"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// address line 1
	csrf := getCsrfValue(t, resp)
	formData := url.Values{
		"addressLine1":       {lib.GenerateSecureRandomString(61)},
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

	elem := doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Please ensure the address line 1 is no longer than 60 characters")

	// address line 2
	formData = url.Values{
		"addressLine1":       {"Rua da Silva 100"},
		"addressLine2":       {lib.GenerateSecureRandomString(61)},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem = doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Please ensure the address line 2 is no longer than 60 characters")

	// locality
	formData = url.Values{
		"addressLine1":       {"Rua da Silva 100"},
		"addressLine2":       {"Something else"},
		"addressLocality":    {lib.GenerateSecureRandomString(61)},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem = doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Please ensure the locality is no longer than 60 characters")

	// region
	formData = url.Values{
		"addressLine1":       {"Rua da Silva 100"},
		"addressLine2":       {"Something else"},
		"addressLocality":    {"Rio de Janeiro"},
		"addressRegion":      {lib.GenerateSecureRandomString(61)},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem = doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Please ensure the region is no longer than 60 characters")

	// postal code
	formData = url.Values{
		"addressLine1":       {"Rua da Silva 100"},
		"addressLine2":       {"Something else"},
		"addressLocality":    {"Rio de Janeiro"},
		"addressRegion":      {"RJ"},
		"addressPostalCode":  {lib.GenerateSecureRandomString(31)},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err = goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem = doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Please ensure the postal code is no longer than 30 characters")
}

func TestAccountAddress_Post_InvalidCountry(t *testing.T) {
	setup()
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/address"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"addressLine1":       {"Rua da Silva 100"},
		"addressLine2":       {"Something else"},
		"addressLocality":    {"Rio de Janeiro"},
		"addressRegion":      {"RJ"},
		"addressPostalCode":  {"22290-160"},
		"addressCountry":     {"invalid"},
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

	elem := doc.Find("div.text-error p")
	assert.Contains(t, elem.Text(), "Invalid country")
}

func TestAccountAddress_Post(t *testing.T) {
	setup()
	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/address"

	resp, err := httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"addressLine1":       {"Rua do João 100 "},
		"addressLine2":       {"Alguma zona  "},
		"addressLocality":    {"São Paulo    "},
		"addressRegion":      {"SP  "},
		"addressPostalCode":  {"22111-222  "},
		"addressCountry":     {"ARG"},
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/account/address")
	destUrl = resp.Header.Get("Location")

	resp, err = httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("input[name='addressLine1']")
	assert.Equal(t, "Rua do João 100", elem.AttrOr("value", ""))

	elem = doc.Find("input[name='addressLine2']")
	assert.Equal(t, "Alguma zona", elem.AttrOr("value", ""))

	elem = doc.Find("input[name='addressLocality']")
	assert.Equal(t, "São Paulo", elem.AttrOr("value", ""))

	elem = doc.Find("input[name='addressRegion']")
	assert.Equal(t, "SP", elem.AttrOr("value", ""))

	elem = doc.Find("input[name='addressPostalCode']")
	assert.Equal(t, "22111-222", elem.AttrOr("value", ""))

	elem = doc.Find("select[name='addressCountry'] option[selected='']")
	assert.Equal(t, "ARG", elem.AttrOr("value", ""))

	elem = doc.Find("div.text-success p")
	assert.Contains(t, elem.Text(), "Address saved successfully")
}
