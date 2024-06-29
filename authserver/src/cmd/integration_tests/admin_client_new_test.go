package integrationtests

import (
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClientNew_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("span:contains('Client identifier')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("span:contains('Description')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientNew_Post_ClientIdentifierIsMissing(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
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

	elem := doc.Find("div.text-error p:contains('Client identifier is required')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientNew_Post_DescriptionIsTooLong(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"clientIdentifier":   {"test"},
		"description":        {lib.GenerateSecureRandomString(101)},
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

	elem := doc.Find("div.text-error p:contains('The description cannot exceed a maximum length of')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientNew_Post_InvalidIdentifier(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	testCases := []struct {
		clientIdentifier string
		expectedError    string
	}{
		{"test client", "Invalid identifier format"},
		{"aa", "The identifier must be at least"},                                                    // too short
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "The identifier cannot exceed a maximum length"}, // too long
		{"-test", "Invalid identifier format"},
		{"0-test", "Invalid identifier format"},
		{"test$client", "Invalid identifier format"},
		{"test__client", "Invalid identifier format"},
		{"test--client", "Invalid identifier format"},
	}

	for _, tc := range testCases {
		destUrl := lib.GetBaseUrl() + "/admin/clients/new"
		resp, err := httpClient.Get(destUrl)
		if err != nil {
			t.Fatalf("Error getting %s: %s", destUrl, err)
		}
		defer resp.Body.Close()

		assert.Equal(t, 200, resp.StatusCode)

		csrf := getCsrfValue(t, resp)

		formData := url.Values{
			"clientIdentifier":   {tc.clientIdentifier},
			"description":        {lib.GenerateSecureRandomString(10)},
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

		elem := doc.Find("div.text-error p:contains('" + tc.expectedError + "')")
		assert.Equal(t, 1, elem.Length())
	}
}

func TestAdminClientNew_Post_ClientAlreadyExists(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	formData := url.Values{
		"clientIdentifier":   {"test-client-1"},
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

	elem := doc.Find("div.text-error p:contains('The client identifier is already in use')")
	assert.Equal(t, 1, elem.Length())
}

func TestAdminClientNew_Post(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	clientIdentifier := "c" + gofakeit.UUID()
	description := gofakeit.Sentence(4)

	formData := url.Values{
		"clientIdentifier":         {clientIdentifier},
		"description":              {description},
		"authorizationCodeEnabled": {"on"},
		"clientCredentialsEnabled": {"on"},
		"gorilla.csrf.Token":       {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)

	redirectLocation := resp.Header.Get("Location")
	assert.Equal(t, lib.GetBaseUrl()+"/admin/clients", redirectLocation)

	client, err := database.GetClientByClientIdentifier(nil, clientIdentifier)
	if err != nil {
		t.Fatal(err)
	}

	assert.NotNil(t, client)

	assert.Equal(t, clientIdentifier, client.ClientIdentifier)
	assert.Equal(t, description, client.Description)
	assert.True(t, client.AuthorizationCodeEnabled)
	assert.True(t, client.ClientCredentialsEnabled)
	assert.False(t, client.IsPublic)
	assert.False(t, client.ConsentRequired)
	assert.True(t, client.Enabled)
	assert.Equal(t, enums.AcrLevel2, client.DefaultAcrLevel)
}
