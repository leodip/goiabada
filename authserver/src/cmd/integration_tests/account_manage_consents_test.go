package integrationtests

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountManageConsents_Get_NotLoggedIn(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/manage-consents"

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

func TestAccountManageConsents_Get_NoConsents(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	url := lib.GetBaseUrl() + "/account/manage-consents"

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	consents, err := database.GetConsentsByUserId(user.Id)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range consents {
		err := database.DeleteUserConsent(c.Id)
		if err != nil {
			t.Fatal(err)
		}
	}

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains(\"You haven't granted any consents yet\")")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountManageConsents_Get_WithConsents(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	url := lib.GetBaseUrl() + "/account/manage-consents"

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	// delete all consents
	consents, err := database.GetConsentsByUserId(user.Id)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range consents {
		err := database.DeleteUserConsent(c.Id)
		if err != nil {
			t.Fatal(err)
		}
	}

	client, err := database.GetClientByClientIdentifier("test-client-1")
	if err != nil {
		t.Fatal(err)
	}

	// add one consent
	consent := &entities.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email",
		GrantedAt: time.Now(),
	}
	database.SaveUserConsent(consent)

	client, err = database.GetClientByClientIdentifier("test-client-2")
	if err != nil {
		t.Fatal(err)
	}

	// add another consent
	consent = &entities.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email",
		GrantedAt: time.Now(),
	}
	database.SaveUserConsent(consent)

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("tbody tr")
	assert.Equal(t, 2, elem.Length())

	elem = doc.Find("tbody tr td span:contains('test-client-1')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("tbody tr td span:contains('test-client-2')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountManageConsents_Post(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/manage-consents"

	user, err := database.GetUserByEmail("viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	// delete all consents
	consents, err := database.GetConsentsByUserId(user.Id)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range consents {
		err := database.DeleteUserConsent(c.Id)
		if err != nil {
			t.Fatal(err)
		}
	}

	client, err := database.GetClientByClientIdentifier("test-client-1")
	if err != nil {
		t.Fatal(err)
	}

	// add one consent
	consent := &entities.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email",
		GrantedAt: time.Now(),
	}
	database.SaveUserConsent(consent)

	client, err = database.GetClientByClientIdentifier("test-client-2")
	if err != nil {
		t.Fatal(err)
	}

	// add another consent
	consent = &entities.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email",
		GrantedAt: time.Now(),
	}
	database.SaveUserConsent(consent)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/account/manage-consents"

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(fmt.Sprintf(`{"consentId": %d}`, consent.Id)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := unmarshalToMap(t, resp)
	assert.True(t, result["Success"].(bool))

	consents, err = database.GetConsentsByUserId(user.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, 1, len(consents))
	assert.Equal(t, "test-client-1", consents[0].Client.ClientIdentifier)
}

func TestAccountManageConsents_Post_RevokingConsentFromAnotherUser(t *testing.T) {
	setup()

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/manage-consents"

	user, err := database.GetUserByEmail("mauro@outlook.com")
	if err != nil {
		t.Fatal(err)
	}

	// delete all consents
	consents, err := database.GetConsentsByUserId(user.Id)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range consents {
		err := database.DeleteUserConsent(c.Id)
		if err != nil {
			t.Fatal(err)
		}
	}

	client, err := database.GetClientByClientIdentifier("test-client-1")
	if err != nil {
		t.Fatal(err)
	}

	// add one consent
	consent := &entities.UserConsent{
		UserId:    user.Id,
		ClientId:  client.Id,
		Scope:     "openid profile email",
		GrantedAt: time.Now(),
	}
	database.SaveUserConsent(consent)

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/account/manage-consents"

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(fmt.Sprintf(`{"consentId": %d}`, consent.Id)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
