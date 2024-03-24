package integrationtests

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountUserSessions_Get_NotLoggedIn(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/account/sessions"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assertRedirect(t, resp, "/auth/authorize")
}

func TestAccountUserSessions_Get(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	for _, userSession := range userSessions {
		err = database.DeleteUserSession(nil, userSession.Id)
		if err != nil {
			t.Fatal(err)
		}
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	destUrl := lib.GetBaseUrl() + "/account/sessions"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("table tbody tr td:contains('Go-http-client 1.1 unknown')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("table tbody tr td ul li:contains('system-website')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountUserSessions_Post(t *testing.T) {
	setup()

	user, err := database.GetUserByEmail(nil, "viviane@gmail.com")
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	for _, userSession := range userSessions {
		err = database.DeleteUserSession(nil, userSession.Id)
		if err != nil {
			t.Fatal(err)
		}
	}

	httpClient := loginToAccountArea(t, "viviane@gmail.com", "asd123")

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	destUrl := lib.GetBaseUrl() + "/account/sessions"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(`{"userSessionId": `+strconv.FormatInt(userSessions[0].Id, 10)+`}`))
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

	data := unmarshalToMap(t, resp)
	assert.Equal(t, true, data["Success"])

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, 0, len(userSessions))
}
