package integrationtests

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClientSessions_Get_ClientNotFound(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/9999/user-sessions"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 500, resp.StatusCode)
}

func TestAdminClientSessions_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/1/user-sessions"
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

	elem := doc.Find("td:contains('Go-http-client'):contains('Current session')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("li:contains('system-website')")
	assert.Greater(t, elem.Length(), 0)
}

func TestAdminClientSessions_Post(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients/1/user-sessions"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	user, err := database.GetUserByEmail(nil, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}

	userSessions, err := database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	userSessionsCount := len(userSessions)
	userSession := userSessions[userSessionsCount-1]

	data := struct {
		UserSessionId int64 `json:"userSessionId"`
	}{
		UserSessionId: userSession.Id,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}

	destUrl = lib.GetBaseUrl() + "/admin/clients/1/user-sessions/delete"

	req, err := http.NewRequest("POST", destUrl, strings.NewReader(string(jsonData)))
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

	assert.Equal(t, 200, resp.StatusCode)

	responseData := unmarshalToMap(t, resp)
	assert.Equal(t, true, responseData["Success"])

	userSessions, err = database.GetUserSessionsByUserId(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, userSessionsCount-1, len(userSessions))
}
