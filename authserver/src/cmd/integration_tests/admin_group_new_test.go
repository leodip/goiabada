package integrationtests

import (
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminGroupNew_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/groups/new"
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

	elem := doc.Find("input[name='gorilla.csrf.Token']").First()
	assert.NotEmpty(t, elem.AttrOr("value", ""))

	elem = doc.Find("input[name='groupIdentifier']").First()
	assert.Empty(t, elem.AttrOr("value", ""))

	elem = doc.Find("input[name='description']").First()
	assert.Empty(t, elem.AttrOr("value", ""))
}

func TestAdminGroupNew_Post_GroupIdentifierIsRequired(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/groups/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/admin/groups/new"
	resp, err = httpClient.PostForm(destUrl, map[string][]string{
		"gorilla.csrf.Token": {csrf},
		"groupIdentifier":    {""},
	})
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains('Group identifier is required')").First()
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupNew_Post_DescriptionIsTooLong(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/groups/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	destUrl = lib.GetBaseUrl() + "/admin/groups/new"
	resp, err = httpClient.PostForm(destUrl, map[string][]string{
		"gorilla.csrf.Token": {csrf},
		"groupIdentifier":    {"test-grp"},
		"description":        {gofakeit.LetterN(101)},
	})
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains('The description cannot exceed a maximum length of 100')").First()
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupNew_Post_IdentifierAlreadyExists(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/groups/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	identifier := "g-" + gofakeit.UUID()

	err = database.CreateGroup(nil, &entities.Group{
		GroupIdentifier: identifier,
		Description:     gofakeit.LetterN(10),
	})
	if err != nil {
		t.Fatalf("Error creating group: %s", err)
	}

	destUrl = lib.GetBaseUrl() + "/admin/groups/new"
	resp, err = httpClient.PostForm(destUrl, map[string][]string{
		"gorilla.csrf.Token": {csrf},
		"groupIdentifier":    {identifier},
		"description":        {gofakeit.LetterN(10)},
	})
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains('The group identifier is already in use')").First()
	assert.Equal(t, 1, elem.Length())
}

func TestAdminGroupNew_Post(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/groups/new"
	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatalf("Error getting %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 200, resp.StatusCode)

	csrf := getCsrfValue(t, resp)

	identifier := "g-" + gofakeit.UUID()

	destUrl = lib.GetBaseUrl() + "/admin/groups/new"
	resp, err = httpClient.PostForm(destUrl, map[string][]string{
		"gorilla.csrf.Token": {csrf},
		"groupIdentifier":    {identifier},
		"description":        {gofakeit.LetterN(10)},
	})
	if err != nil {
		t.Fatalf("Error posting to %s: %s", destUrl, err)
	}
	defer resp.Body.Close()

	assert.Equal(t, 302, resp.StatusCode)

	group, err := database.GetGroupByGroupIdentifier(nil, identifier)
	if err != nil {
		t.Fatalf("Error getting group: %s", err)
	}
	assert.NotNil(t, group)
}
