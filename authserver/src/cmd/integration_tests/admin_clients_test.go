package integrationtests

import (
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAdminClients_Get(t *testing.T) {
	setup()

	httpClient := loginToAdminArea(t, "admin@example.com", "changeme")

	destUrl := lib.GetBaseUrl() + "/admin/clients"
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

	elem := doc.Find("table tbody tr td pre:contains('system-website')")
	assert.Equal(t, 1, elem.Length())

	elem = doc.Find("table tbody tr td pre:contains('test-client-1')")
	assert.Equal(t, 1, elem.Length())
}
