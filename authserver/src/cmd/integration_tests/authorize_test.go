package integrationtests

import (
	"net/http"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	setup()
}

func TestAuthorize_ClientIdIsMissing(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() + "/auth/authorize/"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The client_id parameter is missing.", errorMsg)
}

func TestAuthorize_ClientDoesNotExist(t *testing.T) {
	setup()
	url := lib.GetBaseUrl() + "/auth/authorize/?client_id=does_not_exist"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "We couldn't find a client associated with the provided client_id.", errorMsg)
}

func TestAuthorize_ClientIsDisabled(t *testing.T) {
	setup()

	err := clientSetEnabled("test-client-1", false)
	if err != nil {
		t.Fatal(err)
	}

	url := viper.GetString("BaseUrl") + "/auth/authorize/?client_id=test-client-1"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	errorMsg := doc.Find("p#errorMsg").Text()
	assert.Equal(t, "The client associated with the provided client_id is not enabled.", errorMsg)

	err = clientSetEnabled("test-client-1", true)
	if err != nil {
		t.Fatal(err)
	}
}
