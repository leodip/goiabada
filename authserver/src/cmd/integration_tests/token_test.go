package integrationtests

import (
	"net/url"
	"testing"

	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestToken_MissingClientId(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	formData := url.Values{}
	data := postToTokenEndpoint(t, client, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required client_id parameter.", data["error_description"])
}

func TestToken_InvalidGrantType(t *testing.T) {
	setup()

	destUrl := lib.GetBaseUrl() + "/auth/token"

	client := createHttpClient(&createHttpClientInput{
		T:               t,
		FollowRedirects: true,
		IgnoreTLSErrors: true,
	})

	formData := url.Values{
		"client_id":  {"test-client-1"},
		"grant_type": {"invalid"},
	}
	data := postToTokenEndpoint(t, client, destUrl, formData)

	assert.Equal(t, "unsupported_grant_type", data["error"])
	assert.Equal(t, "Unsupported grant_type.", data["error_description"])
}
