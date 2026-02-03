package integrationtests

import (
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

func TestToken_ClientIdIsMissing(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	httpClient := createHttpClient(t)

	formData := url.Values{}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Missing required client_id parameter.", data["error_description"])
}

func TestToken_ClientDoesNotExist(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	httpClient := createHttpClient(t)

	formData := url.Values{
		"client_id": {"invalid"},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "invalid_request", data["error"])
	assert.Equal(t, "Client does not exist.", data["error_description"])
}

func TestToken_InvalidGrantType(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	client := &models.Client{
		ClientIdentifier:         "test-client-" + gofakeit.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
	}
	err := database.CreateClient(nil, client)
	assert.Nil(t, err)

	httpClient := createHttpClient(t)

	formData := url.Values{
		"grant_type": {"invalid_grant_type"},
		"client_id":  {client.ClientIdentifier},
	}
	data := postToTokenEndpoint(t, httpClient, destUrl, formData)

	assert.Equal(t, "unsupported_grant_type", data["error"])
	assert.Equal(t, "Unsupported grant_type.", data["error_description"])
}
