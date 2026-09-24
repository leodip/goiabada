package integrationtests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
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
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          models.AcrLevel2Optional,
	}
	err := database.CreateClient(context.Background(), nil, client)
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

// TestToken_UnparseableForm_IsInvalidRequest: a token request whose body will not parse is the
// client's malformed request, RFC 6749 section 5.2's invalid_request, through the real server.
//
// A body of "%" is not a valid application/x-www-form-urlencoded document, and a form larger than
// the endpoint's 64 KiB row in the request-body table is cut by the limit, so r.ParseForm() fails
// before any client is identified in both. Both answered the generic 500 until #426, and the first
// was how #213 reached that arm from outside, with a hostile X-Request-Id the description
// interpolated. The header is still sent: the answer is now a fixed sentence that carries no
// request id at all. The generic arm's own conformance is pinned by
// TestJsonErrorConformed_GenericErrorCarriesNoForbiddenByte, since no request from outside reaches
// it through this path any more.
func TestToken_UnparseableForm_IsInvalidRequest(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	httpClient := createHttpClient(t)

	tests := []struct {
		name string
		body string
	}{
		{"a broken percent-encoding", "%"},
		{"a form over the request-body limit", "grant_type=client_credentials&client_id=a-client&pad=" + strings.Repeat("x", 64<<10)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest("POST", destUrl, strings.NewReader(test.body))
			assert.NoError(t, err)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("X-Request-Id", "caller\U0001F4A3id\"x\\y")

			resp, err := httpClient.Do(request)
			assert.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			assert.NoError(t, err)

			var data map[string]interface{}
			assert.NoError(t, json.Unmarshal(body, &data))

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, "invalid_request", data["error"])
			assert.Equal(t, "The request body could not be parsed.", data["error_description"])
		})
	}
}
