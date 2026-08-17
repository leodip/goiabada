package integrationtests

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// TestToken_MalformedForm_RequestIdIsConformed proves the token endpoint's conformance boundary
// also covers the error responses that never reach a validator.
//
// A body of "%" is not a valid application/x-www-form-urlencoded document, so r.ParseForm() fails
// before any client is identified and the endpoint answers with the generic server error. That
// description interpolates chi's request id, and chi adopts an inbound X-Request-Id verbatim, so
// without the filter an unauthenticated caller writes their own bytes into a parameter RFC 6749
// Appendix A.8 confines to %x20-21 / %x23-5B / %x5D-7E. Every byte sent below survives Go's header
// parsing on both sides, which is what makes this reachable rather than theoretical (#213).
//
// Driven through the real server so the real middleware chain supplies the request id. The
// character set itself belongs to TestConformErrorDescription in src/core/customerrors; what this
// tier proves is that the boundary is on the path even when the error is not an *ErrorDetail.
func TestToken_MalformedForm_RequestIdIsConformed(t *testing.T) {
	destUrl := config.GetAuthServer().BaseURL + "/auth/token/"

	httpClient := createHttpClient(t)

	request, err := http.NewRequest("POST", destUrl, strings.NewReader("%"))
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

	assert.Equal(t, "server_error", data["error"])

	description, ok := data["error_description"].(string)
	assert.True(t, ok, "error_description must be a string, got %v", data["error_description"])

	for i := 0; i < len(description); i++ {
		b := description[i]
		conforming := (b >= 0x20 && b <= 0x21) || (b >= 0x23 && b <= 0x5B) || (b >= 0x5D && b <= 0x7E)
		assert.True(t, conforming,
			"byte %d of %q is 0x%02x, which RFC 6749 Appendix A.8 excludes from error-description",
			i, description, b)
	}

	// The request id still correlates the response with the server log, one '?' per offending rune.
	assert.Contains(t, description, "Request Id: caller?id?x?y")
}
