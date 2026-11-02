package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// How the token, revocation and introspection endpoints read the Authorization header, as a client
// sees it over HTTP (#707 decisions 8, 9 and 12): one or more spaces may follow Basic (RFC 9110
// section 11.4); a request with two Authorization fields is refused 400 invalid_request, whether they
// agree or not (RFC 9110 section 5.3, RFC 6749 section 5.2); and a Basic header whose credentials
// cannot be read, or name no client, is refused 401 invalid_client with the Basic challenge, even
// beside right credentials in the body (RFC 6749 section 5.2).

// headerAnswer is what an endpoint answered.
type headerAnswer struct {
	status int
	header http.Header
	body   string
}

// clientAuthEndpoint is one of the three endpoints that authenticate their caller.
type clientAuthEndpoint struct {
	name string
	path string
	// form is a request the client's right credentials get past client authentication with.
	form url.Values
	// assertAuthenticated asserts the answer of a request that got past client authentication.
	assertAuthenticated func(t *testing.T, answer headerAnswer)
}

func clientAuthEndpoints() []clientAuthEndpoint {
	return []clientAuthEndpoint{
		{
			name: "token", path: "/auth/token",
			// The client holds no permission on this scope: past authentication, it is invalid_scope.
			form: url.Values{"grant_type": {"client_credentials"}, "scope": {"no-such-resource:read"}},
			assertAuthenticated: func(t *testing.T, answer headerAnswer) {
				t.Helper()
				require.Equal(t, http.StatusBadRequest, answer.status, answer.body)
				var body map[string]string
				require.NoError(t, json.Unmarshal([]byte(answer.body), &body), answer.body)
				assert.Equal(t, "invalid_scope", body["error"])
			},
		},
		{
			name: "revocation", path: "/auth/revoke",
			// RFC 7009 section 2.2: an invalid token is answered 200, once the client is authenticated.
			form: url.Values{"token": {"not-a-token"}},
			assertAuthenticated: func(t *testing.T, answer headerAnswer) {
				t.Helper()
				require.Equal(t, http.StatusOK, answer.status, answer.body)
				assert.Empty(t, answer.body)
			},
		},
		{
			name: "introspection", path: "/auth/introspect",
			form: url.Values{"token": {"not-a-token"}},
			assertAuthenticated: func(t *testing.T, answer headerAnswer) {
				t.Helper()
				require.Equal(t, http.StatusOK, answer.status, answer.body)
				assert.JSONEq(t, `{"active": false}`, answer.body)
			},
		},
	}
}

// createHeaderClient creates an enabled confidential client of the client credentials grant, with
// a secret of letters alone, so its Basic credentials need no form encoding. Deleted when the test
// ends.
func createHeaderClient(t *testing.T) (*record.Client, string) {
	t.Helper()
	secret := fake.LetterN(32)
	encrypted, err := dataCipher.Encrypt(secret)
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:         "header-client-" + fake.LetterN(8),
		Enabled:                  true,
		ClientCredentialsEnabled: true,
		DefaultAcrLevel:          record.AcrLevel2Optional,
		ClientSecretEncrypted:    encrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	return client, secret
}

// postWithAuthorizationFields posts form to path with one Authorization field per value in fields.
func postWithAuthorizationFields(t *testing.T, path string, form url.Values, fields ...string) headerAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, field := range fields {
		req.Header.Add("Authorization", field)
	}
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return headerAnswer{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

func basicField(spaces, credentials string) string {
	return "Basic" + spaces + base64.StdEncoding.EncodeToString([]byte(credentials))
}

// assertHeaderError asserts answer is an RFC 6749 section 5.2 error with status, code and description.
func assertHeaderError(t *testing.T, answer headerAnswer, status int, code, description string) {
	t.Helper()
	require.Equal(t, status, answer.status, answer.body)
	var body map[string]string
	require.NoError(t, json.Unmarshal([]byte(answer.body), &body), answer.body)
	assert.Equal(t, map[string]string{"error": code, "error_description": description}, body)
}

// Decision 8: Basic followed by two or more spaces authenticates the client, as one space does; until
// #707 the header then counted as absent and the request was refused for a missing client_id.
func TestClientAuthentication_SpacesAfterBasicAuthenticate(t *testing.T) {
	client, secret := createHeaderClient(t)
	credentials := client.ClientIdentifier + ":" + secret

	for _, endpoint := range clientAuthEndpoints() {
		for _, spaces := range []string{" ", "  ", "   "} {
			t.Run(fmt.Sprintf("%s, %d spaces", endpoint.name, len(spaces)), func(t *testing.T) {
				answer := postWithAuthorizationFields(t, endpoint.path, endpoint.form, basicField(spaces, credentials))

				endpoint.assertAuthenticated(t, answer)
			})
		}

		// The header is read after two spaces, so a wrong secret in it is a wrong secret.
		t.Run(endpoint.name+", a wrong secret after two spaces", func(t *testing.T) {
			answer := postWithAuthorizationFields(t, endpoint.path, endpoint.form,
				basicField("  ", client.ClientIdentifier+":not-the-secret"))

			assertHeaderError(t, answer, http.StatusUnauthorized, "invalid_client",
				"Client authentication failed. Please review your client_secret.")
			assert.Equal(t, `Basic realm="goiabada"`, answer.header.Get("WWW-Authenticate"))
		})
	}
}

// Decision 9: two Authorization fields are refused 400 invalid_request with no challenge, whether
// they agree or not; until #707 the first one was read and the others ignored.
func TestClientAuthentication_TwoAuthorizationFieldsAreRefused(t *testing.T) {
	client, secret := createHeaderClient(t)
	right := basicField(" ", client.ClientIdentifier+":"+secret)

	cases := []struct {
		name   string
		fields []string
	}{
		{"two that agree", []string{right, right}},
		{"two that disagree", []string{right, basicField(" ", client.ClientIdentifier+":not-the-secret")}},
		{"a Basic and a Bearer", []string{right, "Bearer a-token"}},
	}
	for _, endpoint := range clientAuthEndpoints() {
		for _, tc := range cases {
			t.Run(endpoint.name+", "+tc.name, func(t *testing.T) {
				answer := postWithAuthorizationFields(t, endpoint.path, endpoint.form, tc.fields...)

				assertHeaderError(t, answer, http.StatusBadRequest, "invalid_request",
					"The request included more than one Authorization header. Send one.")
				assert.Empty(t, answer.header.Get("WWW-Authenticate"))
			})
		}
	}
}

// Decision 12: a Basic header with no credentials, or with credentials that are not base64 or have
// no colon, is refused 401 invalid_client with the Basic challenge, and the body is not read in its
// place: right credentials there do not authenticate the client. Until #707 the header counted as
// absent and the body's credentials authenticated it. Credentials with nothing before the colon name
// no client, and are refused the same way; until #707 they were 400 invalid_request with no challenge.
func TestClientAuthentication_BasicCredentialsNamingNoClientAreRefused(t *testing.T) {
	client, secret := createHeaderClient(t)

	const (
		unreadable = "Client authentication failed: the Basic credentials in the Authorization header could not be read."
		noClient   = "Client authentication failed: the Basic credentials in the Authorization header name no client."
	)
	fields := map[string]struct{ field, description string }{
		"a bare Basic":                        {"Basic", unreadable},
		"credentials that are not base64":     {"Basic not-valid-base64!", unreadable},
		"decoded credentials with no colon":   {basicField(" ", client.ClientIdentifier), unreadable},
		"the secret and no client identifier": {basicField(" ", ":"+secret), noClient},
		"a colon alone":                       {basicField(" ", ":"), noClient},
	}
	for _, endpoint := range clientAuthEndpoints() {
		for name, tc := range fields {
			for _, body := range []bool{false, true} {
				form := url.Values{}
				for key, values := range endpoint.form {
					form[key] = values
				}
				label := endpoint.name + ", " + name
				if body {
					form.Set("client_id", client.ClientIdentifier)
					form.Set("client_secret", secret)
					label += ", right credentials in the body"
				}
				t.Run(label, func(t *testing.T) {
					answer := postWithAuthorizationFields(t, endpoint.path, form, tc.field)

					assertHeaderError(t, answer, http.StatusUnauthorized, "invalid_client", tc.description)
					assert.Equal(t, `Basic realm="goiabada"`, answer.header.Get("WWW-Authenticate"))
				})
			}
		}
	}

	// The control: the same body with no Authorization header authenticates the client.
	for _, endpoint := range clientAuthEndpoints() {
		t.Run(endpoint.name+", the body alone authenticates", func(t *testing.T) {
			form := url.Values{"client_id": {client.ClientIdentifier}, "client_secret": {secret}}
			for key, values := range endpoint.form {
				form[key] = values
			}

			endpoint.assertAuthenticated(t, postWithAuthorizationFields(t, endpoint.path, form))
		})
	}
}
