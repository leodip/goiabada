package handlers

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
)

func TestParseBasicAuth(t *testing.T) {
	t.Run("Empty header returns false", func(t *testing.T) {
		clientId, clientSecret, ok, err := parseBasicAuth("")
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Non-Basic scheme returns false", func(t *testing.T) {
		clientId, clientSecret, ok, err := parseBasicAuth("Bearer some-token")
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("The scheme name is case-insensitive", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		for _, scheme := range []string{"basic", "BASIC", "bAsIc"} {
			clientId, clientSecret, ok, err := parseBasicAuth(scheme + " " + encoded)
			require.NoError(t, err)
			assert.True(t, ok, scheme)
			assert.Equal(t, "client", clientId, scheme)
			assert.Equal(t, "secret", clientSecret, scheme)
		}
	})

	t.Run("A longer scheme name is not Basic", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		_, _, ok, err := parseBasicAuth("Basicx " + encoded)
		assert.False(t, ok)
		require.NoError(t, err)
	})

	// #707 decision 12: Basic credentials that cannot be read are refused, not taken for no header.
	t.Run("Unreadable Basic credentials are invalid_client", func(t *testing.T) {
		for _, header := range []string{
			"Basic not-valid-base64!",
			"Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")),
			"Basic",
			"Basic ",
		} {
			clientId, clientSecret, ok, err := parseBasicAuth(header)
			assert.False(t, ok, header)
			assert.Empty(t, clientId, header)
			assert.Empty(t, clientSecret, header)
			var errDetail *oauth.ErrorDetail
			require.ErrorAs(t, err, &errDetail, header)
			assert.Equal(t, "invalid_client", errDetail.Code(), header)
			assert.Equal(t, http.StatusUnauthorized, errDetail.HTTPStatus(), header)
		}
	})

	t.Run("Valid credentials are parsed correctly", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("my-client-id:my-secret"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "my-client-id", clientId)
		assert.Equal(t, "my-secret", clientSecret)
	})

	// RFC 6749 section 2.3.1: the client form-urlencodes both values before it joins them, which
	// openid-client does, escaping even '-', '.' and '_'. Every generated secret holds those.
	t.Run("Form-urlencoded credentials are decoded", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("my%2Dclient%5Fid:s3cr%2Et%2Dwith%2Bplus%3Aand%25+a+space"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "my-client_id", clientId)
		assert.Equal(t, "s3cr.t-with+plus:and% a space", clientSecret)
	})

	// Preserve the legacy fallback only when form decoding fails on a malformed percent escape.
	t.Run("A malformed escape keeps the unencoded value", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("my-client:a+b/c=d%zz"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "my-client", clientId)
		assert.Equal(t, "a+b/c=d%zz", clientSecret)
	})

	t.Run("A plus in either encoded value is a space", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("my+client:a+b%2Bc"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "my client", clientId)
		assert.Equal(t, "a b+c", clientSecret)
	})

	t.Run("Password with colons is parsed correctly", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:pass:with:colons"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "client", clientId)
		assert.Equal(t, "pass:with:colons", clientSecret)
	})

	t.Run("Empty password is valid", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "client", clientId)
		assert.Empty(t, clientSecret)
	})

	// RFC 6749 section 5.2: the client tried the header, so credentials naming no client are a failed
	// client authentication, 401 invalid_client, not a missing client_id.
	t.Run("Basic credentials naming no client are invalid_client", func(t *testing.T) {
		for _, credentials := range []string{":secret", ":"} {
			encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
			clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
			assert.False(t, ok, credentials)
			assert.Empty(t, clientId, credentials)
			assert.Empty(t, clientSecret, credentials)
			var errDetail *oauth.ErrorDetail
			require.ErrorAs(t, err, &errDetail, credentials)
			assert.Equal(t, "invalid_client", errDetail.Code(), credentials)
			assert.Equal(t, http.StatusUnauthorized, errDetail.HTTPStatus(), credentials)
			assert.Equal(t, "Client authentication failed: the Basic credentials in the Authorization header name no client.",
				errDetail.Description(), credentials)
		}
	})

	t.Run("Special characters in credentials", func(t *testing.T) {
		// Test with special chars that might cause issues
		encoded := base64.StdEncoding.EncodeToString([]byte("client%2Bid%40example.com:p%40ss%3Dword%26special%21"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "client+id@example.com", clientId)
		assert.Equal(t, "p@ss=word&special!", clientSecret)
	})

	t.Run("Unicode characters in credentials", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("клиент:密码"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "клиент", clientId)
		assert.Equal(t, "密码", clientSecret)
	})

	// RFC 9110 section 11.4: one or more spaces follow the scheme (#707 decision 8).
	t.Run("Two spaces after Basic are read", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic  " + encoded) // two spaces
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, "client", clientId)
		assert.Equal(t, "secret", clientSecret)
	})

	t.Run("Missing space after Basic is another scheme", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("client:secret"))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic" + encoded) // no space
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Very long credentials", func(t *testing.T) {
		longClientId := strings.Repeat("a", 1000)
		longSecret := strings.Repeat("b", 1000)
		encoded := base64.StdEncoding.EncodeToString([]byte(longClientId + ":" + longSecret))
		clientId, clientSecret, ok, err := parseBasicAuth("Basic " + encoded)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, longClientId, clientId)
		assert.Equal(t, longSecret, clientSecret)
	})
}

func TestExtractClientCredentials(t *testing.T) {
	t.Run("Basic auth only - credentials extracted from header", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		req, _ := http.NewRequest("POST", "/token", strings.NewReader("grant_type=client_credentials"))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		require.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
	})

	t.Run("POST body only - credentials extracted from form", func(t *testing.T) {
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		require.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
	})

	t.Run("Both methods provided - returns error", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		require.Error(t, err)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)

		var errDetail *oauth.ErrorDetail
		ok := errors.As(err, &errDetail)
		assert.True(t, ok)
		assert.Equal(t, "invalid_request", errDetail.Code())
		assert.Contains(t, errDetail.Description(), "multiple authentication methods")
	})

	t.Run("No credentials provided - returns empty values", func(t *testing.T) {
		formData := "grant_type=authorization_code&code=test"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		require.NoError(t, err)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
	})

	t.Run("Basic auth with client_id in POST but no client_secret - allowed", func(t *testing.T) {
		// This is allowed because only client_secret in POST triggers the conflict
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		require.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
	})

	// #707 decision 12: the client tried the header, so the body is not read in its place.
	t.Run("Invalid Basic auth header is refused, the POST body unread", func(t *testing.T) {
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic invalid-base64!")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		assert.Empty(t, clientId)
		assert.Empty(t, clientSecret)
		var errDetail *oauth.ErrorDetail
		require.ErrorAs(t, err, &errDetail)
		assert.Equal(t, "invalid_client", errDetail.Code())
	})

	t.Run("Bearer token header does not interfere with POST body", func(t *testing.T) {
		// A Bearer token should not be treated as Basic auth
		formData := "grant_type=client_credentials&client_id=post-client&client_secret=post-secret"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer some-access-token")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		require.NoError(t, err)
		assert.Equal(t, "post-client", clientId)
		assert.Equal(t, "post-secret", clientSecret)
	})

	t.Run("Empty client_secret in POST body is not considered authentication", func(t *testing.T) {
		// Empty string for client_secret should not trigger the "multiple methods" error
		encoded := base64.StdEncoding.EncodeToString([]byte("basic-client:basic-secret"))
		formData := "grant_type=client_credentials&client_id=post-client&client_secret="
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Basic "+encoded)
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		require.NoError(t, err)
		assert.Equal(t, "basic-client", clientId)
		assert.Equal(t, "basic-secret", clientSecret)
	})

	t.Run("Public client - only client_id in POST, no secret", func(t *testing.T) {
		formData := "grant_type=authorization_code&client_id=public-client&code=auth-code"
		req, _ := http.NewRequest("POST", "/token", strings.NewReader(formData))
		req = withSettings(req, &record.Settings{})
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		clientId, clientSecret, err := extractClientCredentials(req)
		require.NoError(t, err)
		assert.Equal(t, "public-client", clientId)
		assert.Empty(t, clientSecret)
	})
}
