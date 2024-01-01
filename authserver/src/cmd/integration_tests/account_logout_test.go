package integrationtests

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountLogout_WithoutIdTokenHint(t *testing.T) {
	setup()

	_, httpClient := createAuthCode(t, "openid profile email")

	destUrl := lib.GetBaseUrl() + "/auth/logout"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	csrf := getCsrfValue(t, resp)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains('Are you sure you want to logout?')")
	assert.Equal(t, 1, elem.Length())

	formData := url.Values{
		"gorilla.csrf.Token": {csrf},
	}

	resp, err = httpClient.PostForm(destUrl, formData)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	redirectLocation := resp.Header.Get("Location")
	assert.Equal(t, lib.GetBaseUrl(), redirectLocation)
	assert.Equal(t, http.StatusFound, resp.StatusCode)

	// try to access a logged-in only page
	destUrl = lib.GetBaseUrl() + "/account/email"

	resp, err = httpClient.Get(destUrl)

	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	redirectLocation = resp.Header.Get("Location")
	assert.Contains(t, redirectLocation, "/auth/authorize")
}

func TestAccountLogoutWithEncryptedIdTokenHint_MissingPostLogoutRedirectURI(t *testing.T) {
	setup()

	code, httpClient := createAuthCode(t, "openid profile email")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	idToken := respData["id_token"].(string)

	client, err := database.GetClientByClientIdentifier("test-client-1")
	if err != nil {
		t.Fatal(err)
	}

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}

	clientSecret, err = lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	idTokenEncrypted := aesGcmEncryption(t, idToken, clientSecret)

	destUrl = lib.GetBaseUrl() + "/auth/logout?id_token_hint=" + url.QueryEscape(idTokenEncrypted) +
		"&client_id=test-client-1" +
		"&state=XYZ123"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains('The post_logout_redirect_uri parameter is required')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountLogout_WithEncryptedIdTokenHint_InhvalidPostLogoutRedirectURI(t *testing.T) {
	setup()

	code, httpClient := createAuthCode(t, "openid profile email")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	idToken := respData["id_token"].(string)

	client, err := database.GetClientByClientIdentifier("test-client-1")
	if err != nil {
		t.Fatal(err)
	}

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}

	clientSecret, err = lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	idTokenEncrypted := aesGcmEncryption(t, idToken, clientSecret)

	destUrl = lib.GetBaseUrl() + "/auth/logout?id_token_hint=" + url.QueryEscape(idTokenEncrypted) +
		"&post_logout_redirect_uri=https://example.com" +
		"&client_id=test-client-1" +
		"&state=XYZ123"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	elem := doc.Find("p:contains('The post_logout_redirect_uri parameter is invalid')")
	assert.Equal(t, 1, elem.Length())
}

func TestAccountLogout_WithEncryptedIdTokenHint(t *testing.T) {
	setup()

	code, httpClient := createAuthCode(t, "openid profile email")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	idToken := respData["id_token"].(string)

	client, err := database.GetClientByClientIdentifier("test-client-1")
	if err != nil {
		t.Fatal(err)
	}

	settings, err := database.GetSettings()
	if err != nil {
		t.Fatal(err)
	}

	clientSecret, err = lib.DecryptText(client.ClientSecretEncrypted, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	idTokenEncrypted := aesGcmEncryption(t, idToken, clientSecret)

	destUrl = lib.GetBaseUrl() + "/auth/logout?id_token_hint=" + url.QueryEscape(idTokenEncrypted) +
		"&post_logout_redirect_uri=https://oauthdebugger.com/debug" +
		"&client_id=test-client-1" +
		"&state=XYZ123"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	redirectLocation := resp.Header.Get("Location")
	assert.Contains(t, redirectLocation, "https://oauthdebugger.com/debug")
	assert.Contains(t, redirectLocation, "state=XYZ123")
	assert.Contains(t, redirectLocation, "sid=")
}

func TestAccountLogout_WithUnencryptedIdTokenHint(t *testing.T) {
	setup()

	code, httpClient := createAuthCode(t, "openid profile email")

	destUrl := lib.GetBaseUrl() + "/auth/token"

	clientSecret := getClientSecret(t, "test-client-1")

	formData := url.Values{
		"client_id":     {"test-client-1"},
		"client_secret": {clientSecret},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {code.RedirectURI},
		"code":          {code.Code},
		"code_verifier": {"DdazqdVNuDmRLGGRGQKKehEaoFeatACtNsM2UYGwuHkhBhDsTSzaCqWttcBc0kGx"},
	}
	respData := postToTokenEndpoint(t, httpClient, destUrl, formData)
	idToken := respData["id_token"].(string)

	destUrl = lib.GetBaseUrl() + "/auth/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=https://oauthdebugger.com/debug" +
		"&state=XYZ123"

	resp, err := httpClient.Get(destUrl)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	redirectLocation := resp.Header.Get("Location")
	assert.Contains(t, redirectLocation, "https://oauthdebugger.com/debug")
	assert.Contains(t, redirectLocation, "state=XYZ123")
	assert.Contains(t, redirectLocation, "sid=")
}
