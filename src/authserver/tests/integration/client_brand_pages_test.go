package integration

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A sign-in's pages are drawn in the brand of the client it is for: every step, the error pages
// shown once the client is known, and the form_post page that delivers its answer, a code or an
// error. An error shown before the client is known, the page saying a sign-in is no longer active,
// and another client's sign-in stay in the default brand (#812).
//
// Each test makes a dark Plum brand the default and gives its client a light Avocado brand, so a
// page drawn in the wrong one fails on its data-theme, its color-scheme and its stylesheet alike.

// giveClientBrand creates a brand with appearance and theme and gives it to client. The brand is
// deleted when the test ends, which puts the client back on the default.
func giveClientBrand(t *testing.T, client *record.Client, appearance record.BrandAppearance, theme string) *record.Brand {
	t.Helper()
	ctx := context.Background()

	brand := &record.Brand{Name: "Client " + fake.LetterN(10), Appearance: appearance, Theme: theme}
	require.NoError(t, database.CreateBrand(ctx, nil, brand))
	t.Cleanup(func() {
		assert.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			_, err := database.DeleteBrand(ctx, tx, brand.Id)
			return err
		}), "unable to delete the client's brand")
	})

	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		_, err := database.SetClientBrand(ctx, tx, client.Id, sql.NullInt64{Int64: brand.Id, Valid: true})
		return err
	}))
	return brand
}

// assertDrawnInBrand asserts a page's head draws it in brand: dataTheme on the html element and in
// the color-scheme meta, and the brand's stylesheet linked after main.css.
func assertDrawnInBrand(t *testing.T, resp *http.Response, brand *record.Brand, dataTheme string) {
	t.Helper()
	head := readBrandedPageHead(t, resp)
	assert.Equal(t, dataTheme, head.dataTheme, "data-theme")
	assert.Equal(t, dataTheme, head.colorScheme, "color-scheme")
	if assert.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet") {
		assert.Regexp(t, `^/static/main\.css\?v=[0-9a-f]{12}$`, head.stylesheets[0])
		assert.Regexp(t, `^/brand/`+strconv.FormatInt(brand.Id, 10)+`/stylesheet\.css\?v=[0-9a-f]{12}$`,
			head.stylesheets[1])
	}
}

// brandedSignInClient is a client given the light Avocado brand, with the authorization code flow on
// and consent required, and its one redirect URI.
func brandedSignInClient(t *testing.T, acrLevel record.AcrLevel) (*record.Client, *record.Brand, string) {
	t.Helper()
	client, redirectURI := brandSignInClient(t, acrLevel)
	return client, giveClientBrand(t, client, record.BrandAppearanceLight, "avocado"), redirectURI
}

// brandSignInClient is a client with no brand of its own, with the authorization code flow on and consent
// required, and its one redirect URI.
func brandSignInClient(t *testing.T, acrLevel record.AcrLevel) (*record.Client, string) {
	t.Helper()
	ctx := context.Background()
	client := &record.Client{
		ClientIdentifier:         "brand-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          acrLevel,
	}
	require.NoError(t, database.CreateClient(ctx, nil, client))
	redirectURI := "https://brand.example.com/callback"
	require.NoError(t, database.CreateRedirectURI(ctx, nil, &record.RedirectURI{ClientId: client.Id, URI: redirectURI}))
	return client, redirectURI
}

// brandSignInUser is an enabled user with a password, and a one-time code when otpSecret is not empty.
func brandSignInUser(t *testing.T, otpSecret string) (*record.User, string) {
	t.Helper()
	password := fake.Password(10)
	hashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: hashed}
	if otpSecret != "" {
		user.OTPSecretEncrypted = encryptOTPSecretForTest(t, otpSecret)
		user.OTPEnabled = true
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	return user, password
}

// brandAuthorizeURL is an authorization request of client for a code, at redirectURI, delivered in
// responseMode, or the query when it is empty.
func brandAuthorizeURL(client *record.Client, redirectURI string, responseMode string) string {
	params := url.Values{
		"client_id":             {client.ClientIdentifier},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {randomCodeChallenge()},
		"scope":                 {"openid profile email"},
		"state":                 {fake.LetterN(8)},
		"nonce":                 {fake.LetterN(8)},
	}
	if responseMode != "" {
		params.Set("response_mode", responseMode)
	}
	return appConfig.AuthServer.BaseURL + "/auth/authorize?" + params.Encode()
}

// brandFollowTo loads the redirect resp answers with, which must lead to path, closing resp, and answers
// the page there and its URL.
func brandFollowTo(t *testing.T, browser *http.Client, resp *http.Response, path string) (*http.Response, string) {
	t.Helper()
	location := assertRedirect(t, resp, path)
	_ = resp.Body.Close()
	return loadPage(t, browser, location), location
}

func TestSignInPages_AreDrawnInTheClientsBrand(t *testing.T) {
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, clientBrand, redirectURI := brandedSignInClient(t, record.AcrLevel1)
	user, password := brandSignInUser(t, "")
	browser := createHttpClient(t)

	resp := loadPage(t, browser, brandAuthorizeURL(client, redirectURI, "form_post"))
	resp, _ = brandFollowTo(t, browser, resp, "/auth/level1")
	pwdPage, pwdURL := brandFollowTo(t, browser, resp, "/auth/pwd")
	t.Run("the password page", func(t *testing.T) {
		require.Equal(t, http.StatusOK, pwdPage.StatusCode)
		assertDrawnInBrand(t, pwdPage, clientBrand, "light")
	})

	// A wrong password is answered on the password page again, from the form's POST.
	refused := authenticateWithPassword(t, browser, pwdURL, pwdPage, user.Email, "not-"+password)
	_ = pwdPage.Body.Close()
	t.Run("the password page refusing a wrong password", func(t *testing.T) {
		require.Equal(t, http.StatusOK, refused.StatusCode)
		assertDrawnInBrand(t, refused, clientBrand, "light")
	})

	resp = authenticateWithPassword(t, browser, pwdURL, refused, user.Email, password)
	_ = refused.Body.Close()
	resp, _ = brandFollowTo(t, browser, resp, "/auth/level1completed")
	resp, _ = brandFollowTo(t, browser, resp, "/auth/completed")
	consentPage, consentURL := brandFollowTo(t, browser, resp, "/auth/consent")
	defer func() { _ = consentPage.Body.Close() }()
	t.Run("the consent page", func(t *testing.T) {
		require.Equal(t, http.StatusOK, consentPage.StatusCode)
		assertDrawnInBrand(t, consentPage, clientBrand, "light")
	})

	t.Run("the page refusing a step the sign-in has passed", func(t *testing.T) {
		page := loadPage(t, browser, stepURLOfTheSameCeremony(t, consentURL, "/auth/pwd"))
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusBadRequest, page.StatusCode)
		assertDrawnInBrand(t, page, clientBrand, "light")
	})

	// The page saying a sign-in is no longer active acts on no sign-in, whatever the browser holds.
	t.Run("the page saying a sign-in is no longer active", func(t *testing.T) {
		page := loadPage(t, browser, appConfig.AuthServer.BaseURL+"/auth/pwd?"+
			url.Values{ceremony.QueryParameter: {ceremony.NewId()}}.Encode())
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusBadRequest, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
	})

	resp = postConsent(t, browser, consentURL, consentPage, consentIndices(t, consentPage))
	formPost, _ := brandFollowTo(t, browser, resp, "/auth/issue")
	defer func() { _ = formPost.Body.Close() }()
	t.Run("the form_post page delivering the code", func(t *testing.T) {
		require.Equal(t, http.StatusOK, formPost.StatusCode)
		doc := parseHTMLResponse(t, formPost)
		code, _ := doc.Find(`form input[name="code"]`).Attr("value")
		require.NotEmpty(t, code, "the page carries the code")
		assertDrawnInBrand(t, formPost, clientBrand, "light")
	})

	// Another client's sign-in, in another browser, keeps the default brand.
	t.Run("another client's password page", func(t *testing.T) {
		other, otherRedirectURI := brandSignInClient(t, record.AcrLevel1)
		otherBrowser := createHttpClient(t)
		page := loadPage(t, otherBrowser, brandAuthorizeURL(other, otherRedirectURI, ""))
		page, _ = brandFollowTo(t, otherBrowser, page, "/auth/level1")
		page, _ = brandFollowTo(t, otherBrowser, page, "/auth/pwd")
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, defaultBrand, "dark")
	})
}

// The one-time code step is drawn in the client's brand, its page and its refusal of a wrong code
// alike; the same step of a client with no brand of its own keeps the default.
func TestSignInPages_TheOneTimeCodeStepIsDrawnInTheClientsBrand(t *testing.T) {
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	otpSecret := newOTPSecretForTest(t, "brand@example.com")
	user, password := brandSignInUser(t, otpSecret)

	branded, clientBrand, brandedRedirectURI := brandedSignInClient(t, record.AcrLevel2Mandatory)
	plain, plainRedirectURI := brandSignInClient(t, record.AcrLevel2Mandatory)

	for _, tc := range []struct {
		name        string
		client      *record.Client
		redirectURI string
		brand       *record.Brand
		dataTheme   string
	}{
		{"a client with a brand of its own", branded, brandedRedirectURI, clientBrand, "light"},
		{"a client on the default brand", plain, plainRedirectURI, defaultBrand, "dark"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			browser := createHttpClient(t)
			otpPage := navigateToOtpScreen(t, browser, tc.client, user, password, tc.redirectURI)
			otpURL := otpPage.Request.URL.String()
			require.Equal(t, http.StatusOK, otpPage.StatusCode)
			assertDrawnInBrand(t, otpPage, tc.brand, tc.dataTheme)

			wrong := otptest.Code(t, otpSecret, time.Now().Add(-10*time.Minute))
			refused := authenticateWithOtp(t, browser, otpURL, otpPage, wrong)
			_ = otpPage.Body.Close()
			defer func() { _ = refused.Body.Close() }()
			require.Equal(t, http.StatusOK, refused.StatusCode)
			assertDrawnInBrand(t, refused, tc.brand, tc.dataTheme)
		})
	}
}

// An authorization request refused once its client is known is answered in the client's brand,
// whether on the refusal page or by a form_post to the client, and also when the client is disabled.
// One refused before its client is read, or naming no client, is answered in the default brand.
func TestAuthorizeRefusals_AreDrawnInTheClientsBrandOnceTheClientIsKnown(t *testing.T) {
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, clientBrand, redirectURI := brandedSignInClient(t, record.AcrLevel1)

	disabled, _ := brandSignInClient(t, record.AcrLevel1)
	disabled.Enabled = false
	require.NoError(t, database.UpdateClient(context.Background(), nil, disabled))
	disabledBrand := giveClientBrand(t, disabled, record.BrandAppearanceLight, "avocado")

	withParams := func(raw string, change func(params url.Values)) string {
		parsed, err := url.Parse(raw)
		require.NoError(t, err)
		params := parsed.Query()
		change(params)
		parsed.RawQuery = params.Encode()
		return parsed.String()
	}

	for _, tc := range []struct {
		name       string
		target     string
		wantStatus int
		brand      *record.Brand
		dataTheme  string
	}{
		{
			name:       "a disabled client",
			target:     brandAuthorizeURL(disabled, redirectURI, ""),
			wantStatus: http.StatusOK,
			brand:      disabledBrand,
			dataTheme:  "light",
		},
		{
			name:       "a redirect_uri the client did not register",
			target:     brandAuthorizeURL(client, "https://elsewhere.example.com/callback", ""),
			wantStatus: http.StatusOK,
			brand:      clientBrand,
			dataTheme:  "light",
		},
		{
			name:       "an unsupported response_mode",
			target:     brandAuthorizeURL(client, redirectURI, "no-such-mode"),
			wantStatus: http.StatusBadRequest,
			brand:      clientBrand,
			dataTheme:  "light",
		},
		{
			name: "an error delivered by form_post",
			target: withParams(brandAuthorizeURL(client, redirectURI, "form_post"), func(params url.Values) {
				params.Set("prompt", "none")
			}),
			wantStatus: http.StatusOK,
			brand:      clientBrand,
			dataTheme:  "light",
		},
		{
			name: "a client_id that names no client",
			target: withParams(brandAuthorizeURL(client, redirectURI, ""), func(params url.Values) {
				params.Set("client_id", "no-such-client-"+fake.LetterN(8))
			}),
			wantStatus: http.StatusOK,
			brand:      defaultBrand,
			dataTheme:  "dark",
		},
		{
			name: "a request refused before its client is read",
			target: withParams(brandAuthorizeURL(client, redirectURI, ""), func(params url.Values) {
				params.Add("redirect_uri", redirectURI)
			}),
			wantStatus: http.StatusBadRequest,
			brand:      defaultBrand,
			dataTheme:  "dark",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := loadPage(t, createHttpClient(t), tc.target)
			defer func() { _ = resp.Body.Close() }()
			require.Equal(t, tc.wantStatus, resp.StatusCode)
			assertDrawnInBrand(t, resp, tc.brand, tc.dataTheme)
		})
	}
}
