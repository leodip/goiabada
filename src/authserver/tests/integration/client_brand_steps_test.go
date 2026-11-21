package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/otp/otptest"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The legal acceptance step is drawn in the brand of the client the sign-in is for, its page and
// the page showing it again for a box left unticked alike; the same step of a client with no brand
// of its own keeps the default (#812).
func TestSignInPages_TheLegalAcceptanceStepIsDrawnInTheClientsBrand(t *testing.T) {
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	branded := newLegalAcceptanceFixture(t)
	clientBrand := giveClientBrand(t, branded.client, record.BrandAppearanceLight, "avocado")
	plain := newLegalAcceptanceApp(t, branded.user, branded.password, branded.adminToken)

	for _, tc := range []struct {
		name      string
		app       *legalAcceptanceFixture
		brand     *record.Brand
		dataTheme string
	}{
		{"a client with a brand of its own", branded, clientBrand, "light"},
		{"a client on the default brand", plain, defaultBrand, "dark"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.app.mustAcceptFor(t, "brand", "Brand terms")
			browser := createHTTPClient(t)

			page, stepURL := toStep(t, browser, tc.app.signInToCompleted(t, browser))
			assertDrawnInBrand(t, page, tc.brand, tc.dataTheme)

			again := postStep(t, browser, stepURL, page, nil, false)
			_ = page.Body.Close()
			defer func() { _ = again.Body.Close() }()
			require.Equal(t, http.StatusOK, again.StatusCode, "the step is shown again")
			assertDrawnInBrand(t, again, tc.brand, tc.dataTheme)
		})
	}
}

// A legal document the acceptance step links, opened in the browser holding the sign-in, is drawn in
// the brand of the client the sign-in is for, and so is each version its page links, whose links name
// the sign-in too. The same link in another browser, a sign-in the browser does not hold, an id of
// the wrong shape, or none draws it in the default brand, and is never an error (#812 decision 4).
func TestLegalDocumentPages_KeepTheClientsBrandWhileTheBrowserHoldsTheSignIn(t *testing.T) {
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	branded := newLegalAcceptanceFixture(t)
	clientBrand := giveClientBrand(t, branded.client, record.BrandAppearanceLight, "avocado")
	_, shortName := branded.mustAcceptFor(t, "brand", "Brand terms")
	browser := createHTTPClient(t)

	step, _ := toStep(t, browser, branded.signInToCompleted(t, browser))
	ceremonyID := getCeremonyIDFromPage(t, step)
	_, documents := readStep(t, step)
	_ = step.Body.Close()
	named := "?" + url.Values{ceremony.QueryParameter: {ceremonyID}}.Encode()
	documentPath := "/legal/" + shortName
	versionPath := documentPath + "/versions/1"
	require.Len(t, documents, 1)
	require.Equal(t, documentPath+named, documents[0].href, "the step's link names the sign-in")

	for _, tc := range []struct {
		name      string
		browser   *http.Client
		target    string
		brand     *record.Brand
		dataTheme string
		version   string
	}{
		{"the document, in the browser holding the sign-in", browser, documentPath + named, clientBrand, "light", versionPath + named},
		{"a version it links", browser, versionPath + named, clientBrand, "light", versionPath + named},
		{"the same link in another browser, which still names the sign-in", createHTTPClient(t), documentPath + named,
			defaultBrand, "dark", versionPath + named},
		{"a sign-in the browser does not hold", browser, withCeremonyParameter(t, documentPath, ceremony.NewID()), defaultBrand, "dark", ""},
		{"an id of the wrong shape, not echoed", browser, documentPath + named + "x", defaultBrand, "dark", versionPath},
		{"no sign-in named", browser, documentPath, defaultBrand, "dark", versionPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := loadPage(t, tc.browser, appConfig.AuthServer.BaseURL+tc.target)
			defer func() { _ = page.Body.Close() }()
			require.Equal(t, http.StatusOK, page.StatusCode)
			doc := parseHTMLResponse(t, page)
			assertDrawnInBrand(t, page, tc.brand, tc.dataTheme)
			if tc.version != "" {
				assert.Equal(t, map[string]string{tc.version: "Version 1"}, linksIn(doc, "#legal-document-versions"),
					"the link to its version")
			}
		})
	}
}

// The page showing the recovery codes of an authenticator set up during a sign-in is drawn in the
// brand of the client the sign-in is for; the same page of a client with no brand of its own keeps
// the default (#812).
func TestSignInPages_TheRecoveryCodesStepIsDrawnInTheClientsBrand(t *testing.T) {
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	branded, brandedRedirectURI := createPublicClientAt(t, record.ACRLevel2Mandatory)
	clientBrand := giveClientBrand(t, branded, record.BrandAppearanceLight, "avocado")
	plain, plainRedirectURI := createPublicClientAt(t, record.ACRLevel2Mandatory)

	for _, tc := range []struct {
		name        string
		client      *record.Client
		redirectURI *record.RedirectURI
		brand       *record.Brand
		dataTheme   string
	}{
		{"a client with a brand of its own", branded, brandedRedirectURI, clientBrand, "light"},
		{"a client on the default brand", plain, plainRedirectURI, defaultBrand, "dark"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, user, password, _ := createLevel2MandatoryUser(t, false)
			browser, setupPage, otpURL := startOTPCeremony(t, tc.client, tc.redirectURI, user, password, "")
			secret := getOTPSecretFromEnrollmentPage(t, setupPage)
			accepted := authenticateWithOTP(t, browser, otpURL, setupPage, otptest.Code(t, secret, time.Now()))
			_ = setupPage.Body.Close()

			location := assertRedirect(t, accepted, "/auth/recovery-codes")
			_ = accepted.Body.Close()
			page := loadPage(t, browser, location)
			defer func() { _ = page.Body.Close() }()
			require.Equal(t, http.StatusOK, page.StatusCode)
			require.Len(t, recoveryCodesOnPage(t, page), 10, "the page shows the set")
			assertDrawnInBrand(t, page, tc.brand, tc.dataTheme)
		})
	}
}

// A client that registers itself starts on the default brand: a brand named in the registration
// request, as the admin API names one or in the snake case of RFC 7591's members, is metadata the
// server does not understand, which RFC 7591 section 2 says it MUST ignore (#812).
func TestDCR_ABrandInTheRequestIsIgnored(t *testing.T) {
	enableDCR(t)
	ctx := context.Background()

	brand := &record.Brand{Name: "Registered " + fake.LetterN(10), Appearance: record.BrandAppearanceLight, Theme: "avocado"}
	require.NoError(t, database.CreateBrand(ctx, nil, brand))
	t.Cleanup(func() {
		assert.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			_, err := database.DeleteBrand(ctx, tx, brand.ID)
			return err
		}), "unable to delete the brand")
	})

	body, err := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://brand-dcr.example.com/callback"},
		"client_name":   "Brand DCR " + fake.LetterN(6),
		"brandId":       brand.ID,
		"brand_id":      brand.ID,
		"brand":         strconv.FormatInt(brand.ID, 10),
	})
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+"/connect/register", bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	resp, err := createHTTPClient(t).Do(request)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusCreated, resp.StatusCode, "the registration succeeds")
	var response oidc.DynamicClientRegistrationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))

	client, err := database.GetClientByClientIdentifier(ctx, nil, response.ClientID)
	require.NoError(t, err)
	require.NotNil(t, client)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.ID) })
	assert.False(t, client.BrandID.Valid, "the client follows the default brand, whatever the request named")
}
