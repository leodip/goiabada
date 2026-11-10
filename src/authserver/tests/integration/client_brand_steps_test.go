package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

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
			browser := createHttpClient(t)

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

// The page showing the recovery codes of an authenticator set up during a sign-in is drawn in the
// brand of the client the sign-in is for; the same page of a client with no brand of its own keeps
// the default (#812).
func TestSignInPages_TheRecoveryCodesStepIsDrawnInTheClientsBrand(t *testing.T) {
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	branded, brandedRedirectURI := createPublicClientAt(t, record.AcrLevel2Mandatory)
	clientBrand := giveClientBrand(t, branded, record.BrandAppearanceLight, "avocado")
	plain, plainRedirectURI := createPublicClientAt(t, record.AcrLevel2Mandatory)

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
			browser, setupPage, otpURL := startOtpCeremony(t, tc.client, tc.redirectURI, user, password, "")
			secret := getOtpSecretFromEnrollmentPage(t, setupPage)
			accepted := authenticateWithOtp(t, browser, otpURL, setupPage, otptest.Code(t, secret, time.Now()))
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
			_, err := database.DeleteBrand(ctx, tx, brand.Id)
			return err
		}), "unable to delete the brand")
	})

	body, err := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://brand-dcr.example.com/callback"},
		"client_name":   "Brand DCR " + fake.LetterN(6),
		"brandId":       brand.Id,
		"brand_id":      brand.Id,
		"brand":         strconv.FormatInt(brand.Id, 10),
	})
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+"/connect/register", bytes.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	resp, err := createHttpClient(t).Do(request)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusCreated, resp.StatusCode, "the registration succeeds")
	var response oidc.DynamicClientRegistrationResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&response))

	client, err := database.GetClientByClientIdentifier(ctx, nil, response.ClientID)
	require.NoError(t, err)
	require.NotNil(t, client)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	assert.False(t, client.BrandId.Valid, "the client follows the default brand, whatever the request named")
}
