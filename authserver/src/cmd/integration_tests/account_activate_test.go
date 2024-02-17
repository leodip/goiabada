package integrationtests

import (
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/stretchr/testify/assert"
)

func TestAccountActivate_Get_NoEmail(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/activate"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestAccountActivate_Get_NoCode(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/activate?email=john@example.com"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestAccountActivate_Get_NoPreRegistration(t *testing.T) {
	setup()

	url := lib.GetBaseUrl() + "/account/activate?email=" + gofakeit.Username() + "@example.com&code=123456"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestAccountActivate_Get_WrongVerificationCode(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	email := gofakeit.Email()

	password := "abc123"
	passwordHash, err := lib.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	verificationCode := lib.GenerateSecureRandomString(32)
	verificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	issuedAt := time.Now().UTC()
	preRegistration := &entitiesv2.PreRegistration{
		Email:                     email,
		PasswordHash:              passwordHash,
		VerificationCodeEncrypted: verificationCodeEncrypted,
		VerificationCodeIssuedAt:  sql.NullTime{Time: issuedAt, Valid: true},
	}

	err = database.CreatePreRegistration(nil, preRegistration)
	if err != nil {
		t.Fatal(err)
	}

	url := lib.GetBaseUrl() + "/account/activate?email=" + email + "&code=invalid"

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestAccountActivate_Get_ExpiredPreRegistration(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	email := gofakeit.Email()

	password := "abc123"
	passwordHash, err := lib.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	verificationCode := lib.GenerateSecureRandomString(32)
	verificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	issuedAt := time.Now().UTC().Add(-6 * time.Minute)
	preRegistration := &entitiesv2.PreRegistration{
		Email:                     email,
		PasswordHash:              passwordHash,
		VerificationCodeEncrypted: verificationCodeEncrypted,
		VerificationCodeIssuedAt:  sql.NullTime{Time: issuedAt, Valid: true},
	}

	err = database.CreatePreRegistration(nil, preRegistration)
	if err != nil {
		t.Fatal(err)
	}

	url := lib.GetBaseUrl() + "/account/activate?email=" + email + "&code=" + verificationCode

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	docHtml, err := doc.Html()
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, docHtml, "Unable to activate the account. The verification code appears to be expired")

	// make sure the pre registration was deleted
	preRegistration, err = database.GetPreRegistrationByEmail(nil, email)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, preRegistration)
}

func TestAccountActivate_Get_SuccessfulActivation(t *testing.T) {
	setup()

	settings, err := database.GetSettingsById(nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	email := gofakeit.Email()

	password := "abc123"
	passwordHash, err := lib.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	verificationCode := lib.GenerateSecureRandomString(32)
	verificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	issuedAt := time.Now().UTC()
	preRegistration := &entitiesv2.PreRegistration{
		Email:                     email,
		PasswordHash:              passwordHash,
		VerificationCodeEncrypted: verificationCodeEncrypted,
		VerificationCodeIssuedAt:  sql.NullTime{Time: issuedAt, Valid: true},
	}

	err = database.CreatePreRegistration(nil, preRegistration)
	if err != nil {
		t.Fatal(err)
	}

	url := lib.GetBaseUrl() + "/account/activate?email=" + email + "&code=" + verificationCode

	httpClient := createHttpClient(&createHttpClientInput{
		T: t,
	})

	resp, err := httpClient.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	docHtml, err := doc.Html()
	if err != nil {
		t.Fatal(err)
	}
	assert.Contains(t, docHtml, "Congratulations! Your account has been activated")

	// make sure the pre registration was deleted
	preRegistration, err = database.GetPreRegistrationByEmail(nil, email)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, preRegistration)

	// make sure the user was created
	user, err := database.GetUserByEmail(nil, email)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, user)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, true, user.EmailVerified)
	assert.Equal(t, passwordHash, user.PasswordHash)
}
