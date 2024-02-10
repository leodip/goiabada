package integrationtests

import (
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/internal/datav2"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/initialization"
	"github.com/stretchr/testify/assert"
)

var databasev2 datav2.Database

func TestDatabase_MySQL_Setup(t *testing.T) {
	initialization.InitViper()
	var err error
	databasev2, err = datav2.NewDatabase()
	if err != nil {
		t.Fatal(err)
	}

	err = seedTestDatav2(databasev2)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDatabase_MySQL_Client(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	client := &entitiesv2.Client{
		ClientIdentifier:                        gofakeit.UUID(),
		ClientSecretEncrypted:                   []byte{1, 2, 3, 4, 5},
		Description:                             gofakeit.Sentence(10),
		Enabled:                                 true,
		ConsentRequired:                         true,
		IsPublic:                                true,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 3600,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		DefaultAcrLevel:                         "acr-level-1",
	}

	err := databasev2.CreateClient(nil, client)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, client.Id, int64(0))
	assert.WithinDuration(t, client.CreatedAt, client.UpdatedAt, 2*time.Second)

	retrievedClient, err := databasev2.GetClientById(nil, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, client.Id, retrievedClient.Id)
	assert.WithinDuration(t, retrievedClient.CreatedAt, retrievedClient.UpdatedAt, 2*time.Second)
	assert.Equal(t, client.ClientIdentifier, retrievedClient.ClientIdentifier)
	assert.Equal(t, client.ClientSecretEncrypted, retrievedClient.ClientSecretEncrypted)
	assert.Equal(t, client.Description, retrievedClient.Description)
	assert.Equal(t, client.Enabled, retrievedClient.Enabled)
	assert.Equal(t, client.ConsentRequired, retrievedClient.ConsentRequired)
	assert.Equal(t, client.IsPublic, retrievedClient.IsPublic)
	assert.Equal(t, client.AuthorizationCodeEnabled, retrievedClient.AuthorizationCodeEnabled)
	assert.Equal(t, client.ClientCredentialsEnabled, retrievedClient.ClientCredentialsEnabled)
	assert.Equal(t, client.TokenExpirationInSeconds, retrievedClient.TokenExpirationInSeconds)
	assert.Equal(t, client.RefreshTokenOfflineIdleTimeoutInSeconds, retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, client.RefreshTokenOfflineMaxLifetimeInSeconds, retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, client.IncludeOpenIDConnectClaimsInAccessToken, retrievedClient.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, client.DefaultAcrLevel, retrievedClient.DefaultAcrLevel)

	retrievedClient.ClientIdentifier = gofakeit.UUID()
	retrievedClient.ClientSecretEncrypted = []byte{5, 4, 3, 2, 1}
	retrievedClient.Description = gofakeit.Sentence(10)
	retrievedClient.Enabled = false
	retrievedClient.ConsentRequired = false
	retrievedClient.IsPublic = false
	retrievedClient.AuthorizationCodeEnabled = false
	retrievedClient.ClientCredentialsEnabled = false
	retrievedClient.TokenExpirationInSeconds = 7200
	retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds = 7200
	retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds = 7200
	retrievedClient.IncludeOpenIDConnectClaimsInAccessToken = enums.ThreeStateSettingOff.String()
	retrievedClient.DefaultAcrLevel = "acr-level-2"

	time.Sleep(300 * time.Millisecond)
	updatedAt := retrievedClient.UpdatedAt
	err = databasev2.UpdateClient(nil, retrievedClient)
	if err != nil {
		t.Fatal(err)
	}

	updatedClient, err := databasev2.GetClientById(nil, retrievedClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedClient.Id, updatedClient.Id)
	assert.WithinDuration(t, updatedClient.CreatedAt, updatedClient.UpdatedAt, 2*time.Second)
	assert.Greater(t, updatedClient.UpdatedAt, updatedAt)
	assert.Equal(t, retrievedClient.ClientIdentifier, updatedClient.ClientIdentifier)
	assert.Equal(t, retrievedClient.ClientSecretEncrypted, updatedClient.ClientSecretEncrypted)
	assert.Equal(t, retrievedClient.Description, updatedClient.Description)
	assert.Equal(t, retrievedClient.Enabled, updatedClient.Enabled)
	assert.Equal(t, retrievedClient.ConsentRequired, updatedClient.ConsentRequired)
	assert.Equal(t, retrievedClient.IsPublic, updatedClient.IsPublic)
	assert.Equal(t, retrievedClient.AuthorizationCodeEnabled, updatedClient.AuthorizationCodeEnabled)
	assert.Equal(t, retrievedClient.ClientCredentialsEnabled, updatedClient.ClientCredentialsEnabled)
	assert.Equal(t, retrievedClient.TokenExpirationInSeconds, updatedClient.TokenExpirationInSeconds)
	assert.Equal(t, retrievedClient.RefreshTokenOfflineIdleTimeoutInSeconds, updatedClient.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, retrievedClient.RefreshTokenOfflineMaxLifetimeInSeconds, updatedClient.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, retrievedClient.IncludeOpenIDConnectClaimsInAccessToken, updatedClient.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, retrievedClient.DefaultAcrLevel, updatedClient.DefaultAcrLevel)
}

func TestDatabase_MySQL_User(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	now := time.Now().UTC()
	dob := gofakeit.Date()

	user := &entitiesv2.User{
		Enabled:                              true,
		Subject:                              uuid.New(),
		Username:                             gofakeit.Username(),
		GivenName:                            gofakeit.FirstName(),
		MiddleName:                           gofakeit.FirstName(),
		FamilyName:                           gofakeit.LastName(),
		Nickname:                             gofakeit.Username(),
		Website:                              gofakeit.URL(),
		Gender:                               enums.GenderFemale.String(),
		Email:                                gofakeit.Email(),
		EmailVerified:                        true,
		EmailVerificationCodeEncrypted:       []byte{1, 2, 3, 4, 5},
		EmailVerificationCodeIssuedAt:        &now,
		ZoneInfoCountryName:                  gofakeit.Country(),
		ZoneInfo:                             gofakeit.TimeZone(),
		Locale:                               gofakeit.Language(),
		BirthDate:                            &dob,
		PhoneNumber:                          gofakeit.Phone(),
		PhoneNumberVerified:                  true,
		PhoneNumberVerificationCodeEncrypted: []byte{6, 7, 8, 9, 10},
		PhoneNumberVerificationCodeIssuedAt:  &now,
		AddressLine1:                         gofakeit.Street(),
		AddressLine2:                         gofakeit.Street(),
		AddressLocality:                      gofakeit.City(),
		AddressRegion:                        gofakeit.State(),
		AddressPostalCode:                    gofakeit.Zip(),
		AddressCountry:                       gofakeit.Country(),
		PasswordHash:                         gofakeit.RandomString([]string{"aaaaaaaaaaaaaaa"}),
		OTPSecret:                            gofakeit.UUID(),
		OTPEnabled:                           true,
		ForgotPasswordCodeEncrypted:          []byte{11, 12, 13, 14, 15},
		ForgotPasswordCodeIssuedAt:           &now,
	}

	err := databasev2.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, user.Id, int64(0))
	assert.WithinDuration(t, user.CreatedAt, user.UpdatedAt, 2*time.Second)

	retrievedUser, err := databasev2.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, user.Id, retrievedUser.Id)
	assert.WithinDuration(t, retrievedUser.CreatedAt, retrievedUser.UpdatedAt, 2*time.Second)
	assert.Equal(t, user.Enabled, retrievedUser.Enabled)
	assert.Equal(t, user.Subject, retrievedUser.Subject)
	assert.Equal(t, user.Username, retrievedUser.Username)
	assert.Equal(t, user.GivenName, retrievedUser.GivenName)
	assert.Equal(t, user.MiddleName, retrievedUser.MiddleName)
	assert.Equal(t, user.FamilyName, retrievedUser.FamilyName)
	assert.Equal(t, user.Nickname, retrievedUser.Nickname)
	assert.Equal(t, user.Website, retrievedUser.Website)
	assert.Equal(t, user.Gender, retrievedUser.Gender)
	assert.Equal(t, user.Email, retrievedUser.Email)
	assert.Equal(t, user.EmailVerified, retrievedUser.EmailVerified)
	assert.Equal(t, user.EmailVerificationCodeEncrypted, retrievedUser.EmailVerificationCodeEncrypted)
	issuedAt := *retrievedUser.EmailVerificationCodeIssuedAt
	assert.Equal(t, user.EmailVerificationCodeIssuedAt.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, user.ZoneInfoCountryName, retrievedUser.ZoneInfoCountryName)
	assert.Equal(t, user.ZoneInfo, retrievedUser.ZoneInfo)
	assert.Equal(t, user.Locale, retrievedUser.Locale)
	issuedAt = *retrievedUser.BirthDate
	assert.Equal(t, user.BirthDate.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, user.PhoneNumber, retrievedUser.PhoneNumber)
	assert.Equal(t, user.PhoneNumberVerified, retrievedUser.PhoneNumberVerified)
	assert.Equal(t, user.PhoneNumberVerificationCodeEncrypted, retrievedUser.PhoneNumberVerificationCodeEncrypted)
	issuedAt = *retrievedUser.PhoneNumberVerificationCodeIssuedAt
	assert.Equal(t, user.PhoneNumberVerificationCodeIssuedAt.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, user.AddressLine1, retrievedUser.AddressLine1)
	assert.Equal(t, user.AddressLine2, retrievedUser.AddressLine2)
	assert.Equal(t, user.AddressLocality, retrievedUser.AddressLocality)
	assert.Equal(t, user.AddressRegion, retrievedUser.AddressRegion)
	assert.Equal(t, user.AddressPostalCode, retrievedUser.AddressPostalCode)
	assert.Equal(t, user.AddressCountry, retrievedUser.AddressCountry)
	assert.Equal(t, user.PasswordHash, retrievedUser.PasswordHash)
	assert.Equal(t, user.OTPSecret, retrievedUser.OTPSecret)
	assert.Equal(t, user.OTPEnabled, retrievedUser.OTPEnabled)
	assert.Equal(t, user.ForgotPasswordCodeEncrypted, retrievedUser.ForgotPasswordCodeEncrypted)
	issuedAt = *retrievedUser.ForgotPasswordCodeIssuedAt
	assert.Equal(t, user.ForgotPasswordCodeIssuedAt.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))

	// Update some fields of the retrieved user
	time.Sleep(300 * time.Millisecond)
	now = time.Now().UTC()
	dob = gofakeit.Date()

	retrievedUser.Username = gofakeit.Username()
	retrievedUser.Email = gofakeit.Email()
	retrievedUser.Enabled = !retrievedUser.Enabled
	retrievedUser.Subject = uuid.New()
	retrievedUser.Username = gofakeit.Username()
	retrievedUser.GivenName = gofakeit.FirstName()
	retrievedUser.MiddleName = gofakeit.FirstName()
	retrievedUser.FamilyName = gofakeit.LastName()
	retrievedUser.Nickname = gofakeit.Username()
	retrievedUser.Website = gofakeit.URL()
	retrievedUser.Gender = "Other"
	retrievedUser.Email = gofakeit.Email()
	retrievedUser.EmailVerified = !retrievedUser.EmailVerified
	retrievedUser.EmailVerificationCodeEncrypted = []byte{7, 6, 5, 4, 3}
	retrievedUser.EmailVerificationCodeIssuedAt = &now
	retrievedUser.ZoneInfoCountryName = gofakeit.Country()
	retrievedUser.ZoneInfo = gofakeit.TimeZone()
	retrievedUser.Locale = gofakeit.Language()
	retrievedUser.BirthDate = &dob
	retrievedUser.PhoneNumber = gofakeit.Phone()
	retrievedUser.PhoneNumberVerified = !retrievedUser.PhoneNumberVerified
	retrievedUser.PhoneNumberVerificationCodeEncrypted = []byte{9, 8, 7}
	retrievedUser.PhoneNumberVerificationCodeIssuedAt = &now
	retrievedUser.AddressLine1 = gofakeit.Street()
	retrievedUser.AddressLine2 = gofakeit.Street()
	retrievedUser.AddressLocality = gofakeit.City()
	retrievedUser.OTPEnabled = !retrievedUser.OTPEnabled
	retrievedUser.ForgotPasswordCodeEncrypted = []byte{15, 14, 13, 12, 11}
	retrievedUser.ForgotPasswordCodeIssuedAt = &now

	time.Sleep(300 * time.Millisecond)
	updatedAt := retrievedUser.UpdatedAt
	err = databasev2.UpdateUser(nil, retrievedUser)
	if err != nil {
		t.Fatal(err)
	}

	updatedUser, err := databasev2.GetUserById(nil, retrievedUser.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedUser.Id, updatedUser.Id)
	assert.WithinDuration(t, updatedUser.CreatedAt, updatedUser.UpdatedAt, 2*time.Second)
	assert.Greater(t, updatedUser.UpdatedAt, updatedAt)
	assert.Equal(t, retrievedUser.Enabled, updatedUser.Enabled)
	assert.Equal(t, retrievedUser.Subject, updatedUser.Subject)
	assert.Equal(t, retrievedUser.Username, updatedUser.Username)
	assert.Equal(t, retrievedUser.GivenName, updatedUser.GivenName)
	assert.Equal(t, retrievedUser.MiddleName, updatedUser.MiddleName)
	assert.Equal(t, retrievedUser.FamilyName, updatedUser.FamilyName)
	assert.Equal(t, retrievedUser.Nickname, updatedUser.Nickname)
	assert.Equal(t, retrievedUser.Website, updatedUser.Website)
	assert.Equal(t, retrievedUser.Gender, updatedUser.Gender)
	assert.Equal(t, retrievedUser.Email, updatedUser.Email)
	assert.Equal(t, retrievedUser.EmailVerified, updatedUser.EmailVerified)
	assert.Equal(t, retrievedUser.EmailVerificationCodeEncrypted, updatedUser.EmailVerificationCodeEncrypted)
	issuedAt = *updatedUser.EmailVerificationCodeIssuedAt
	assert.Equal(t, retrievedUser.EmailVerificationCodeIssuedAt.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUser.ZoneInfoCountryName, updatedUser.ZoneInfoCountryName)
	assert.Equal(t, retrievedUser.ZoneInfo, updatedUser.ZoneInfo)
	assert.Equal(t, retrievedUser.Locale, updatedUser.Locale)
	issuedAt = *updatedUser.BirthDate
	assert.Equal(t, retrievedUser.BirthDate.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUser.PhoneNumber, updatedUser.PhoneNumber)
	assert.Equal(t, retrievedUser.PhoneNumberVerified, updatedUser.PhoneNumberVerified)
	assert.Equal(t, retrievedUser.PhoneNumberVerificationCodeEncrypted, updatedUser.PhoneNumberVerificationCodeEncrypted)
	issuedAt = *updatedUser.PhoneNumberVerificationCodeIssuedAt
	assert.Equal(t, retrievedUser.PhoneNumberVerificationCodeIssuedAt.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUser.AddressLine1, updatedUser.AddressLine1)
	assert.Equal(t, retrievedUser.AddressLine2, updatedUser.AddressLine2)
	assert.Equal(t, retrievedUser.AddressLocality, updatedUser.AddressLocality)
	assert.Equal(t, retrievedUser.AddressRegion, updatedUser.AddressRegion)
	assert.Equal(t, retrievedUser.AddressPostalCode, updatedUser.AddressPostalCode)
	assert.Equal(t, retrievedUser.AddressCountry, updatedUser.AddressCountry)
	assert.Equal(t, retrievedUser.PasswordHash, updatedUser.PasswordHash)
	assert.Equal(t, retrievedUser.OTPSecret, updatedUser.OTPSecret)
	assert.Equal(t, retrievedUser.OTPEnabled, updatedUser.OTPEnabled)
	assert.Equal(t, retrievedUser.ForgotPasswordCodeEncrypted, updatedUser.ForgotPasswordCodeEncrypted)
	issuedAt = *updatedUser.ForgotPasswordCodeIssuedAt
	assert.Equal(t, retrievedUser.ForgotPasswordCodeIssuedAt.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
}

func TestDatabase_MySQL_Code(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	code := &entitiesv2.Code{
		CodeHash:            gofakeit.UUID(),
		ClientId:            1,
		CodeChallenge:       gofakeit.UUID(),
		CodeChallengeMethod: "S256",
		Scope:               "openid profile email",
		State:               gofakeit.UUID(),
		Nonce:               gofakeit.UUID(),
		RedirectURI:         "https://example.com/callback",
		UserId:              1,
		IpAddress:           gofakeit.IPv4Address(),
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537",
		ResponseMode:        "form_post",
		AuthenticatedAt:     time.Now().UTC(),
		SessionIdentifier:   gofakeit.UUID(),
		AcrLevel:            "acr-1",
		AuthMethods:         "password",
		Used:                true,
	}

	err := databasev2.CreateCode(nil, code)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, code.Id, int64(0))
	assert.WithinDuration(t, code.CreatedAt, code.UpdatedAt, 2*time.Second)

	retrievedCode, err := databasev2.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, code.Id, retrievedCode.Id)
	assert.WithinDuration(t, retrievedCode.CreatedAt, retrievedCode.UpdatedAt, 2*time.Second)
	assert.Equal(t, code.CodeHash, retrievedCode.CodeHash)
	assert.Equal(t, code.ClientId, retrievedCode.ClientId)
	assert.Equal(t, code.CodeChallenge, retrievedCode.CodeChallenge)
	assert.Equal(t, code.CodeChallengeMethod, retrievedCode.CodeChallengeMethod)
	assert.Equal(t, code.Scope, retrievedCode.Scope)
	assert.Equal(t, code.State, retrievedCode.State)
	assert.Equal(t, code.Nonce, retrievedCode.Nonce)
	assert.Equal(t, code.RedirectURI, retrievedCode.RedirectURI)
	assert.Equal(t, code.UserId, retrievedCode.UserId)
	assert.Equal(t, code.IpAddress, retrievedCode.IpAddress)
	assert.Equal(t, code.UserAgent, retrievedCode.UserAgent)
	assert.Equal(t, code.ResponseMode, retrievedCode.ResponseMode)
	assert.Equal(t, code.AuthenticatedAt.Truncate(time.Millisecond), retrievedCode.AuthenticatedAt.Truncate(time.Millisecond))
	assert.Equal(t, code.SessionIdentifier, retrievedCode.SessionIdentifier)
	assert.Equal(t, code.AcrLevel, retrievedCode.AcrLevel)
	assert.Equal(t, code.AuthMethods, retrievedCode.AuthMethods)
	assert.Equal(t, code.Used, retrievedCode.Used)

	retrievedCode.CodeHash = gofakeit.UUID()
	retrievedCode.ClientId = 2
	retrievedCode.CodeChallenge = gofakeit.UUID()
	retrievedCode.CodeChallengeMethod = "plain"
	retrievedCode.Scope = "openid profile email address"
	retrievedCode.State = gofakeit.UUID()
	retrievedCode.Nonce = gofakeit.UUID()
	retrievedCode.RedirectURI = "https://example.com/callback2"
	retrievedCode.UserId = 2
	retrievedCode.IpAddress = gofakeit.IPv4Address()
	retrievedCode.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537"
	retrievedCode.ResponseMode = "query"
	retrievedCode.AuthenticatedAt = time.Now().UTC()
	retrievedCode.SessionIdentifier = gofakeit.UUID()
	retrievedCode.AcrLevel = "acr-2"
	retrievedCode.AuthMethods = "password,otp"
	retrievedCode.Used = false

	time.Sleep(300 * time.Millisecond)
	updatedAt := retrievedCode.UpdatedAt
	err = databasev2.UpdateCode(nil, retrievedCode)
	if err != nil {
		t.Fatal(err)
	}

	updatedCode, err := databasev2.GetCodeById(nil, retrievedCode.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedCode.Id, updatedCode.Id)
	assert.WithinDuration(t, updatedCode.CreatedAt, updatedCode.UpdatedAt, 2*time.Second)
	assert.Greater(t, updatedCode.UpdatedAt, updatedAt)
	assert.Equal(t, retrievedCode.CodeHash, updatedCode.CodeHash)
	assert.Equal(t, retrievedCode.ClientId, updatedCode.ClientId)
	assert.Equal(t, retrievedCode.CodeChallenge, updatedCode.CodeChallenge)
	assert.Equal(t, retrievedCode.CodeChallengeMethod, updatedCode.CodeChallengeMethod)
	assert.Equal(t, retrievedCode.Scope, updatedCode.Scope)
	assert.Equal(t, retrievedCode.State, updatedCode.State)
	assert.Equal(t, retrievedCode.Nonce, updatedCode.Nonce)
	assert.Equal(t, retrievedCode.RedirectURI, updatedCode.RedirectURI)
	assert.Equal(t, retrievedCode.UserId, updatedCode.UserId)
	assert.Equal(t, retrievedCode.IpAddress, updatedCode.IpAddress)
	assert.Equal(t, retrievedCode.UserAgent, updatedCode.UserAgent)
	assert.Equal(t, retrievedCode.ResponseMode, updatedCode.ResponseMode)
	assert.Equal(t, retrievedCode.AuthenticatedAt.Truncate(time.Millisecond), updatedCode.AuthenticatedAt.Truncate(time.Millisecond))
	assert.Equal(t, retrievedCode.SessionIdentifier, updatedCode.SessionIdentifier)
	assert.Equal(t, retrievedCode.AcrLevel, updatedCode.AcrLevel)
	assert.Equal(t, retrievedCode.AuthMethods, updatedCode.AuthMethods)
	assert.Equal(t, retrievedCode.Used, updatedCode.Used)
}
