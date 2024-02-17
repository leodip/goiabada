package integrationtests

import (
	"database/sql"
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
	assert.WithinDuration(t, client.CreatedAt.Time, client.UpdatedAt.Time, 2*time.Second)

	retrievedClient, err := databasev2.GetClientById(nil, client.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, client.Id, retrievedClient.Id)
	assert.WithinDuration(t, retrievedClient.CreatedAt.Time, retrievedClient.UpdatedAt.Time, 2*time.Second)
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

	time.Sleep(100 * time.Millisecond)
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
	assert.WithinDuration(t, updatedClient.CreatedAt.Time, updatedClient.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedClient.UpdatedAt.Time, updatedAt)
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

	err = databasev2.DeleteClient(nil, updatedClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	client, err = databasev2.GetClientById(nil, updatedClient.Id)
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, client)
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
		EmailVerificationCodeIssuedAt:        sql.NullTime{Time: now, Valid: true},
		ZoneInfoCountryName:                  gofakeit.Country(),
		ZoneInfo:                             gofakeit.TimeZone(),
		Locale:                               gofakeit.Language(),
		BirthDate:                            sql.NullTime{Time: dob, Valid: true},
		PhoneNumber:                          gofakeit.Phone(),
		PhoneNumberVerified:                  true,
		PhoneNumberVerificationCodeEncrypted: []byte{6, 7, 8, 9, 10},
		PhoneNumberVerificationCodeIssuedAt:  sql.NullTime{Time: now, Valid: true},
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
		ForgotPasswordCodeIssuedAt:           sql.NullTime{Time: now, Valid: true},
	}

	err := databasev2.CreateUser(nil, user)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, user.Id, int64(0))
	assert.WithinDuration(t, user.CreatedAt.Time, user.UpdatedAt.Time, 2*time.Second)

	retrievedUser, err := databasev2.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, user.Id, retrievedUser.Id)
	assert.WithinDuration(t, retrievedUser.CreatedAt.Time, retrievedUser.UpdatedAt.Time, 2*time.Second)
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
	issuedAt := retrievedUser.EmailVerificationCodeIssuedAt.Time
	assert.Equal(t, user.EmailVerificationCodeIssuedAt.Time.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, user.ZoneInfoCountryName, retrievedUser.ZoneInfoCountryName)
	assert.Equal(t, user.ZoneInfo, retrievedUser.ZoneInfo)
	assert.Equal(t, user.Locale, retrievedUser.Locale)
	issuedAt = retrievedUser.BirthDate.Time
	assert.Equal(t, user.BirthDate.Time.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, user.PhoneNumber, retrievedUser.PhoneNumber)
	assert.Equal(t, user.PhoneNumberVerified, retrievedUser.PhoneNumberVerified)
	assert.Equal(t, user.PhoneNumberVerificationCodeEncrypted, retrievedUser.PhoneNumberVerificationCodeEncrypted)
	issuedAt = retrievedUser.PhoneNumberVerificationCodeIssuedAt.Time
	assert.Equal(t, user.PhoneNumberVerificationCodeIssuedAt.Time.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
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
	issuedAt = retrievedUser.ForgotPasswordCodeIssuedAt.Time
	assert.Equal(t, user.ForgotPasswordCodeIssuedAt.Time.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))

	time.Sleep(100 * time.Millisecond)
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
	retrievedUser.EmailVerificationCodeIssuedAt = sql.NullTime{Time: now, Valid: true}
	retrievedUser.ZoneInfoCountryName = gofakeit.Country()
	retrievedUser.ZoneInfo = gofakeit.TimeZone()
	retrievedUser.Locale = gofakeit.Language()
	retrievedUser.BirthDate = sql.NullTime{Time: dob, Valid: true}
	retrievedUser.PhoneNumber = gofakeit.Phone()
	retrievedUser.PhoneNumberVerified = !retrievedUser.PhoneNumberVerified
	retrievedUser.PhoneNumberVerificationCodeEncrypted = []byte{9, 8, 7}
	retrievedUser.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: now, Valid: true}
	retrievedUser.AddressLine1 = gofakeit.Street()
	retrievedUser.AddressLine2 = gofakeit.Street()
	retrievedUser.AddressLocality = gofakeit.City()
	retrievedUser.OTPEnabled = !retrievedUser.OTPEnabled
	retrievedUser.ForgotPasswordCodeEncrypted = []byte{15, 14, 13, 12, 11}
	retrievedUser.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: now, Valid: true}

	time.Sleep(100 * time.Millisecond)
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
	assert.WithinDuration(t, updatedUser.CreatedAt.Time, updatedUser.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedUser.UpdatedAt.Time, updatedAt)
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
	issuedAt = updatedUser.EmailVerificationCodeIssuedAt.Time
	assert.Equal(t, retrievedUser.EmailVerificationCodeIssuedAt.Time.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUser.ZoneInfoCountryName, updatedUser.ZoneInfoCountryName)
	assert.Equal(t, retrievedUser.ZoneInfo, updatedUser.ZoneInfo)
	assert.Equal(t, retrievedUser.Locale, updatedUser.Locale)
	issuedAt = updatedUser.BirthDate.Time
	assert.Equal(t, retrievedUser.BirthDate.Time.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUser.PhoneNumber, updatedUser.PhoneNumber)
	assert.Equal(t, retrievedUser.PhoneNumberVerified, updatedUser.PhoneNumberVerified)
	assert.Equal(t, retrievedUser.PhoneNumberVerificationCodeEncrypted, updatedUser.PhoneNumberVerificationCodeEncrypted)
	issuedAt = updatedUser.PhoneNumberVerificationCodeIssuedAt.Time
	assert.Equal(t, retrievedUser.PhoneNumberVerificationCodeIssuedAt.Time.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))
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
	issuedAt = updatedUser.ForgotPasswordCodeIssuedAt.Time
	assert.Equal(t, retrievedUser.ForgotPasswordCodeIssuedAt.Time.Truncate(time.Millisecond), issuedAt.Truncate(time.Millisecond))

	err = databasev2.DeleteUser(nil, updatedUser.Id)
	if err != nil {
		t.Fatal(err)
	}

	user, err = databasev2.GetUserById(nil, updatedUser.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, user)
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
	assert.WithinDuration(t, code.CreatedAt.Time, code.UpdatedAt.Time, 2*time.Second)

	retrievedCode, err := databasev2.GetCodeById(nil, code.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, code.Id, retrievedCode.Id)
	assert.WithinDuration(t, retrievedCode.CreatedAt.Time, retrievedCode.UpdatedAt.Time, 2*time.Second)
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

	time.Sleep(100 * time.Millisecond)
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
	assert.WithinDuration(t, updatedCode.CreatedAt.Time, updatedCode.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedCode.UpdatedAt.Time, updatedAt)
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

	err = databasev2.DeleteCode(nil, updatedCode.Id)
	if err != nil {
		t.Fatal(err)
	}

	code, err = databasev2.GetCodeById(nil, updatedCode.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, code)
}

func TestDatabase_MySQL_ClientPermission(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	clientPermission := &entitiesv2.ClientPermission{
		ClientId:     1,
		PermissionId: 1,
	}

	err := databasev2.CreateClientPermission(nil, clientPermission)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, clientPermission.Id, int64(0))
	assert.WithinDuration(t, clientPermission.CreatedAt.Time, clientPermission.UpdatedAt.Time, 2*time.Second)

	retrievedClientPermission, err := databasev2.GetClientPermissionById(nil, clientPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, clientPermission.Id, retrievedClientPermission.Id)
	assert.WithinDuration(t, retrievedClientPermission.CreatedAt.Time, retrievedClientPermission.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, clientPermission.ClientId, retrievedClientPermission.ClientId)
	assert.Equal(t, clientPermission.PermissionId, retrievedClientPermission.PermissionId)

	retrievedClientPermission.ClientId = 2
	retrievedClientPermission.PermissionId = 2

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedClientPermission.UpdatedAt
	err = databasev2.UpdateClientPermission(nil, retrievedClientPermission)
	if err != nil {
		t.Fatal(err)
	}

	updatedClientPermission, err := databasev2.GetClientPermissionById(nil, retrievedClientPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedClientPermission.Id, updatedClientPermission.Id)
	assert.WithinDuration(t, updatedClientPermission.CreatedAt.Time, updatedClientPermission.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedClientPermission.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedClientPermission.ClientId, updatedClientPermission.ClientId)
	assert.Equal(t, retrievedClientPermission.PermissionId, updatedClientPermission.PermissionId)

	err = databasev2.DeleteClientPermission(nil, updatedClientPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	clientPermission, err = databasev2.GetClientPermissionById(nil, updatedClientPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, clientPermission)
}

func TestDatabase_MySQL_Group(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	group := &entitiesv2.Group{
		GroupIdentifier:      gofakeit.UUID(),
		Description:          gofakeit.Sentence(10),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}

	err := databasev2.CreateGroup(nil, group)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, group.Id, int64(0))
	assert.WithinDuration(t, group.CreatedAt.Time, group.UpdatedAt.Time, 2*time.Second)

	retrievedGroup, err := databasev2.GetGroupById(nil, group.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, group.Id, retrievedGroup.Id)
	assert.WithinDuration(t, retrievedGroup.CreatedAt.Time, retrievedGroup.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, group.GroupIdentifier, retrievedGroup.GroupIdentifier)
	assert.Equal(t, group.Description, retrievedGroup.Description)
	assert.Equal(t, group.IncludeInIdToken, retrievedGroup.IncludeInIdToken)
	assert.Equal(t, group.IncludeInAccessToken, retrievedGroup.IncludeInAccessToken)

	retrievedGroup.GroupIdentifier = gofakeit.UUID()
	retrievedGroup.Description = gofakeit.Sentence(10)
	retrievedGroup.IncludeInIdToken = false
	retrievedGroup.IncludeInAccessToken = false

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedGroup.UpdatedAt
	err = databasev2.UpdateGroup(nil, retrievedGroup)
	if err != nil {
		t.Fatal(err)
	}

	updatedGroup, err := databasev2.GetGroupById(nil, retrievedGroup.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedGroup.Id, updatedGroup.Id)
	assert.WithinDuration(t, updatedGroup.CreatedAt.Time, updatedGroup.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedGroup.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedGroup.GroupIdentifier, updatedGroup.GroupIdentifier)
	assert.Equal(t, retrievedGroup.Description, updatedGroup.Description)
	assert.Equal(t, retrievedGroup.IncludeInIdToken, updatedGroup.IncludeInIdToken)
	assert.Equal(t, retrievedGroup.IncludeInAccessToken, updatedGroup.IncludeInAccessToken)

	err = databasev2.DeleteGroup(nil, updatedGroup.Id)
	if err != nil {
		t.Fatal(err)
	}

	group, err = databasev2.GetGroupById(nil, updatedGroup.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, group)
}

func TestDatabase_MySQL_KeyPair(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	keyPair := &entitiesv2.KeyPair{
		State:             enums.KeyStateCurrent.String(),
		KeyIdentifier:     gofakeit.UUID(),
		Type:              "type1",
		Algorithm:         "alg1",
		PrivateKeyPEM:     []byte{1, 2, 3, 4, 5},
		PublicKeyPEM:      []byte{5, 4, 3, 2, 1},
		PublicKeyASN1_DER: []byte{6, 7, 8, 9},
		PublicKeyJWK:      []byte{9, 8, 7, 6},
	}

	err := databasev2.CreateKeyPair(nil, keyPair)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, keyPair.Id, int64(0))
	assert.WithinDuration(t, keyPair.CreatedAt.Time, keyPair.UpdatedAt.Time, 2*time.Second)

	retrievedKeyPair, err := databasev2.GetKeyPairById(nil, keyPair.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, keyPair.Id, retrievedKeyPair.Id)
	assert.WithinDuration(t, retrievedKeyPair.CreatedAt.Time, retrievedKeyPair.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, keyPair.State, retrievedKeyPair.State)
	assert.Equal(t, keyPair.KeyIdentifier, retrievedKeyPair.KeyIdentifier)
	assert.Equal(t, keyPair.Type, retrievedKeyPair.Type)
	assert.Equal(t, keyPair.Algorithm, retrievedKeyPair.Algorithm)
	assert.Equal(t, keyPair.PrivateKeyPEM, retrievedKeyPair.PrivateKeyPEM)
	assert.Equal(t, keyPair.PublicKeyPEM, retrievedKeyPair.PublicKeyPEM)
	assert.Equal(t, keyPair.PublicKeyASN1_DER, retrievedKeyPair.PublicKeyASN1_DER)
	assert.Equal(t, keyPair.PublicKeyJWK, retrievedKeyPair.PublicKeyJWK)

	retrievedKeyPair.State = enums.KeyStateNext.String()
	retrievedKeyPair.KeyIdentifier = gofakeit.UUID()
	retrievedKeyPair.Type = "type2"
	retrievedKeyPair.Algorithm = "alg2"
	retrievedKeyPair.PrivateKeyPEM = []byte{5, 4, 3, 2, 1}
	retrievedKeyPair.PublicKeyPEM = []byte{1, 2, 3, 4, 5}
	retrievedKeyPair.PublicKeyASN1_DER = []byte{9, 8, 7, 6}
	retrievedKeyPair.PublicKeyJWK = []byte{6, 7, 8, 9}

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedKeyPair.UpdatedAt
	err = databasev2.UpdateKeyPair(nil, retrievedKeyPair)
	if err != nil {
		t.Fatal(err)
	}

	updatedKeyPair, err := databasev2.GetKeyPairById(nil, retrievedKeyPair.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedKeyPair.Id, updatedKeyPair.Id)
	assert.WithinDuration(t, updatedKeyPair.CreatedAt.Time, updatedKeyPair.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedKeyPair.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedKeyPair.State, updatedKeyPair.State)
	assert.Equal(t, retrievedKeyPair.KeyIdentifier, updatedKeyPair.KeyIdentifier)
	assert.Equal(t, retrievedKeyPair.Type, updatedKeyPair.Type)
	assert.Equal(t, retrievedKeyPair.Algorithm, updatedKeyPair.Algorithm)
	assert.Equal(t, retrievedKeyPair.PrivateKeyPEM, updatedKeyPair.PrivateKeyPEM)
	assert.Equal(t, retrievedKeyPair.PublicKeyPEM, updatedKeyPair.PublicKeyPEM)
	assert.Equal(t, retrievedKeyPair.PublicKeyASN1_DER, updatedKeyPair.PublicKeyASN1_DER)
	assert.Equal(t, retrievedKeyPair.PublicKeyJWK, updatedKeyPair.PublicKeyJWK)

	err = databasev2.DeleteKeyPair(nil, updatedKeyPair.Id)
	if err != nil {
		t.Fatal(err)
	}

	keyPair, err = databasev2.GetKeyPairById(nil, updatedKeyPair.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, keyPair)
}

func TestDatabase_MySQL_Permission(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	permission := &entitiesv2.Permission{
		PermissionIdentifier: gofakeit.UUID(),
		Description:          gofakeit.Sentence(5),
		ResourceId:           1,
	}

	err := databasev2.CreatePermission(nil, permission)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, permission.Id, int64(0))
	assert.WithinDuration(t, permission.CreatedAt.Time, permission.UpdatedAt.Time, 2*time.Second)

	retrievedPermission, err := databasev2.GetPermissionById(nil, permission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, permission.Id, retrievedPermission.Id)
	assert.WithinDuration(t, retrievedPermission.CreatedAt.Time, retrievedPermission.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, permission.PermissionIdentifier, retrievedPermission.PermissionIdentifier)
	assert.Equal(t, permission.Description, retrievedPermission.Description)
	assert.Equal(t, permission.ResourceId, retrievedPermission.ResourceId)

	retrievedPermission.PermissionIdentifier = gofakeit.UUID()
	retrievedPermission.Description = gofakeit.Sentence(5)
	retrievedPermission.ResourceId = 2

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedPermission.UpdatedAt
	err = databasev2.UpdatePermission(nil, retrievedPermission)
	if err != nil {
		t.Fatal(err)
	}

	updatedPermission, err := databasev2.GetPermissionById(nil, retrievedPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedPermission.Id, updatedPermission.Id)
	assert.WithinDuration(t, updatedPermission.CreatedAt.Time, updatedPermission.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedPermission.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedPermission.PermissionIdentifier, updatedPermission.PermissionIdentifier)
	assert.Equal(t, retrievedPermission.Description, updatedPermission.Description)
	assert.Equal(t, retrievedPermission.ResourceId, updatedPermission.ResourceId)

	err = databasev2.DeletePermission(nil, updatedPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	permission, err = databasev2.GetPermissionById(nil, updatedPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, permission)
}

func TestDatabase_MySQL_RedirectURI(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	redirectURI := &entitiesv2.RedirectURI{
		URI:      "https://example.com/callback",
		ClientId: 1,
	}

	err := databasev2.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, redirectURI.Id, int64(0))

	retrievedRedirectURI, err := databasev2.GetRedirectURIById(nil, redirectURI.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, redirectURI.Id, retrievedRedirectURI.Id)
	assert.Equal(t, redirectURI.URI, retrievedRedirectURI.URI)
	assert.Equal(t, redirectURI.ClientId, retrievedRedirectURI.ClientId)

	err = databasev2.DeleteRedirectURI(nil, redirectURI.Id)
	if err != nil {
		t.Fatal(err)
	}

	redirectURI, err = databasev2.GetRedirectURIById(nil, redirectURI.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, redirectURI)
}

func TestDatabase_MySQL_Resource(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	resource := &entitiesv2.Resource{
		ResourceIdentifier: gofakeit.UUID(),
		Description:        gofakeit.Sentence(5),
	}

	err := databasev2.CreateResource(nil, resource)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, resource.Id, int64(0))
	assert.WithinDuration(t, resource.CreatedAt.Time, resource.UpdatedAt.Time, 2*time.Second)

	retrievedResource, err := databasev2.GetResourceById(nil, resource.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, resource.Id, retrievedResource.Id)
	assert.WithinDuration(t, retrievedResource.CreatedAt.Time, retrievedResource.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, resource.ResourceIdentifier, retrievedResource.ResourceIdentifier)
	assert.Equal(t, resource.Description, retrievedResource.Description)

	retrievedResource.ResourceIdentifier = gofakeit.UUID()
	retrievedResource.Description = gofakeit.Sentence(5)

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedResource.UpdatedAt
	err = databasev2.UpdateResource(nil, retrievedResource)
	if err != nil {
		t.Fatal(err)
	}

	updatedResource, err := databasev2.GetResourceById(nil, retrievedResource.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedResource.Id, updatedResource.Id)
	assert.WithinDuration(t, updatedResource.CreatedAt.Time, updatedResource.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedResource.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedResource.ResourceIdentifier, updatedResource.ResourceIdentifier)
	assert.Equal(t, retrievedResource.Description, updatedResource.Description)

	err = databasev2.DeleteResource(nil, updatedResource.Id)
	if err != nil {
		t.Fatal(err)
	}

	resource, err = databasev2.GetResourceById(nil, updatedResource.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, resource)
}

func TestDatabase_MySQL_Settings(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	settings := &entitiesv2.Settings{
		AppName:                 "Goiabada",
		Issuer:                  "https://example.com",
		UITheme:                 "dark",
		PasswordPolicy:          enums.PasswordPolicyHigh,
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: true,
		TokenExpirationInSeconds:                  3600,
		RefreshTokenOfflineIdleTimeoutInSeconds:   3600,
		RefreshTokenOfflineMaxLifetimeInSeconds:   3600,
		UserSessionIdleTimeoutInSeconds:           3600,
		UserSessionMaxLifetimeInSeconds:           3600,
		IncludeOpenIDConnectClaimsInAccessToken:   true,
		SessionAuthenticationKey:                  []byte{1, 2, 3, 4, 5},
		SessionEncryptionKey:                      []byte{5, 4, 3, 2, 1},
		AESEncryptionKey:                          []byte{6, 7, 8, 9, 10},
		SMTPHost:                                  "smtp.example.com",
		SMTPPort:                                  587,
		SMTPUsername:                              "username",
		SMTPPasswordEncrypted:                     []byte{11, 12, 13, 14, 15},
		SMTPFromName:                              "Goiabada",
		SMTPFromEmail:                             "from@example.com",
		SMTPEncryption:                            "tls",
		SMTPEnabled:                               true,
		SMSProvider:                               "twilio",
		SMSConfigEncrypted:                        []byte{16, 17, 18, 19, 20},
	}

	err := databasev2.CreateSettings(nil, settings)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, settings.Id, int64(0))
	assert.WithinDuration(t, settings.CreatedAt.Time, settings.UpdatedAt.Time, 2*time.Second)

	retrievedSettings, err := databasev2.GetSettingsById(nil, settings.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, settings.Id, retrievedSettings.Id)
	assert.WithinDuration(t, retrievedSettings.CreatedAt.Time, retrievedSettings.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, settings.AppName, retrievedSettings.AppName)
	assert.Equal(t, settings.Issuer, retrievedSettings.Issuer)
	assert.Equal(t, settings.UITheme, retrievedSettings.UITheme)
	assert.Equal(t, settings.PasswordPolicy, retrievedSettings.PasswordPolicy)
	assert.Equal(t, settings.SelfRegistrationEnabled, retrievedSettings.SelfRegistrationEnabled)
	assert.Equal(t, settings.SelfRegistrationRequiresEmailVerification, retrievedSettings.SelfRegistrationRequiresEmailVerification)
	assert.Equal(t, settings.TokenExpirationInSeconds, retrievedSettings.TokenExpirationInSeconds)
	assert.Equal(t, settings.RefreshTokenOfflineIdleTimeoutInSeconds, retrievedSettings.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, settings.RefreshTokenOfflineMaxLifetimeInSeconds, retrievedSettings.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, settings.UserSessionIdleTimeoutInSeconds, retrievedSettings.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, settings.UserSessionMaxLifetimeInSeconds, retrievedSettings.UserSessionMaxLifetimeInSeconds)
	assert.Equal(t, settings.IncludeOpenIDConnectClaimsInAccessToken, retrievedSettings.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, settings.SessionAuthenticationKey, retrievedSettings.SessionAuthenticationKey)
	assert.Equal(t, settings.SessionEncryptionKey, retrievedSettings.SessionEncryptionKey)
	assert.Equal(t, settings.AESEncryptionKey, retrievedSettings.AESEncryptionKey)
	assert.Equal(t, settings.SMTPHost, retrievedSettings.SMTPHost)
	assert.Equal(t, settings.SMTPPort, retrievedSettings.SMTPPort)
	assert.Equal(t, settings.SMTPUsername, retrievedSettings.SMTPUsername)
	assert.Equal(t, settings.SMTPPasswordEncrypted, retrievedSettings.SMTPPasswordEncrypted)
	assert.Equal(t, settings.SMTPFromName, retrievedSettings.SMTPFromName)
	assert.Equal(t, settings.SMTPFromEmail, retrievedSettings.SMTPFromEmail)
	assert.Equal(t, settings.SMTPEncryption, retrievedSettings.SMTPEncryption)
	assert.Equal(t, settings.SMTPEnabled, retrievedSettings.SMTPEnabled)
	assert.Equal(t, settings.SMSProvider, retrievedSettings.SMSProvider)
	assert.Equal(t, settings.SMSConfigEncrypted, retrievedSettings.SMSConfigEncrypted)

	retrievedSettings.AppName = "Goiabada2"
	retrievedSettings.Issuer = "https://example.com2"
	retrievedSettings.UITheme = "light"
	retrievedSettings.PasswordPolicy = enums.PasswordPolicyLow
	retrievedSettings.SelfRegistrationEnabled = false
	retrievedSettings.SelfRegistrationRequiresEmailVerification = false
	retrievedSettings.TokenExpirationInSeconds = 7200
	retrievedSettings.RefreshTokenOfflineIdleTimeoutInSeconds = 7200
	retrievedSettings.RefreshTokenOfflineMaxLifetimeInSeconds = 7200
	retrievedSettings.UserSessionIdleTimeoutInSeconds = 7200
	retrievedSettings.UserSessionMaxLifetimeInSeconds = 7200
	retrievedSettings.IncludeOpenIDConnectClaimsInAccessToken = false

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedSettings.UpdatedAt
	err = databasev2.UpdateSettings(nil, retrievedSettings)
	if err != nil {
		t.Fatal(err)
	}

	updatedSettings, err := databasev2.GetSettingsById(nil, retrievedSettings.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedSettings.Id, updatedSettings.Id)
	assert.WithinDuration(t, updatedSettings.CreatedAt.Time, updatedSettings.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedSettings.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedSettings.AppName, updatedSettings.AppName)
	assert.Equal(t, retrievedSettings.Issuer, updatedSettings.Issuer)
	assert.Equal(t, retrievedSettings.UITheme, updatedSettings.UITheme)
	assert.Equal(t, retrievedSettings.PasswordPolicy, updatedSettings.PasswordPolicy)
	assert.Equal(t, retrievedSettings.SelfRegistrationEnabled, updatedSettings.SelfRegistrationEnabled)
	assert.Equal(t, retrievedSettings.SelfRegistrationRequiresEmailVerification, updatedSettings.SelfRegistrationRequiresEmailVerification)
	assert.Equal(t, retrievedSettings.TokenExpirationInSeconds, updatedSettings.TokenExpirationInSeconds)
	assert.Equal(t, retrievedSettings.RefreshTokenOfflineIdleTimeoutInSeconds, updatedSettings.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, retrievedSettings.RefreshTokenOfflineMaxLifetimeInSeconds, updatedSettings.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, retrievedSettings.UserSessionIdleTimeoutInSeconds, updatedSettings.UserSessionIdleTimeoutInSeconds)
	assert.Equal(t, retrievedSettings.UserSessionMaxLifetimeInSeconds, updatedSettings.UserSessionMaxLifetimeInSeconds)
	assert.Equal(t, retrievedSettings.IncludeOpenIDConnectClaimsInAccessToken, updatedSettings.IncludeOpenIDConnectClaimsInAccessToken)
	assert.Equal(t, retrievedSettings.SessionAuthenticationKey, updatedSettings.SessionAuthenticationKey)
	assert.Equal(t, retrievedSettings.SessionEncryptionKey, updatedSettings.SessionEncryptionKey)
	assert.Equal(t, retrievedSettings.AESEncryptionKey, updatedSettings.AESEncryptionKey)
	assert.Equal(t, retrievedSettings.SMTPHost, updatedSettings.SMTPHost)
	assert.Equal(t, retrievedSettings.SMTPPort, updatedSettings.SMTPPort)
	assert.Equal(t, retrievedSettings.SMTPUsername, updatedSettings.SMTPUsername)
	assert.Equal(t, retrievedSettings.SMTPPasswordEncrypted, updatedSettings.SMTPPasswordEncrypted)
	assert.Equal(t, retrievedSettings.SMTPFromName, updatedSettings.SMTPFromName)
	assert.Equal(t, retrievedSettings.SMTPFromEmail, updatedSettings.SMTPFromEmail)
	assert.Equal(t, retrievedSettings.SMTPEncryption, updatedSettings.SMTPEncryption)
	assert.Equal(t, retrievedSettings.SMTPEnabled, updatedSettings.SMTPEnabled)
	assert.Equal(t, retrievedSettings.SMSProvider, updatedSettings.SMSProvider)
	assert.Equal(t, retrievedSettings.SMSConfigEncrypted, updatedSettings.SMSConfigEncrypted)
}

func TestDatabase_MySQL_UserAttribute(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	userAttribute := &entitiesv2.UserAttribute{
		Key:                  "key1",
		Value:                "value1",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		UserId:               1,
	}

	err := databasev2.CreateUserAttribute(nil, userAttribute)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, userAttribute.Id, int64(0))
	assert.WithinDuration(t, userAttribute.CreatedAt.Time, userAttribute.UpdatedAt.Time, 2*time.Second)

	retrievedUserAttribute, err := databasev2.GetUserAttributeById(nil, userAttribute.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, userAttribute.Id, retrievedUserAttribute.Id)
	assert.WithinDuration(t, retrievedUserAttribute.CreatedAt.Time, retrievedUserAttribute.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, userAttribute.Key, retrievedUserAttribute.Key)
	assert.Equal(t, userAttribute.Value, retrievedUserAttribute.Value)
	assert.Equal(t, userAttribute.IncludeInIdToken, retrievedUserAttribute.IncludeInIdToken)
	assert.Equal(t, userAttribute.IncludeInAccessToken, retrievedUserAttribute.IncludeInAccessToken)
	assert.Equal(t, userAttribute.UserId, retrievedUserAttribute.UserId)

	retrievedUserAttribute.Key = "key2"
	retrievedUserAttribute.Value = "value2"
	retrievedUserAttribute.IncludeInIdToken = false
	retrievedUserAttribute.IncludeInAccessToken = false
	retrievedUserAttribute.UserId = 2

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedUserAttribute.UpdatedAt
	err = databasev2.UpdateUserAttribute(nil, retrievedUserAttribute)
	if err != nil {
		t.Fatal(err)
	}

	updatedUserAttribute, err := databasev2.GetUserAttributeById(nil, retrievedUserAttribute.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedUserAttribute.Id, updatedUserAttribute.Id)
	assert.WithinDuration(t, updatedUserAttribute.CreatedAt.Time, updatedUserAttribute.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedUserAttribute.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedUserAttribute.Key, updatedUserAttribute.Key)
	assert.Equal(t, retrievedUserAttribute.Value, updatedUserAttribute.Value)
	assert.Equal(t, retrievedUserAttribute.IncludeInIdToken, updatedUserAttribute.IncludeInIdToken)
	assert.Equal(t, retrievedUserAttribute.IncludeInAccessToken, updatedUserAttribute.IncludeInAccessToken)
	assert.Equal(t, retrievedUserAttribute.UserId, updatedUserAttribute.UserId)

	err = databasev2.DeleteUserAttribute(nil, updatedUserAttribute.Id)
	if err != nil {
		t.Fatal(err)
	}

	userAttribute, err = databasev2.GetUserAttributeById(nil, updatedUserAttribute.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, userAttribute)
}

func TestDatabase_MySQL_UserPermission(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	userPermission := &entitiesv2.UserPermission{
		UserId:       1,
		PermissionId: 1,
	}

	err := databasev2.CreateUserPermission(nil, userPermission)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, userPermission.Id, int64(0))
	assert.WithinDuration(t, userPermission.CreatedAt.Time, userPermission.UpdatedAt.Time, 2*time.Second)

	retrievedUserPermission, err := databasev2.GetUserPermissionById(nil, userPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, userPermission.Id, retrievedUserPermission.Id)
	assert.WithinDuration(t, retrievedUserPermission.CreatedAt.Time, retrievedUserPermission.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, userPermission.UserId, retrievedUserPermission.UserId)
	assert.Equal(t, userPermission.PermissionId, retrievedUserPermission.PermissionId)

	retrievedUserPermission.UserId = 2
	retrievedUserPermission.PermissionId = 2

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedUserPermission.UpdatedAt
	err = databasev2.UpdateUserPermission(nil, retrievedUserPermission)
	if err != nil {
		t.Fatal(err)
	}

	updatedUserPermission, err := databasev2.GetUserPermissionById(nil, retrievedUserPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedUserPermission.Id, updatedUserPermission.Id)
	assert.WithinDuration(t, updatedUserPermission.CreatedAt.Time, updatedUserPermission.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedUserPermission.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedUserPermission.UserId, updatedUserPermission.UserId)
	assert.Equal(t, retrievedUserPermission.PermissionId, updatedUserPermission.PermissionId)

	err = databasev2.DeleteUserPermission(nil, updatedUserPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	userPermission, err = databasev2.GetUserPermissionById(nil, updatedUserPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, userPermission)
}

func TestDatabase_MySQL_UserSession(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	userSession := &entitiesv2.UserSession{
		SessionIdentifier: gofakeit.UUID(),
		Started:           time.Now().UTC(),
		LastAccessed:      time.Now().UTC(),
		AuthMethods:       "password",
		AcrLevel:          "acr-1",
		AuthTime:          time.Now().UTC(),
		IpAddress:         gofakeit.IPv4Address(),
		DeviceName:        "device1",
		DeviceType:        "type1",
		DeviceOS:          "os1",
		UserId:            1,
	}

	err := databasev2.CreateUserSession(nil, userSession)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, userSession.Id, int64(0))
	assert.WithinDuration(t, userSession.CreatedAt.Time, userSession.UpdatedAt.Time, 2*time.Second)

	retrievedUserSession, err := databasev2.GetUserSessionById(nil, userSession.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, userSession.Id, retrievedUserSession.Id)
	assert.WithinDuration(t, retrievedUserSession.CreatedAt.Time, retrievedUserSession.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, userSession.SessionIdentifier, retrievedUserSession.SessionIdentifier)
	assert.Equal(t, userSession.Started.Truncate(time.Millisecond), retrievedUserSession.Started.Truncate(time.Millisecond))
	assert.Equal(t, userSession.LastAccessed.Truncate(time.Millisecond), retrievedUserSession.LastAccessed.Truncate(time.Millisecond))
	assert.Equal(t, userSession.AuthMethods, retrievedUserSession.AuthMethods)
	assert.Equal(t, userSession.AcrLevel, retrievedUserSession.AcrLevel)
	assert.Equal(t, userSession.AuthTime.Truncate(time.Millisecond), retrievedUserSession.AuthTime.Truncate(time.Millisecond))
	assert.Equal(t, userSession.IpAddress, retrievedUserSession.IpAddress)
	assert.Equal(t, userSession.DeviceName, retrievedUserSession.DeviceName)
	assert.Equal(t, userSession.DeviceType, retrievedUserSession.DeviceType)
	assert.Equal(t, userSession.DeviceOS, retrievedUserSession.DeviceOS)
	assert.Equal(t, userSession.UserId, retrievedUserSession.UserId)

	retrievedUserSession.SessionIdentifier = gofakeit.UUID()
	retrievedUserSession.Started = time.Now().UTC()
	retrievedUserSession.LastAccessed = time.Now().UTC()
	retrievedUserSession.AuthMethods = "password,otp"
	retrievedUserSession.AcrLevel = "acr-2"
	retrievedUserSession.AuthTime = time.Now().UTC()
	retrievedUserSession.IpAddress = gofakeit.IPv4Address()
	retrievedUserSession.DeviceName = "device2"
	retrievedUserSession.DeviceType = "type2"
	retrievedUserSession.DeviceOS = "os2"
	retrievedUserSession.UserId = 2

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedUserSession.UpdatedAt
	err = databasev2.UpdateUserSession(nil, retrievedUserSession)
	if err != nil {
		t.Fatal(err)
	}

	updatedUserSession, err := databasev2.GetUserSessionById(nil, retrievedUserSession.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedUserSession.Id, updatedUserSession.Id)
	assert.WithinDuration(t, updatedUserSession.CreatedAt.Time, updatedUserSession.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedUserSession.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedUserSession.SessionIdentifier, updatedUserSession.SessionIdentifier)
	assert.Equal(t, retrievedUserSession.Started.Truncate(time.Millisecond), updatedUserSession.Started.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUserSession.LastAccessed.Truncate(time.Millisecond), updatedUserSession.LastAccessed.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUserSession.AuthMethods, updatedUserSession.AuthMethods)
	assert.Equal(t, retrievedUserSession.AcrLevel, updatedUserSession.AcrLevel)
	assert.Equal(t, retrievedUserSession.AuthTime.Truncate(time.Millisecond), updatedUserSession.AuthTime.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUserSession.IpAddress, updatedUserSession.IpAddress)
	assert.Equal(t, retrievedUserSession.DeviceName, updatedUserSession.DeviceName)
	assert.Equal(t, retrievedUserSession.DeviceType, updatedUserSession.DeviceType)
	assert.Equal(t, retrievedUserSession.DeviceOS, updatedUserSession.DeviceOS)
	assert.Equal(t, retrievedUserSession.UserId, updatedUserSession.UserId)

	err = databasev2.DeleteUserSession(nil, updatedUserSession.Id)
	if err != nil {
		t.Fatal(err)
	}

	userSession, err = databasev2.GetUserSessionById(nil, updatedUserSession.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, userSession)
}

func TestDatabase_MySQL_UserConsent(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	userConsent := &entitiesv2.UserConsent{
		UserId:    1,
		ClientId:  1,
		Scope:     "openid profile email",
		GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
	}

	err := databasev2.CreateUserConsent(nil, userConsent)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, userConsent.Id, int64(0))
	assert.WithinDuration(t, userConsent.CreatedAt.Time, userConsent.UpdatedAt.Time, 2*time.Second)

	retrievedUserConsent, err := databasev2.GetUserConsentById(nil, userConsent.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, userConsent.Id, retrievedUserConsent.Id)
	assert.WithinDuration(t, retrievedUserConsent.CreatedAt.Time, retrievedUserConsent.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, userConsent.UserId, retrievedUserConsent.UserId)
	assert.Equal(t, userConsent.ClientId, retrievedUserConsent.ClientId)
	assert.Equal(t, userConsent.Scope, retrievedUserConsent.Scope)
	assert.Equal(t, userConsent.GrantedAt.Time.Truncate(time.Millisecond), retrievedUserConsent.GrantedAt.Time.Truncate(time.Millisecond))

	retrievedUserConsent.UserId = 2
	retrievedUserConsent.ClientId = 2
	retrievedUserConsent.Scope = "openid profile email address"
	retrievedUserConsent.GrantedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedUserConsent.UpdatedAt
	err = databasev2.UpdateUserConsent(nil, retrievedUserConsent)
	if err != nil {
		t.Fatal(err)
	}

	updatedUserConsent, err := databasev2.GetUserConsentById(nil, retrievedUserConsent.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedUserConsent.Id, updatedUserConsent.Id)
	assert.WithinDuration(t, updatedUserConsent.CreatedAt.Time, updatedUserConsent.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedUserConsent.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedUserConsent.UserId, updatedUserConsent.UserId)
	assert.Equal(t, retrievedUserConsent.ClientId, updatedUserConsent.ClientId)
	assert.Equal(t, retrievedUserConsent.Scope, updatedUserConsent.Scope)
	assert.Equal(t, retrievedUserConsent.GrantedAt.Time.Truncate(time.Millisecond), updatedUserConsent.GrantedAt.Time.Truncate(time.Millisecond))

	err = databasev2.DeleteUserConsent(nil, updatedUserConsent.Id)
	if err != nil {
		t.Fatal(err)
	}

	userConsent, err = databasev2.GetUserConsentById(nil, updatedUserConsent.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, userConsent)
}

func TestDatabase_MySQL_PreRegistration(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	now := time.Now().UTC()

	preRegistration := &entitiesv2.PreRegistration{
		Email:                     gofakeit.Email(),
		PasswordHash:              gofakeit.UUID(),
		VerificationCodeEncrypted: []byte{1, 2, 3, 4, 5},
		VerificationCodeIssuedAt:  sql.NullTime{Time: now, Valid: true},
	}

	err := databasev2.CreatePreRegistration(nil, preRegistration)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, preRegistration.Id, int64(0))
	assert.WithinDuration(t, preRegistration.CreatedAt.Time, preRegistration.UpdatedAt.Time, 2*time.Second)

	retrievedPreRegistration, err := databasev2.GetPreRegistrationById(nil, preRegistration.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, preRegistration.Id, retrievedPreRegistration.Id)
	assert.WithinDuration(t, retrievedPreRegistration.CreatedAt.Time, retrievedPreRegistration.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, preRegistration.Email, retrievedPreRegistration.Email)
	assert.Equal(t, preRegistration.PasswordHash, retrievedPreRegistration.PasswordHash)
	assert.Equal(t, preRegistration.VerificationCodeEncrypted, retrievedPreRegistration.VerificationCodeEncrypted)
	assert.Equal(t, preRegistration.VerificationCodeIssuedAt.Time.Truncate(time.Millisecond), retrievedPreRegistration.VerificationCodeIssuedAt.Time.Truncate(time.Millisecond))

	now = time.Now().UTC()

	retrievedPreRegistration.Email = gofakeit.Email()
	retrievedPreRegistration.PasswordHash = gofakeit.UUID()
	retrievedPreRegistration.VerificationCodeEncrypted = []byte{5, 4, 3, 2, 1}
	retrievedPreRegistration.VerificationCodeIssuedAt = sql.NullTime{Time: now, Valid: true}

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedPreRegistration.UpdatedAt
	err = databasev2.UpdatePreRegistration(nil, retrievedPreRegistration)
	if err != nil {
		t.Fatal(err)
	}

	updatedPreRegistration, err := databasev2.GetPreRegistrationById(nil, retrievedPreRegistration.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedPreRegistration.Id, updatedPreRegistration.Id)
	assert.WithinDuration(t, updatedPreRegistration.CreatedAt.Time, updatedPreRegistration.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedPreRegistration.UpdatedAt.Time, updatedAt)
	assert.Equal(t, retrievedPreRegistration.Email, updatedPreRegistration.Email)
	assert.Equal(t, retrievedPreRegistration.PasswordHash, updatedPreRegistration.PasswordHash)
	assert.Equal(t, retrievedPreRegistration.VerificationCodeEncrypted, updatedPreRegistration.VerificationCodeEncrypted)
	assert.Equal(t, retrievedPreRegistration.VerificationCodeIssuedAt.Time.Truncate(time.Millisecond), updatedPreRegistration.VerificationCodeIssuedAt.Time.Truncate(time.Millisecond))

	err = databasev2.DeletePreRegistration(nil, updatedPreRegistration.Id)
	if err != nil {
		t.Fatal(err)
	}

	preRegistration, err = databasev2.GetPreRegistrationById(nil, updatedPreRegistration.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, preRegistration)
}

func TestDatabase_MySQL_UserGroup(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	userGroup := &entitiesv2.UserGroup{
		UserId:  1,
		GroupId: 1,
	}

	err := databasev2.CreateUserGroup(nil, userGroup)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, userGroup.Id, int64(0))
	assert.WithinDuration(t, userGroup.CreatedAt.Time, userGroup.UpdatedAt.Time, 2*time.Second)

	retrievedUserGroup, err := databasev2.GetUserGroupById(nil, userGroup.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, userGroup.Id, retrievedUserGroup.Id)
	assert.WithinDuration(t, retrievedUserGroup.CreatedAt.Time, retrievedUserGroup.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, userGroup.UserId, retrievedUserGroup.UserId)
	assert.Equal(t, userGroup.GroupId, retrievedUserGroup.GroupId)

	retrievedUserGroup.UserId = 2
	retrievedUserGroup.GroupId = 2

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedUserGroup.UpdatedAt

	err = databasev2.UpdateUserGroup(nil, retrievedUserGroup)
	if err != nil {
		t.Fatal(err)
	}

	updatedUserGroup, err := databasev2.GetUserGroupById(nil, retrievedUserGroup.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedUserGroup.Id, updatedUserGroup.Id)
	assert.WithinDuration(t, updatedUserGroup.CreatedAt.Time, updatedUserGroup.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedUserGroup.UpdatedAt.Time, updatedAt.Time)
	assert.Equal(t, retrievedUserGroup.UserId, updatedUserGroup.UserId)
	assert.Equal(t, retrievedUserGroup.GroupId, updatedUserGroup.GroupId)

	err = databasev2.DeleteUserGroup(nil, updatedUserGroup.Id)
	if err != nil {
		t.Fatal(err)
	}

	userGroup, err = databasev2.GetUserGroupById(nil, updatedUserGroup.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, userGroup)
}

func TestDatabase_MySQL_GroupAttribute(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	groupAttribute := &entitiesv2.GroupAttribute{
		Key:                  "key1",
		Value:                "value1",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		GroupId:              1,
	}

	err := databasev2.CreateGroupAttribute(nil, groupAttribute)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, groupAttribute.Id, int64(0))
	assert.WithinDuration(t, groupAttribute.CreatedAt.Time, groupAttribute.UpdatedAt.Time, 2*time.Second)

	retrievedGroupAttribute, err := databasev2.GetGroupAttributeById(nil, groupAttribute.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, groupAttribute.Id, retrievedGroupAttribute.Id)
	assert.WithinDuration(t, retrievedGroupAttribute.CreatedAt.Time, retrievedGroupAttribute.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, groupAttribute.Key, retrievedGroupAttribute.Key)
	assert.Equal(t, groupAttribute.Value, retrievedGroupAttribute.Value)
	assert.Equal(t, groupAttribute.IncludeInIdToken, retrievedGroupAttribute.IncludeInIdToken)
	assert.Equal(t, groupAttribute.IncludeInAccessToken, retrievedGroupAttribute.IncludeInAccessToken)
	assert.Equal(t, groupAttribute.GroupId, retrievedGroupAttribute.GroupId)

	retrievedGroupAttribute.Key = "key2"
	retrievedGroupAttribute.Value = "value2"
	retrievedGroupAttribute.IncludeInIdToken = false
	retrievedGroupAttribute.IncludeInAccessToken = false
	retrievedGroupAttribute.GroupId = 2

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedGroupAttribute.UpdatedAt
	err = databasev2.UpdateGroupAttribute(nil, retrievedGroupAttribute)
	if err != nil {
		t.Fatal(err)
	}

	updatedGroupAttribute, err := databasev2.GetGroupAttributeById(nil, retrievedGroupAttribute.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedGroupAttribute.Id, updatedGroupAttribute.Id)
	assert.WithinDuration(t, updatedGroupAttribute.CreatedAt.Time, updatedGroupAttribute.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedGroupAttribute.UpdatedAt.Time, updatedAt.Time)
	assert.Equal(t, retrievedGroupAttribute.Key, updatedGroupAttribute.Key)
	assert.Equal(t, retrievedGroupAttribute.Value, updatedGroupAttribute.Value)
	assert.Equal(t, retrievedGroupAttribute.IncludeInIdToken, updatedGroupAttribute.IncludeInIdToken)
	assert.Equal(t, retrievedGroupAttribute.IncludeInAccessToken, updatedGroupAttribute.IncludeInAccessToken)
	assert.Equal(t, retrievedGroupAttribute.GroupId, updatedGroupAttribute.GroupId)

	err = databasev2.DeleteGroupAttribute(nil, updatedGroupAttribute.Id)
	if err != nil {
		t.Fatal(err)
	}

	groupAttribute, err = databasev2.GetGroupAttributeById(nil, updatedGroupAttribute.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, groupAttribute)
}

func TestDatabase_MySQL_GroupPermission(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	groupPermission := &entitiesv2.GroupPermission{
		GroupId:      1,
		PermissionId: 1,
	}

	err := databasev2.CreateGroupPermission(nil, groupPermission)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, groupPermission.Id, int64(0))
	assert.WithinDuration(t, groupPermission.CreatedAt.Time, groupPermission.UpdatedAt.Time, 2*time.Second)

	retrievedGroupPermission, err := databasev2.GetGroupPermissionById(nil, groupPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, groupPermission.Id, retrievedGroupPermission.Id)
	assert.WithinDuration(t, retrievedGroupPermission.CreatedAt.Time, retrievedGroupPermission.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, groupPermission.GroupId, retrievedGroupPermission.GroupId)
	assert.Equal(t, groupPermission.PermissionId, retrievedGroupPermission.PermissionId)

	retrievedGroupPermission.GroupId = 2
	retrievedGroupPermission.PermissionId = 2

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedGroupPermission.UpdatedAt
	err = databasev2.UpdateGroupPermission(nil, retrievedGroupPermission)
	if err != nil {
		t.Fatal(err)
	}

	updatedGroupPermission, err := databasev2.GetGroupPermissionById(nil, retrievedGroupPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedGroupPermission.Id, updatedGroupPermission.Id)
	assert.WithinDuration(t, updatedGroupPermission.CreatedAt.Time, updatedGroupPermission.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedGroupPermission.UpdatedAt.Time, updatedAt.Time)
	assert.Equal(t, retrievedGroupPermission.GroupId, updatedGroupPermission.GroupId)
	assert.Equal(t, retrievedGroupPermission.PermissionId, updatedGroupPermission.PermissionId)

	err = databasev2.DeleteGroupPermission(nil, updatedGroupPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	groupPermission, err = databasev2.GetGroupPermissionById(nil, updatedGroupPermission.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, groupPermission)
}

func TestDatabase_MySQL_RefreshToken(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	code := &entitiesv2.Code{
		CodeHash:        gofakeit.UUID(),
		ClientId:        1,
		UserId:          1,
		AuthenticatedAt: time.Now().UTC(),
	}
	err := databasev2.CreateCode(nil, code)
	if err != nil {
		t.Fatal(err)
	}

	code = &entitiesv2.Code{
		CodeHash:        gofakeit.UUID(),
		ClientId:        1,
		UserId:          1,
		AuthenticatedAt: time.Now().UTC(),
	}
	err = databasev2.CreateCode(nil, code)
	if err != nil {
		t.Fatal(err)
	}

	refreshToken := &entitiesv2.RefreshToken{
		CodeId:                  1,
		RefreshTokenJti:         gofakeit.UUID(),
		PreviousRefreshTokenJti: gofakeit.UUID(),
		FirstRefreshTokenJti:    gofakeit.UUID(),
		SessionIdentifier:       gofakeit.UUID(),
		RefreshTokenType:        "offline",
		Scope:                   "openid profile email",
		IssuedAt:                sql.NullTime{Time: time.Now().UTC(), Valid: true},
		ExpiresAt:               sql.NullTime{Time: time.Now().UTC().Add(3600 * time.Second), Valid: true},
		Revoked:                 true,
	}

	err = databasev2.CreateRefreshToken(nil, refreshToken)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, refreshToken.Id, int64(0))
	assert.WithinDuration(t, refreshToken.CreatedAt.Time, refreshToken.UpdatedAt.Time, 2*time.Second)

	retrievedRefreshToken, err := databasev2.GetRefreshTokenById(nil, refreshToken.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, refreshToken.Id, retrievedRefreshToken.Id)
	assert.WithinDuration(t, retrievedRefreshToken.CreatedAt.Time, retrievedRefreshToken.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, refreshToken.CodeId, retrievedRefreshToken.CodeId)
	assert.Equal(t, refreshToken.RefreshTokenJti, retrievedRefreshToken.RefreshTokenJti)
	assert.Equal(t, refreshToken.PreviousRefreshTokenJti, retrievedRefreshToken.PreviousRefreshTokenJti)
	assert.Equal(t, refreshToken.FirstRefreshTokenJti, retrievedRefreshToken.FirstRefreshTokenJti)
	assert.Equal(t, refreshToken.SessionIdentifier, retrievedRefreshToken.SessionIdentifier)
	assert.Equal(t, refreshToken.RefreshTokenType, retrievedRefreshToken.RefreshTokenType)
	assert.Equal(t, refreshToken.Scope, retrievedRefreshToken.Scope)
	assert.Equal(t, refreshToken.IssuedAt.Time.Truncate(time.Millisecond), retrievedRefreshToken.IssuedAt.Time.Truncate(time.Millisecond))
	assert.Equal(t, refreshToken.ExpiresAt.Time.Truncate(time.Millisecond), retrievedRefreshToken.ExpiresAt.Time.Truncate(time.Millisecond))
	assert.Equal(t, refreshToken.Revoked, retrievedRefreshToken.Revoked)

	retrievedRefreshToken.CodeId = 2
	retrievedRefreshToken.RefreshTokenJti = gofakeit.UUID()
	retrievedRefreshToken.PreviousRefreshTokenJti = gofakeit.UUID()
	retrievedRefreshToken.FirstRefreshTokenJti = gofakeit.UUID()
	retrievedRefreshToken.SessionIdentifier = gofakeit.UUID()
	retrievedRefreshToken.RefreshTokenType = "offline_access"
	retrievedRefreshToken.Scope = "openid profile email address"
	retrievedRefreshToken.IssuedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	retrievedRefreshToken.ExpiresAt = sql.NullTime{Time: time.Now().UTC().Add(7200 * time.Second), Valid: true}
	retrievedRefreshToken.Revoked = false

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedRefreshToken.UpdatedAt
	err = databasev2.UpdateRefreshToken(nil, retrievedRefreshToken)
	if err != nil {
		t.Fatal(err)
	}

	updatedRefreshToken, err := databasev2.GetRefreshTokenById(nil, retrievedRefreshToken.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedRefreshToken.Id, updatedRefreshToken.Id)
	assert.WithinDuration(t, updatedRefreshToken.CreatedAt.Time, updatedRefreshToken.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedRefreshToken.UpdatedAt.Time, updatedAt.Time)
	assert.Equal(t, retrievedRefreshToken.CodeId, updatedRefreshToken.CodeId)
	assert.Equal(t, retrievedRefreshToken.RefreshTokenJti, updatedRefreshToken.RefreshTokenJti)
	assert.Equal(t, retrievedRefreshToken.PreviousRefreshTokenJti, updatedRefreshToken.PreviousRefreshTokenJti)
	assert.Equal(t, retrievedRefreshToken.FirstRefreshTokenJti, updatedRefreshToken.FirstRefreshTokenJti)
	assert.Equal(t, retrievedRefreshToken.SessionIdentifier, updatedRefreshToken.SessionIdentifier)
	assert.Equal(t, retrievedRefreshToken.RefreshTokenType, updatedRefreshToken.RefreshTokenType)
	assert.Equal(t, retrievedRefreshToken.Scope, updatedRefreshToken.Scope)

	err = databasev2.DeleteRefreshToken(nil, updatedRefreshToken.Id)
	if err != nil {
		t.Fatal(err)
	}

	refreshToken, err = databasev2.GetRefreshTokenById(nil, updatedRefreshToken.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, refreshToken)
}

func TestDatabase_MySQL_UserSessionClient(t *testing.T) {
	TestDatabase_MySQL_Setup(t)

	userSession := &entitiesv2.UserSession{
		SessionIdentifier: gofakeit.UUID(),
		UserId:            1,
		Started:           time.Now().UTC(),
		LastAccessed:      time.Now().UTC(),
		AuthTime:          time.Now().UTC(),
	}

	err := databasev2.CreateUserSession(nil, userSession)
	if err != nil {
		t.Fatal(err)
	}

	userSession = &entitiesv2.UserSession{
		SessionIdentifier: gofakeit.UUID(),
		UserId:            1,
		Started:           time.Now().UTC(),
		LastAccessed:      time.Now().UTC(),
		AuthTime:          time.Now().UTC(),
	}

	err = databasev2.CreateUserSession(nil, userSession)
	if err != nil {
		t.Fatal(err)
	}

	userSessionClient := &entitiesv2.UserSessionClient{
		UserSessionId: 1,
		ClientId:      1,
		Started:       time.Now().UTC(),
		LastAccessed:  time.Now().UTC(),
	}

	err = databasev2.CreateUserSessionClient(nil, userSessionClient)
	if err != nil {
		t.Fatal(err)
	}

	assert.Greater(t, userSessionClient.Id, int64(0))
	assert.WithinDuration(t, userSessionClient.CreatedAt.Time, userSessionClient.UpdatedAt.Time, 2*time.Second)

	retrievedUserSessionClient, err := databasev2.GetUserSessionClientById(nil, userSessionClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, userSessionClient.Id, retrievedUserSessionClient.Id)
	assert.WithinDuration(t, retrievedUserSessionClient.CreatedAt.Time, retrievedUserSessionClient.UpdatedAt.Time, 2*time.Second)
	assert.Equal(t, userSessionClient.UserSessionId, retrievedUserSessionClient.UserSessionId)
	assert.Equal(t, userSessionClient.ClientId, retrievedUserSessionClient.ClientId)
	assert.Equal(t, userSessionClient.Started.Truncate(time.Millisecond), retrievedUserSessionClient.Started.Truncate(time.Millisecond))
	assert.Equal(t, userSessionClient.LastAccessed.Truncate(time.Millisecond), retrievedUserSessionClient.LastAccessed.Truncate(time.Millisecond))

	retrievedUserSessionClient.UserSessionId = 2
	retrievedUserSessionClient.ClientId = 2
	retrievedUserSessionClient.Started = time.Now().UTC()
	retrievedUserSessionClient.LastAccessed = time.Now().UTC()

	time.Sleep(100 * time.Millisecond)
	updatedAt := retrievedUserSessionClient.UpdatedAt
	err = databasev2.UpdateUserSessionClient(nil, retrievedUserSessionClient)
	if err != nil {
		t.Fatal(err)
	}

	updatedUserSessionClient, err := databasev2.GetUserSessionClientById(nil, retrievedUserSessionClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, retrievedUserSessionClient.Id, updatedUserSessionClient.Id)
	assert.WithinDuration(t, updatedUserSessionClient.CreatedAt.Time, updatedUserSessionClient.UpdatedAt.Time, 2*time.Second)
	assert.Greater(t, updatedUserSessionClient.UpdatedAt.Time, updatedAt.Time)
	assert.Equal(t, retrievedUserSessionClient.UserSessionId, updatedUserSessionClient.UserSessionId)
	assert.Equal(t, retrievedUserSessionClient.ClientId, updatedUserSessionClient.ClientId)
	assert.Equal(t, retrievedUserSessionClient.Started.Truncate(time.Millisecond), updatedUserSessionClient.Started.Truncate(time.Millisecond))
	assert.Equal(t, retrievedUserSessionClient.LastAccessed.Truncate(time.Millisecond), updatedUserSessionClient.LastAccessed.Truncate(time.Millisecond))

	err = databasev2.DeleteUserSessionClient(nil, updatedUserSessionClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	userSessionClient, err = databasev2.GetUserSessionClientById(nil, updatedUserSessionClient.Id)
	if err != nil {
		t.Fatal(err)
	}

	assert.Nil(t, userSessionClient)
}
