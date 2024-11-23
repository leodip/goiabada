package data

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/rsautil"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/pkg/errors"
)

type DatabaseSeeder struct {
	DB Database
}

func NewDatabaseSeeder(database Database) *DatabaseSeeder {
	return &DatabaseSeeder{
		DB: database,
	}
}

func (ds *DatabaseSeeder) Seed() error {

	encryptionKey := securecookie.GenerateRandomKey(32)

	clientSecret := stringutil.GenerateSecurityRandomString(60)
	clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, encryptionKey)

	client1 := &models.Client{
		ClientIdentifier:                        constants.AdminConsoleClientIdentifier,
		Description:                             "Admin console client (system-level)",
		Enabled:                                 true,
		ConsentRequired:                         false,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		DefaultAcrLevel:                         enums.AcrLevel2Optional,
		ClientCredentialsEnabled:                false,
		ClientSecretEncrypted:                   clientSecretEncrypted,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
	}

	err := ds.DB.CreateClient(nil, client1)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("client '%v' created", client1.ClientIdentifier))

	var redirectURI = &models.RedirectURI{
		URI:      config.GetAdminConsole().BaseURL + "/auth/callback",
		ClientId: client1.Id,
	}
	err = ds.DB.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("redirect URI '%v' created", redirectURI.URI))

	redirectURI = &models.RedirectURI{
		URI:      config.GetAdminConsole().BaseURL,
		ClientId: client1.Id,
	}
	err = ds.DB.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("redirect URI '%v' created", redirectURI.URI))

	adminEmail := config.GetAdminEmail()
	if len(adminEmail) == 0 {
		const defaultAdminEmail = "admin@example.com"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_ADMIN_EMAIL is not set. Will default admin email to '%v'", defaultAdminEmail))
		adminEmail = defaultAdminEmail
	}

	adminPassword := config.GetAdminPassword()
	if len(adminPassword) == 0 {
		const defaultAdminPassword = "changeme"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_ADMIN_PASSWORD is not set. Will default admin password to '%v'", defaultAdminPassword))
		adminPassword = defaultAdminPassword
	}

	passwordHash, _ := hashutil.HashPassword(adminPassword)

	user := &models.User{
		Subject:       uuid.New(),
		Email:         adminEmail,
		EmailVerified: true,
		PasswordHash:  passwordHash,
		Enabled:       true,
	}
	err = ds.DB.CreateUser(nil, user)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("user '%v' created", user.Email))

	resource1 := &models.Resource{
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
		Description:        "Authorization server (system-level)",
	}
	err = ds.DB.CreateResource(nil, resource1)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("resource '%v' created", resource1.ResourceIdentifier))

	resource2 := &models.Resource{
		ResourceIdentifier: constants.AdminConsoleResourceIdentifier,
		Description:        "Admin console (system-level)",
	}
	err = ds.DB.CreateResource(nil, resource2)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("resource '%v' created", resource2.ResourceIdentifier))

	permission1 := &models.Permission{
		PermissionIdentifier: constants.UserinfoPermissionIdentifier,
		Description:          "Access to the OpenID Connect user info endpoint",
		ResourceId:           resource1.Id,
	}
	err = ds.DB.CreatePermission(nil, permission1)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permission1.PermissionIdentifier))

	permission2 := &models.Permission{
		PermissionIdentifier: constants.ManageAccountPermissionIdentifier,
		Description:          "View and update user account data for the current user",
		ResourceId:           resource2.Id,
	}
	err = ds.DB.CreatePermission(nil, permission2)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permission2.PermissionIdentifier))

	permission3 := &models.Permission{
		PermissionIdentifier: constants.ManageAdminConsolePermissionIdentifier,
		Description:          "Manage the authorization server via the admin console",
		ResourceId:           resource2.Id,
	}
	err = ds.DB.CreatePermission(nil, permission3)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permission3.PermissionIdentifier))

	err = ds.DB.CreateUserPermission(nil, &models.UserPermission{
		UserId:       user.Id,
		PermissionId: permission2.Id,
	})
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("user '%v' granted permission '%v'", user.Email, permission2.PermissionIdentifier))

	err = ds.DB.CreateUserPermission(nil, &models.UserPermission{
		UserId:       user.Id,
		PermissionId: permission3.Id,
	})
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("user '%v' granted permission '%v'", user.Email, permission3.PermissionIdentifier))

	// key pair (current)

	privateKey, err := rsautil.GeneratePrivateKey(4096)
	if err != nil {
		return errors.Wrap(err, "unable to generate a private key")
	}
	privateKeyPEM := rsautil.EncodePrivateKeyToPEM(privateKey)

	publicKeyASN1_DER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return errors.Wrap(err, "unable to marshal public key to PKIX")
	}

	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyASN1_DER,
		},
	)

	kid := uuid.New().String()
	publicKeyJWK, err := rsautil.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
	if err != nil {
		return err
	}

	keyPair := &models.KeyPair{
		State:             enums.KeyStateCurrent.String(),
		KeyIdentifier:     kid,
		Type:              "RSA",
		Algorithm:         "RS256",
		PrivateKeyPEM:     privateKeyPEM,
		PublicKeyPEM:      publicKeyPEM,
		PublicKeyASN1_DER: publicKeyASN1_DER,
		PublicKeyJWK:      publicKeyJWK,
	}
	err = ds.DB.CreateKeyPair(nil, keyPair)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("key pair '%v' (current) created", keyPair.KeyIdentifier))

	// key pair (next)
	privateKey, err = rsautil.GeneratePrivateKey(4096)
	if err != nil {
		return errors.Wrap(err, "unable to generate a private key")
	}
	privateKeyPEM = rsautil.EncodePrivateKeyToPEM(privateKey)

	publicKeyASN1_DER, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return errors.Wrap(err, "unable to marshal public key to PKIX")
	}

	publicKeyPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyASN1_DER,
		},
	)

	kid = uuid.New().String()
	publicKeyJWK, err = rsautil.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
	if err != nil {
		return err
	}

	keyPair = &models.KeyPair{
		State:             enums.KeyStateNext.String(),
		KeyIdentifier:     kid,
		Type:              "RSA",
		Algorithm:         "RS256",
		PrivateKeyPEM:     privateKeyPEM,
		PublicKeyPEM:      publicKeyPEM,
		PublicKeyASN1_DER: publicKeyASN1_DER,
		PublicKeyJWK:      publicKeyJWK,
	}
	err = ds.DB.CreateKeyPair(nil, keyPair)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("key pair '%v' (next) created", keyPair.KeyIdentifier))

	appName := config.GetAppName()
	if len(appName) == 0 {
		appName = "Goiabada"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_APPNAME is not set. Will default app name to '%v'", appName))
	}

	settings := &models.Settings{
		AppName:                 appName,
		Issuer:                  config.Get().BaseURL,
		UITheme:                 "",
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: false,
		PasswordPolicy:                          enums.PasswordPolicyLow,
		SessionAuthenticationKey:                securecookie.GenerateRandomKey(64),
		SessionEncryptionKey:                    securecookie.GenerateRandomKey(32),
		AESEncryptionKey:                        encryptionKey,
		TokenExpirationInSeconds:                300,      // 5 minutes
		RefreshTokenOfflineIdleTimeoutInSeconds: 2592000,  // 30 days
		RefreshTokenOfflineMaxLifetimeInSeconds: 31536000, // 1 year
		UserSessionIdleTimeoutInSeconds:         7200,     // 2 hours
		UserSessionMaxLifetimeInSeconds:         86400,    // 24 hours
		IncludeOpenIDConnectClaimsInAccessToken: false,
	}
	err = ds.DB.CreateSettings(nil, settings)
	if err != nil {
		return err
	}
	slog.Info("settings created")

	slog.Info("database seeded")

	return nil
}
