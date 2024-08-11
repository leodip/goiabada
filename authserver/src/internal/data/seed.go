package data

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/enums"
	"github.com/leodip/goiabada/authserver/internal/hashutil"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/rsautil"
	"github.com/leodip/goiabada/authserver/internal/stringutil"
	"github.com/pkg/errors"
)

func seed(database Database) error {

	encryptionKey := securecookie.GenerateRandomKey(32)

	clientSecret := stringutil.GenerateSecureRandomString(60)
	clientSecretEncrypted, _ := encryption.EncryptText(clientSecret, encryptionKey)

	client1 := &models.Client{
		ClientIdentifier:                        constants.AdminConsoleClientIdentifier,
		Description:                             "Admin console client (system-level)",
		Enabled:                                 true,
		ConsentRequired:                         false,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		DefaultAcrLevel:                         enums.AcrLevel2,
		ClientCredentialsEnabled:                false,
		ClientSecretEncrypted:                   clientSecretEncrypted,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
	}

	err := database.CreateClient(nil, client1)
	if err != nil {
		return err
	}

	var redirectURI = &models.RedirectURI{
		URI:      config.AdminConsoleBaseUrl + "/auth/callback",
		ClientId: client1.Id,
	}
	err = database.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		return err
	}

	redirectURI = &models.RedirectURI{
		URI:      config.AdminConsoleBaseUrl,
		ClientId: client1.Id,
	}
	err = database.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		return err
	}

	adminEmail := config.AdminEmail
	if len(adminEmail) == 0 {
		const defaultAdminEmail = "admin@example.com"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_ADMIN_EMAIL is not set. Will default admin email to '%v'", defaultAdminEmail))
		adminEmail = defaultAdminEmail
	}

	adminPassword := config.AdminPassword
	if len(adminPassword) == 0 {
		const defaultAdminPassword = "admin123"
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
	err = database.CreateUser(nil, user)
	if err != nil {
		return err
	}

	resource1 := &models.Resource{
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
		Description:        "Authorization server (system-level)",
	}
	err = database.CreateResource(nil, resource1)
	if err != nil {
		return err
	}

	resource2 := &models.Resource{
		ResourceIdentifier: constants.AdminConsoleResourceIdentifier,
		Description:        "Admin console (system-level)",
	}
	err = database.CreateResource(nil, resource2)
	if err != nil {
		return err
	}

	permission1 := &models.Permission{
		PermissionIdentifier: constants.UserinfoPermissionIdentifier,
		Description:          "Access to the OpenID Connect user info endpoint",
		ResourceId:           resource1.Id,
	}
	err = database.CreatePermission(nil, permission1)
	if err != nil {
		return err
	}

	permission2 := &models.Permission{
		PermissionIdentifier: constants.ManageAccountPermissionIdentifier,
		Description:          "View and update user account data for the current user",
		ResourceId:           resource2.Id,
	}
	err = database.CreatePermission(nil, permission2)
	if err != nil {
		return err
	}

	permission3 := &models.Permission{
		PermissionIdentifier: constants.ManageAdminConsolePermissionIdentifier,
		Description:          "Manage the authorization server via the admin console",
		ResourceId:           resource2.Id,
	}
	err = database.CreatePermission(nil, permission3)
	if err != nil {
		return err
	}

	err = database.CreateUserPermission(nil, &models.UserPermission{
		UserId:       user.Id,
		PermissionId: permission2.Id,
	})
	if err != nil {
		return err
	}

	err = database.CreateUserPermission(nil, &models.UserPermission{
		UserId:       user.Id,
		PermissionId: permission3.Id,
	})
	if err != nil {
		return err
	}

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
	err = database.CreateKeyPair(nil, keyPair)
	if err != nil {
		return err
	}

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
	err = database.CreateKeyPair(nil, keyPair)
	if err != nil {
		return err
	}

	appName := config.AppName
	if len(appName) == 0 {
		appName = "Goiabada"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_APPNAME is not set. Will default app name to '%v'", appName))
	}

	settings := &models.Settings{
		AppName:                 appName,
		Issuer:                  config.AuthServerBaseUrl,
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
	err = database.CreateSettings(nil, settings)
	if err != nil {
		return err
	}

	return nil
}
