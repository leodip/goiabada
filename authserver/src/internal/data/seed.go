package data

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

func seed(database Database) error {

	encryptionKey := securecookie.GenerateRandomKey(32)

	clientSecret := lib.GenerateSecureRandomString(60)
	clientSecretEncrypted, _ := lib.EncryptText(clientSecret, encryptionKey)

	client1 := &entities.Client{
		ClientIdentifier:                        constants.SystemClientIdentifier,
		Description:                             "Website client (system-level)",
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

	var redirectURI = &entities.RedirectURI{
		URI:      lib.GetBaseUrl() + "/auth/callback",
		ClientId: client1.Id,
	}
	err = database.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		return err
	}

	adminEmail := viper.GetString("Admin.Email")
	if len(adminEmail) == 0 {
		const defaultAdminEmail = "admin@example.com"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_ADMIN_EMAIL is not set. Will default admin email to '%v'", defaultAdminEmail))
		adminEmail = defaultAdminEmail
	}

	adminPassword := viper.GetString("Admin.Password")
	if len(adminPassword) == 0 {
		const defaultAdminPassword = "admin123"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_ADMIN_PASSWORD is not set. Will default admin password to '%v'", defaultAdminPassword))
		adminPassword = defaultAdminPassword
	}

	passwordHash, _ := lib.HashPassword(adminPassword)

	user := &entities.User{
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

	resource := &entities.Resource{
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
		Description:        "Authorization server (system-level)",
	}
	err = database.CreateResource(nil, resource)
	if err != nil {
		return err
	}

	permission1 := &entities.Permission{
		PermissionIdentifier: constants.UserinfoPermissionIdentifier,
		Description:          "Access to the OpenID Connect user info endpoint",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission1)
	if err != nil {
		return err
	}

	permission2 := &entities.Permission{
		PermissionIdentifier: constants.ManageAccountPermissionIdentifier,
		Description:          "View and update user account data for the current user",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission2)
	if err != nil {
		return err
	}

	permission3 := &entities.Permission{
		PermissionIdentifier: constants.AdminWebsitePermissionIdentifier,
		Description:          "Manage the authorization server settings via the web interface",
		ResourceId:           resource.Id,
	}
	err = database.CreatePermission(nil, permission3)
	if err != nil {
		return err
	}

	err = database.CreateUserPermission(nil, &entities.UserPermission{
		UserId:       user.Id,
		PermissionId: permission2.Id,
	})
	if err != nil {
		return err
	}

	err = database.CreateUserPermission(nil, &entities.UserPermission{
		UserId:       user.Id,
		PermissionId: permission3.Id,
	})
	if err != nil {
		return err
	}

	// key pair (current)

	privateKey, err := lib.GeneratePrivateKey(4096)
	if err != nil {
		return errors.Wrap(err, "unable to generate a private key")
	}
	privateKeyPEM := lib.EncodePrivateKeyToPEM(privateKey)

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
	publicKeyJWK, err := lib.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
	if err != nil {
		return err
	}

	keyPair := &entities.KeyPair{
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
	privateKey, err = lib.GeneratePrivateKey(4096)
	if err != nil {
		return errors.Wrap(err, "unable to generate a private key")
	}
	privateKeyPEM = lib.EncodePrivateKeyToPEM(privateKey)

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
	publicKeyJWK, err = lib.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
	if err != nil {
		return err
	}

	keyPair = &entities.KeyPair{
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

	appName := viper.GetString("AppName")
	if len(appName) == 0 {
		appName = "Goiabada"
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_APPNAME is not set. Will default app name to '%v'", appName))
	}

	issuer := viper.GetString("Issuer")
	if len(issuer) == 0 {
		baseUrl := lib.GetBaseUrl()
		if len(baseUrl) > 0 {
			issuer = lib.GetBaseUrl()
		} else {
			issuer = "https://goiabada.dev"
		}
		slog.Warn(fmt.Sprintf("Environment variable GOIABADA_ISSUER is not set. Will default issuer to '%v'", issuer))
	}

	settings := &entities.Settings{
		AppName:                 appName,
		Issuer:                  issuer,
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
