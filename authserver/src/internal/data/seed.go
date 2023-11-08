package data

import (
	b64 "encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"golang.org/x/exp/slog"
)

func (d *Database) seed() error {

	if d.isDbEmpty() {

		slog.Info("seeding database")

		encryptionKey := securecookie.GenerateRandomKey(32)

		clientSecret := lib.GenerateSecureRandomString(60)
		clientSecretEncrypted, _ := lib.EncryptText(clientSecret, encryptionKey)

		client1 := entities.Client{
			ClientIdentifier:         "system-website",
			Description:              "Website client (system-level)",
			Enabled:                  true,
			ConsentRequired:          false,
			IsPublic:                 false,
			AuthorizationCodeEnabled: true,
			DefaultAcrLevel:          enums.AcrLevel2,
			ClientCredentialsEnabled: false,
			ClientSecretEncrypted:    clientSecretEncrypted,
			RedirectURIs: []entities.RedirectURI{
				{URI: lib.GetBaseUrl() + "/auth/callback"},
			},
		}
		d.DB.Create(&client1)

		adminEmail := viper.GetString("AdminEmail")
		if len(adminEmail) == 0 {
			const defaultAdminEmail = "admin@example.com"
			slog.Warn(fmt.Sprintf("expecting GOIABADA_ADMIN_EMAIL environment variable, but it was null or empty. Will default email to '%v'", defaultAdminEmail))
			adminEmail = defaultAdminEmail
		}

		adminPassword := viper.GetString("AdminPassword")
		if len(adminPassword) == 0 {
			const defaultAdminPassword = "admin123"
			slog.Warn(fmt.Sprintf("expecting GOIABADA_ADMIN_PASSWORD environment variable, but it was null or empty. Will default password to '%v'", defaultAdminPassword))
			adminPassword = defaultAdminPassword
		}

		passwordHash, _ := lib.HashPassword(adminPassword)

		user := entities.User{
			Subject:       uuid.New(),
			Email:         adminEmail,
			EmailVerified: true,
			PasswordHash:  passwordHash,
			Enabled:       true,
		}

		resource := entities.Resource{
			ResourceIdentifier: "authserver",
			Description:        "Authorization server (system-level)",
		}
		d.DB.Create(&resource)

		permission1 := entities.Permission{
			PermissionIdentifier: "account",
			Description:          "View and update user account data for the current user",
			Resource:             resource,
		}
		d.DB.Create(&permission1)

		permission2 := entities.Permission{
			PermissionIdentifier: "admin-website",
			Description:          "Manage the authorization server settings via the web interface",
			Resource:             resource,
		}
		d.DB.Create(&permission2)

		user.Permissions = []entities.Permission{permission1, permission2}
		d.DB.Create(&user)

		permission3 := entities.Permission{
			PermissionIdentifier: "admin-rest-api",
			Description:          "Manage the authorization server settings via the REST API",
			Resource:             resource,
		}
		d.DB.Create(&permission3)

		privateKey, err := lib.GeneratePrivateKey(4096)
		if err != nil {
			return errors.Wrap(err, "unable to generate a private key")
		}
		privateKeyPEM := lib.EncodePrivateKeyToPEM(privateKey)
		publicKeyPEM, err := lib.EncodePublicKeyToPEM(&privateKey.PublicKey)
		if err != nil {
			return errors.Wrap(err, "unable to encode public key to PEM")
		}

		keyPair := &entities.KeyPair{
			KeyIdentifier: uuid.New().String(),
			Type:          "RSA",
			Algorithm:     "RS256",
			PrivateKeyPEM: b64.StdEncoding.EncodeToString(privateKeyPEM),
			PublicKeyPEM:  b64.StdEncoding.EncodeToString(publicKeyPEM),
		}
		d.DB.Create(&keyPair)

		settings := &entities.Settings{
			AppName:                 "Goiabada",
			Issuer:                  "https://goiabada.dev",
			SelfRegistrationEnabled: true,
			SelfRegistrationRequiresEmailVerification: true,
			PasswordPolicy:                  enums.PasswordPolicyLow,
			SessionAuthenticationKey:        securecookie.GenerateRandomKey(64),
			SessionEncryptionKey:            securecookie.GenerateRandomKey(32),
			AESEncryptionKey:                encryptionKey,
			TokenExpirationInSeconds:        300,   // 5 minutes
			UserSessionIdleTimeoutInSeconds: 1800,  // 30 minutes
			UserSessionMaxLifetimeInSeconds: 86400, // 24 hours
		}
		d.DB.Create(&settings)

		slog.Info("finished seeding database")
	} else {
		slog.Info("no need to seed")
	}

	return nil
}
