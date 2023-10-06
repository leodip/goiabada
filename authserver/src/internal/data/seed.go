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

		var client entities.Client

		clientSecret := lib.GenerateSecureRandomString(60)
		clientSecretEncrypted, _ := lib.EncryptText(clientSecret, encryptionKey)

		client = entities.Client{
			ClientIdentifier:      "account-management",
			Enabled:               true,
			ConsentRequired:       false,
			IsPublic:              false,
			ClientSecretEncrypted: clientSecretEncrypted,
			RedirectUris: []entities.RedirectUri{
				{Uri: lib.GetBaseUrl() + "/auth/callback"},
			},
		}
		d.DB.Create(&client)

		admin := viper.GetString("Admin")
		if len(admin) == 0 {
			const defaultAdmin = "admin"
			slog.Warn(fmt.Sprintf("expecting GOIABADA_ADMIN environment variable, but it was null or empty. Will default username to '%v'", defaultAdmin))
			admin = defaultAdmin
		}

		adminPassword := viper.GetString("AdminPassword")
		if len(adminPassword) == 0 {
			const defaultAdminPassword = "admin123"
			slog.Warn(fmt.Sprintf("expecting GOIABADA_ADMINPASSWORD environment variable, but it was null or empty. Will default password to '%v'", defaultAdminPassword))
			adminPassword = defaultAdminPassword
		}

		passwordHash, _ := lib.HashPassword(adminPassword)

		user := entities.User{
			Subject:      uuid.New(),
			Username:     admin,
			PasswordHash: passwordHash,
		}
		permission := entities.Permission{}
		d.DB.Where("permission_identifier = ?", "manage-website").First(&permission)
		user.Permissions = []entities.Permission{permission}
		d.DB.Create(&user)

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
			AppName:                                   "Goiabada",
			Issuer:                                    "https://goiabada.dev",
			SessionAuthenticationKey:                  securecookie.GenerateRandomKey(64),
			SessionEncryptionKey:                      securecookie.GenerateRandomKey(32),
			AuthorizationCodeExpirationInSeconds:      30,
			TokenExpirationInSeconds:                  600,
			RefreshTokenExpirationInSeconds:           3600,
			UserSessionIdleTimeoutInSeconds:           3600,
			UserSessionMaxLifetimeInSeconds:           86400,
			AcrLevel1MaxAgeInSeconds:                  43200,
			AcrLevel2MaxAgeInSeconds:                  21600,
			AESEncryptionKey:                          encryptionKey,
			IncludeRolesInIdToken:                     false,
			PasswordPolicy:                            enums.PasswordPolicyLow,
			SelfRegistrationEnabled:                   true,
			SelfRegistrationRequiresEmailVerification: true,
		}
		d.DB.Create(&settings)

		slog.Info("finished seeding database")
	} else {
		slog.Info("no need to seed")
	}

	return nil
}
