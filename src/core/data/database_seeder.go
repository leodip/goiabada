package data

import (
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"
    "fmt"
    "log/slog"
    "os"
    "path/filepath"

    "github.com/google/uuid"
    "github.com/gorilla/securecookie"
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
    DB                        Database
    adminEmail                string
    adminPassword             string
    appName                   string
    authServerBaseURL         string
    adminConsoleBaseURL       string
    bootstrapEnvOutFile       string
    providedOAuthClientSecret string
}

func NewDatabaseSeeder(database Database, adminEmail, adminPassword, appName, authServerBaseURL, adminConsoleBaseURL string) *DatabaseSeeder {
    return &DatabaseSeeder{
        DB:                        database,
        adminEmail:                adminEmail,
        adminPassword:             adminPassword,
        appName:                   appName,
        authServerBaseURL:         authServerBaseURL,
        adminConsoleBaseURL:       adminConsoleBaseURL,
        bootstrapEnvOutFile:       "",
        providedOAuthClientSecret: "",
    }
}

// WithBootstrapEnvOutFile sets an optional path where bootstrap credentials will be written during seed (0600 perms).
func (ds *DatabaseSeeder) WithBootstrapEnvOutFile(path string) *DatabaseSeeder {
    ds.bootstrapEnvOutFile = path
    return ds
}

// WithOAuthClientSecret sets a pre-generated OAuth client secret to use instead of generating one.
// This enables single-step setup where credentials are generated externally (e.g., by goiabada-setup).
func (ds *DatabaseSeeder) WithOAuthClientSecret(secret string) *DatabaseSeeder {
    ds.providedOAuthClientSecret = secret
    return ds
}

func (ds *DatabaseSeeder) Seed() error {

	encryptionKey := securecookie.GenerateRandomKey(32)

	// Generate session keys for both auth server and admin console
	// These are only used if bootstrapEnvOutFile is set (legacy two-step bootstrap)
	authServerSessionAuthKey := securecookie.GenerateRandomKey(64)
	authServerSessionEncKey := securecookie.GenerateRandomKey(32)
	adminConsoleSessionAuthKey := securecookie.GenerateRandomKey(64)
	adminConsoleSessionEncKey := securecookie.GenerateRandomKey(32)

	// Use provided OAuth client secret if available, otherwise generate one
	var clientSecret string
	if ds.providedOAuthClientSecret != "" {
		clientSecret = ds.providedOAuthClientSecret
		slog.Info("using pre-generated OAuth client secret from environment")
	} else {
		clientSecret = stringutil.GenerateSecurityRandomString(60)
		slog.Info("generated new OAuth client secret")
	}
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
    if len(ds.bootstrapEnvOutFile) > 0 {
        // Prepare directory
        dir := filepath.Dir(ds.bootstrapEnvOutFile)
        if err := os.MkdirAll(dir, 0o700); err != nil {
            return errors.Wrap(err, "unable to create bootstrap env directory")
        }
        f, err := os.OpenFile(ds.bootstrapEnvOutFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
        if err != nil {
            return errors.Wrap(err, "unable to open bootstrap env file for writing")
        }
        // Write OAuth credentials AND session keys
        content := fmt.Sprintf(`# Admin Console OAuth Credentials
GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID=%s
GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=%s

# Auth Server Session Keys
GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=%s
GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=%s

# Admin Console Session Keys
GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=%s
GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=%s
`,
            client1.ClientIdentifier,
            clientSecret,
            hex.EncodeToString(authServerSessionAuthKey),
            hex.EncodeToString(authServerSessionEncKey),
            hex.EncodeToString(adminConsoleSessionAuthKey),
            hex.EncodeToString(adminConsoleSessionEncKey),
        )
        if _, err := f.WriteString(content); err != nil {
            _ = f.Close()
            return errors.Wrap(err, "unable to write bootstrap env file")
        }
        _ = f.Sync()
        _ = f.Close()
        slog.Info("================================================================================")
        slog.Info("BOOTSTRAP CREDENTIALS GENERATED")
        slog.Info("================================================================================")
        slog.Info(fmt.Sprintf("File location: %s", ds.bootstrapEnvOutFile))
        slog.Info("File permissions: 0600 (owner read/write only)")
        slog.Info("")
        slog.Info("The file contains:")
        slog.Info("  - OAuth client ID and secret for admin console")
        slog.Info("  - Session authentication and encryption keys")
        slog.Info("")
        slog.Info("NEXT STEP: Open the file and copy credentials to your deployment configuration")
        slog.Info("================================================================================")
    }

	var redirectURI = &models.RedirectURI{
		URI:      ds.adminConsoleBaseURL + "/auth/callback",
		ClientId: client1.Id,
	}
	err = ds.DB.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("redirect URI '%v' created", redirectURI.URI))

	redirectURI = &models.RedirectURI{
		URI:      ds.adminConsoleBaseURL,
		ClientId: client1.Id,
	}
	err = ds.DB.CreateRedirectURI(nil, redirectURI)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("redirect URI '%v' created", redirectURI.URI))

	adminEmail := ds.adminEmail
	if len(adminEmail) == 0 {
		const defaultAdminEmail = "admin@example.com"
		slog.Warn(fmt.Sprintf("Admin email is not set. Will default admin email to '%v'", defaultAdminEmail))
		adminEmail = defaultAdminEmail
	}

	adminPassword := ds.adminPassword
	if len(adminPassword) == 0 {
		const defaultAdminPassword = "changeme"
		slog.Warn(fmt.Sprintf("Admin password is not set. Will default admin password to '%v'", defaultAdminPassword))
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
		ResourceId:           resource1.Id,
	}
	err = ds.DB.CreatePermission(nil, permission2)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permission2.PermissionIdentifier))

	permission3 := &models.Permission{
		PermissionIdentifier: constants.ManagePermissionIdentifier,
		Description:          "Manage the authorization server via the admin console",
		ResourceId:           resource1.Id,
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

	appName := ds.appName
	if len(appName) == 0 {
		appName = "Goiabada"
		slog.Warn(fmt.Sprintf("App name is not set. Will default app name to '%v'", appName))
	}

	settings := &models.Settings{
		AppName:                 appName,
		Issuer:                  ds.authServerBaseURL,
		UITheme:                 "",
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: false,
		PasswordPolicy:                          enums.PasswordPolicyLow,
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
