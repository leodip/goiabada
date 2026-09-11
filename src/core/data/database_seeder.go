package data

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/rsautil"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/leodip/goiabada/core/uuidutil"
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

// logBootstrapCredentialsGenerated reports the legacy two-step bootstrap file the seeder has just
// written, which is the one place the generated credentials are ever readable.
//
// One record where a 12-line banner used to be, and a named function rather than a block inside
// Seed so the record it writes can be asserted: the ruled box, the blank lines and the inventory
// of what the file contains were unparseable in a JSON stream and said less than the message and
// the two attributes do (#320 decision 6).
func logBootstrapCredentialsGenerated(bootstrapEnvOutFile string) {
	slog.Info("bootstrap credentials generated: open the file and copy the OAuth client secret and the session keys into the deployment configuration",
		"bootstrap_file", bootstrapEnvOutFile,
		"file_mode", "0600")
}

// bootstrapEnvContent renders the legacy two-step bootstrap file. It carries no client id: the
// admin console always authenticates as constants.AdminConsoleClientIdentifier, which the seeder
// writes and the migrations grant against, so there is nothing for an operator to copy across
// (#285). Kept a pure function so the file's contents can be tested without a database.
func bootstrapEnvContent(clientSecret, authServerAuthKey, authServerEncKey,
	adminConsoleAuthKey, adminConsoleEncKey string) string {
	return fmt.Sprintf(`# Admin Console OAuth Client Secret
GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET=%s

# Auth Server Session Keys
GOIABADA_AUTHSERVER_SESSION_AUTHENTICATION_KEY=%s
GOIABADA_AUTHSERVER_SESSION_ENCRYPTION_KEY=%s

# Admin Console Session Keys
GOIABADA_ADMINCONSOLE_SESSION_AUTHENTICATION_KEY=%s
GOIABADA_ADMINCONSOLE_SESSION_ENCRYPTION_KEY=%s
`,
		clientSecret,
		authServerAuthKey,
		authServerEncKey,
		adminConsoleAuthKey,
		adminConsoleEncKey,
	)
}

func (ds *DatabaseSeeder) Seed() error {

	// The data-encryption key comes from the environment (GOIABADA_AES_ENCRYPTION_KEY,
	// issue #83) via the process cipher; the seeder no longer generates or stores it.

	// Generate session keys for both auth server and admin console
	// These are only used if bootstrapEnvOutFile is set (legacy two-step bootstrap)
	//
	// A CSPRNG failure fails the seed. The library call these replaced answered one with
	// a nil slice, which the hex encoding below turned into an empty string, so a failed
	// read produced a bootstrap env file naming a session key of no bytes at all and a
	// deployment that came up and ran on it (#269).
	authServerSessionAuthKey, err := encryption.RandomKey(64)
	if err != nil {
		return errs.Wrap(err, "unable to generate the auth server session authentication key")
	}
	authServerSessionEncKey, err := encryption.RandomKey(32)
	if err != nil {
		return errs.Wrap(err, "unable to generate the auth server session encryption key")
	}
	adminConsoleSessionAuthKey, err := encryption.RandomKey(64)
	if err != nil {
		return errs.Wrap(err, "unable to generate the admin console session authentication key")
	}
	adminConsoleSessionEncKey, err := encryption.RandomKey(32)
	if err != nil {
		return errs.Wrap(err, "unable to generate the admin console session encryption key")
	}

	// Use provided OAuth client secret if available, otherwise generate one
	var clientSecret string
	if ds.providedOAuthClientSecret != "" {
		clientSecret = ds.providedOAuthClientSecret
		slog.Info("using pre-generated OAuth client secret from environment")
	} else {
		clientSecret = stringutil.GenerateSecurityRandomString(60)
		slog.Info("generated new OAuth client secret")
	}
	clientSecretEncrypted, encErr := encryption.EncryptData(clientSecret)
	if encErr != nil {
		return errs.Wrap(encErr, "unable to encrypt admin console client secret")
	}

	client1 := &models.Client{
		ClientIdentifier:         constants.AdminConsoleClientIdentifier,
		Description:              "Admin console client (system-level)",
		DisplayName:              "Admin console",
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          enums.AcrLevel2Optional,
		// The admin console obtains a bearer token through client_credentials to reach
		// its own browser sessions on the auth server, so this grant is on from the
		// start. It carries the single browser-sessions permission granted below and
		// nothing wider (#266).
		ClientCredentialsEnabled:                true,
		ClientSecretEncrypted:                   clientSecretEncrypted,
		IncludeOpenIDConnectClaimsInAccessToken: enums.ThreeStateSettingDefault.String(),
		IncludeOpenIDConnectClaimsInIdToken:     enums.ThreeStateSettingDefault.String(),
		ShowDisplayName:                         true,
	}

	err = ds.DB.CreateClient(nil, client1)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("client '%v' created", client1.ClientIdentifier))
	if len(ds.bootstrapEnvOutFile) > 0 {
		// Prepare directory
		dir := filepath.Dir(ds.bootstrapEnvOutFile)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return errs.Wrap(err, "unable to create bootstrap env directory")
		}
		f, err := os.OpenFile(ds.bootstrapEnvOutFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return errs.Wrap(err, "unable to open bootstrap env file for writing")
		}
		// Write the OAuth client secret AND session keys
		content := bootstrapEnvContent(
			clientSecret,
			hex.EncodeToString(authServerSessionAuthKey),
			hex.EncodeToString(authServerSessionEncKey),
			hex.EncodeToString(adminConsoleSessionAuthKey),
			hex.EncodeToString(adminConsoleSessionEncKey),
		)
		if _, err := f.WriteString(content); err != nil {
			_ = f.Close()
			return errs.Wrap(err, "unable to write bootstrap env file")
		}
		_ = f.Sync()
		_ = f.Close()
		logBootstrapCredentialsGenerated(ds.bootstrapEnvOutFile)
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
		Subject: uuidutil.New(),
		// Lowercased at the write, exactly as every other path that stores an email does.
		// Without it GOIABADA_ADMIN_EMAIL reaches the column verbatim, and an operator who
		// sets Admin@Example.com gets an admin who cannot sign in at all on SQLite or
		// PostgreSQL, on first run: both compare "=" exactly, and the password handler and
		// the ROPC grant each look the account up by the lowercased address (#221, #283).
		Email:         strings.ToLower(strings.TrimSpace(adminEmail)),
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

	// Granular admin API scopes
	permissionAdminRead := &models.Permission{
		PermissionIdentifier: constants.AdminReadPermissionIdentifier,
		Description:          "Read-only access to all admin API endpoints",
		ResourceId:           resource1.Id,
	}
	err = ds.DB.CreatePermission(nil, permissionAdminRead)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permissionAdminRead.PermissionIdentifier))

	permissionManageUsers := &models.Permission{
		PermissionIdentifier: constants.ManageUsersPermissionIdentifier,
		Description:          "Manage users, groups, and permissions",
		ResourceId:           resource1.Id,
	}
	err = ds.DB.CreatePermission(nil, permissionManageUsers)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permissionManageUsers.PermissionIdentifier))

	permissionManageClients := &models.Permission{
		PermissionIdentifier: constants.ManageClientsPermissionIdentifier,
		Description:          "Manage OAuth2 clients",
		ResourceId:           resource1.Id,
	}
	err = ds.DB.CreatePermission(nil, permissionManageClients)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permissionManageClients.PermissionIdentifier))

	permissionManageSettings := &models.Permission{
		PermissionIdentifier: constants.ManageSettingsPermissionIdentifier,
		Description:          "Manage system settings and signing keys",
		ResourceId:           resource1.Id,
	}
	err = ds.DB.CreatePermission(nil, permissionManageSettings)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permissionManageSettings.PermissionIdentifier))

	permissionBrowserSessions := &models.Permission{
		PermissionIdentifier: constants.BrowserSessionsPermissionIdentifier,
		Description:          "Read and write admin console browser sessions",
		ResourceId:           resource1.Id,
	}
	err = ds.DB.CreatePermission(nil, permissionBrowserSessions)
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("permission '%v' created", permissionBrowserSessions.PermissionIdentifier))

	// Migration 000035 produces this same end state for an installation that already
	// existed, and the two must not drift: the permission on the authserver resource,
	// the grant to the admin console client, and client_credentials_enabled on it.
	err = ds.DB.CreateClientPermission(nil, &models.ClientPermission{
		ClientId:     client1.Id,
		PermissionId: permissionBrowserSessions.Id,
	})
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("client '%v' granted permission '%v'", client1.ClientIdentifier,
		permissionBrowserSessions.PermissionIdentifier))

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
		return errs.Wrap(err, "unable to generate a private key")
	}
	privateKeyPEM := rsautil.EncodePrivateKeyToPEM(privateKey)

	publicKeyASN1_DER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return errs.Wrap(err, "unable to marshal public key to PKIX")
	}

	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyASN1_DER,
		},
	)

	kid := uuidutil.New()
	publicKeyJWK, err := rsautil.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
	if err != nil {
		return err
	}

	currentPrivateKeyEncrypted, err := encryption.EncryptData(string(privateKeyPEM))
	if err != nil {
		return errs.Wrap(err, "unable to encrypt current signing key")
	}
	keyPair := &models.KeyPair{
		State:             enums.KeyStateCurrent.String(),
		KeyIdentifier:     kid,
		Type:              "RSA",
		Algorithm:         "RS256",
		PrivateKeyPEM:     currentPrivateKeyEncrypted,
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
		return errs.Wrap(err, "unable to generate a private key")
	}
	privateKeyPEM = rsautil.EncodePrivateKeyToPEM(privateKey)

	publicKeyASN1_DER, err = x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return errs.Wrap(err, "unable to marshal public key to PKIX")
	}

	publicKeyPEM = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyASN1_DER,
		},
	)

	kid = uuidutil.New()
	publicKeyJWK, err = rsautil.MarshalRSAPublicKeyToJWK(&privateKey.PublicKey, kid)
	if err != nil {
		return err
	}

	nextPrivateKeyEncrypted, err := encryption.EncryptData(string(privateKeyPEM))
	if err != nil {
		return errs.Wrap(err, "unable to encrypt next signing key")
	}
	keyPair = &models.KeyPair{
		State:             enums.KeyStateNext.String(),
		KeyIdentifier:     kid,
		Type:              "RSA",
		Algorithm:         "RS256",
		PrivateKeyPEM:     nextPrivateKeyEncrypted,
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
		PasswordPolicy: enums.PasswordPolicyLow,
		// The data key is supplied from the environment (issue #83); the legacy
		// aes_encryption_key column is left empty on fresh installs. It is NOT NULL,
		// so store an empty (non-nil) blob rather than nil.
		AESEncryptionKeyLegacy:                  []byte{},
		TokenExpirationInSeconds:                300,      // 5 minutes
		RefreshTokenOfflineIdleTimeoutInSeconds: 2592000,  // 30 days
		RefreshTokenOfflineMaxLifetimeInSeconds: 31536000, // 1 year
		UserSessionIdleTimeoutInSeconds:         7200,     // 2 hours
		UserSessionMaxLifetimeInSeconds:         86400,    // 24 hours
		IncludeOpenIDConnectClaimsInAccessToken: false,
		IncludeOpenIDConnectClaimsInIdToken:     true,  // Industry standard (Auth0, Microsoft, Keycloak)
		PKCERequired:                            true,  // OAuth 2.1 recommendation
		ImplicitFlowEnabled:                     false, // Disabled by default (deprecated in OAuth 2.1)
		AuditLogsInConsoleEnabled:               true,  // Enabled by default for observability
		AuditLogsInDatabaseEnabled:              true,  // Enabled by default for compliance
		AuditLogRetentionDays:                   180,   // 180 days default retention
	}
	err = ds.DB.CreateSettings(nil, settings)
	if err != nil {
		return err
	}
	slog.Info("settings created")

	slog.Info("database seeded")

	return nil
}
