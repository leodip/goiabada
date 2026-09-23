package bootstrap

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/authserver/internal/uuidutil"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/stringutil"
)

// seedDatabase is the seed's port: the transaction and the nine creates its 19 writes call.
type seedDatabase interface {
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	CreateClient(ctx context.Context, tx *sql.Tx, client *models.Client) error
	CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *models.RedirectURI) error
	CreateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
	CreateResource(ctx context.Context, tx *sql.Tx, resource *models.Resource) error
	CreatePermission(ctx context.Context, tx *sql.Tx, permission *models.Permission) error
	CreateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *models.ClientPermission) error
	CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *models.UserPermission) error
	CreateKeyPair(ctx context.Context, tx *sql.Tx, keyPair *models.KeyPair) error
	CreateInitialSettings(ctx context.Context, tx *sql.Tx, settings *models.Settings) error
}

// seedValues is everything the seed generates before it writes: each can fail, and a failure
// here has to leave the database untouched.
type seedValues struct {
	adminEmail            string
	passwordHash          string
	appName               string
	clientSecretEncrypted []byte
	currentKey            *models.KeyPair
	nextKey               *models.KeyPair
}

// seed writes a deployment's first state: the admin console's client, the admin, the auth
// server's resource and permissions, both signing keys and the settings row.
//
// WHY IT IS ORDERED THIS WAY. Every step that can fail without the database's help runs first --
// the password check, the random keys, the encryption, both RSA keys, the hash and the bootstrap
// file's staging -- and then all 19 writes run in one transaction, so a failure anywhere up to the
// commit leaves an empty database that the next start seeds from the beginning. The one step after
// it, publishing the file, cannot be undone that way, and its failure keeps the staged file and
// names it instead (below). They used to run one statement at a time with no transaction, the
// file written after the first of them: a failure part-way left a database IsEmpty still called
// empty, whose next seed then failed on the client it had already written, and no restart
// recovered it (#424). The file appears under its name only after the commit, by a rename in its
// own directory, so an operator never copies credentials the database does not hold.
// bootstrapFile is empty in single-step mode, which writes no file even when one is configured
// beside the secret.
func (r *runner) seed(ctx context.Context, bootstrapFile string) error {

	// The data-encryption key comes from the environment (GOIABADA_AES_ENCRYPTION_KEY,
	// issue #83) via the process cipher; the seed does not generate or store it.

	adminEmail := r.cfg.AdminEmail
	if len(adminEmail) == 0 {
		const defaultAdminEmail = "admin@example.com"
		slog.WarnContext(ctx, "admin email is not set, defaulting it", "email", defaultAdminEmail)
		adminEmail = defaultAdminEmail
	}
	// Lowercased at the write, exactly as every other path that stores an email does.
	// Without it GOIABADA_ADMIN_EMAIL reaches the column verbatim, and an operator who
	// sets Admin@Example.com gets an admin who cannot sign in at all on SQLite or
	// PostgreSQL, on first run: both compare "=" exactly, and the password handler and
	// the ROPC grant each look the account up by the lowercased address (#221, #283).
	adminEmail = strings.ToLower(strings.TrimSpace(adminEmail))

	adminPassword := r.cfg.AdminPassword
	if len(adminPassword) == 0 {
		const defaultAdminPassword = "changeme"
		// The default is a published constant rather than a secret, and an operator who did not
		// set one has to be told what they got: the alternative is an admin account nobody can
		// sign in to. A configured password is never written here.
		slog.WarnContext(ctx, "admin password is not set, defaulting it", "password", defaultAdminPassword)
		adminPassword = defaultAdminPassword
	}

	// Checked before anything is generated or written, so a password bcrypt refuses costs no key
	// generation and leaves the database empty for the next start, with the variable fixed (#409).
	if err := checkAdminPasswordLength(adminPassword); err != nil {
		return err
	}

	appName := r.cfg.AppName
	if len(appName) == 0 {
		appName = "Goiabada"
		slog.WarnContext(ctx, "app name is not set, defaulting it", "app_name", appName)
	}

	// Generate session keys for both auth server and admin console
	// These are only used if the bootstrap file is configured (legacy two-step bootstrap)
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
	if r.cfg.OAuthClientSecret != "" {
		clientSecret = r.cfg.OAuthClientSecret
		slog.InfoContext(ctx, "using pre-generated OAuth client secret from environment")
	} else {
		clientSecret = stringutil.GenerateSecurityRandomString(60)
		slog.InfoContext(ctx, "generated new OAuth client secret")
	}
	clientSecretEncrypted, err := encryption.EncryptData(clientSecret)
	if err != nil {
		return errs.Wrap(err, "unable to encrypt admin console client secret")
	}

	currentKey, err := signingkeys.NewKeyPair(models.KeyStateCurrent, r.keySizeBits)
	if err != nil {
		return err
	}
	nextKey, err := signingkeys.NewKeyPair(models.KeyStateNext, r.keySizeBits)
	if err != nil {
		return err
	}

	passwordHash, err := passwordhash.Hash(adminPassword)
	if err != nil {
		return errs.Wrap(err, "unable to hash the admin password")
	}

	// Staged before the transaction and published after it (#424 decision 4). An unwritable or
	// unmounted volume is refused here, before any row exists, so fixing the mount and restarting
	// seeds cleanly; writing the file only after the commit would instead leave a seeded database
	// whose generated credentials exist nowhere.
	var staged string
	if bootstrapFile != "" {
		staged, err = stageBootstrapEnvFile(bootstrapFile, bootstrapEnvContent(
			clientSecret,
			hex.EncodeToString(authServerSessionAuthKey),
			hex.EncodeToString(authServerSessionEncKey),
			hex.EncodeToString(adminConsoleSessionAuthKey),
			hex.EncodeToString(adminConsoleSessionEncKey),
		))
		if err != nil {
			return err
		}
	}

	values := seedValues{
		adminEmail:            adminEmail,
		passwordHash:          passwordHash,
		appName:               appName,
		clientSecretEncrypted: clientSecretEncrypted,
		currentKey:            currentKey,
		nextKey:               nextKey,
	}
	err = r.db.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return r.writeSeedRows(ctx, tx, values)
	})
	if err != nil {
		if staged != "" {
			_ = os.Remove(staged)
		}
		return err
	}

	// After the commit the staged file is the only copy of the credentials the rows were written
	// with: the client secret is stored encrypted and the session keys are not stored at all, and
	// the database is no longer empty, so no later start regenerates them. A failed rename
	// therefore keeps the file and names it rather than removing it (#424 decision 4).
	if staged != "" {
		if err := r.rename(staged, bootstrapFile); err != nil {
			return errs.Wrapf(err, "the database is seeded, but the bootstrap file could not be moved into place: "+
				"its credentials are in %s and nowhere else, so move that file to %s rather than deleting it",
				staged, bootstrapFile)
		}
		logBootstrapCredentialsGenerated(ctx, bootstrapFile)
	}

	// One record after the commit where there was one per row: written inside the transaction,
	// those announced rows a rollback then removed, and would repeat on a deadlock rerun.
	slog.InfoContext(ctx, "database seeded",
		"client_identifier", constants.AdminConsoleClientIdentifier,
		"email", adminEmail,
		"current_key_identifier", currentKey.KeyIdentifier,
		"next_key_identifier", nextKey.KeyIdentifier)

	return nil
}

// writeSeedRows is the seed transaction's body. It builds every row itself, so a rerun after a
// deadlock starts from fresh structs rather than ones carrying the aborted attempt's ids, and
// every write takes tx: one made outside it would survive a rollback, which on SQLite's single
// connection hangs instead.
func (r *runner) writeSeedRows(ctx context.Context, tx *sql.Tx, values seedValues) error {
	client := &models.Client{
		ClientIdentifier:         constants.AdminConsoleClientIdentifier,
		Description:              "Admin console client (system-level)",
		DisplayName:              "Admin console",
		Enabled:                  true,
		ConsentRequired:          false,
		IsPublic:                 false,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          models.AcrLevel2Optional,
		// The admin console obtains a bearer token through client_credentials to reach
		// its own browser sessions on the auth server, so this grant is on from the
		// start. It carries the single browser-sessions permission granted below and
		// nothing wider (#266).
		ClientCredentialsEnabled:                true,
		ClientSecretEncrypted:                   values.clientSecretEncrypted,
		IncludeOpenIDConnectClaimsInAccessToken: models.ThreeStateSettingDefault.String(),
		IncludeOpenIDConnectClaimsInIdToken:     models.ThreeStateSettingDefault.String(),
		ShowDisplayName:                         true,
	}
	if err := r.db.CreateClient(ctx, tx, client); err != nil {
		return err
	}

	for _, uri := range []string{r.cfg.AdminConsoleBaseURL + "/auth/callback", r.cfg.AdminConsoleBaseURL} {
		if err := r.db.CreateRedirectURI(ctx, tx, &models.RedirectURI{URI: uri, ClientId: client.Id}); err != nil {
			return err
		}
	}

	user := &models.User{
		Subject:       uuidutil.New(),
		Email:         values.adminEmail,
		EmailVerified: true,
		PasswordHash:  values.passwordHash,
		Enabled:       true,
	}
	if err := r.db.CreateUser(ctx, tx, user); err != nil {
		return err
	}

	resource := &models.Resource{
		ResourceIdentifier: constants.AuthServerResourceIdentifier,
		Description:        "Authorization server (system-level)",
	}
	if err := r.db.CreateResource(ctx, tx, resource); err != nil {
		return err
	}

	permissions := make(map[string]*models.Permission)
	for _, p := range []struct{ identifier, description string }{
		{constants.UserinfoPermissionIdentifier, "Access to the OpenID Connect user info endpoint"},
		{constants.ManageAccountPermissionIdentifier, "View and update user account data for the current user"},
		{constants.ManagePermissionIdentifier, "Manage the authorization server via the admin console"},
		// Granular admin API scopes
		{constants.AdminReadPermissionIdentifier, "Read-only access to all admin API endpoints"},
		{constants.ManageUsersPermissionIdentifier, "Manage users, groups, and permissions"},
		{constants.ManageClientsPermissionIdentifier, "Manage OAuth2 clients"},
		{constants.ManageSettingsPermissionIdentifier, "Manage system settings and signing keys"},
		{constants.BrowserSessionsPermissionIdentifier, "Read and write admin console browser sessions"},
	} {
		permission := &models.Permission{
			PermissionIdentifier: p.identifier,
			Description:          p.description,
			ResourceId:           resource.Id,
		}
		if err := r.db.CreatePermission(ctx, tx, permission); err != nil {
			return err
		}
		permissions[p.identifier] = permission
	}

	// Migration 000035 produces this same end state for an installation that already
	// existed, and the two must not drift: the permission on the authserver resource,
	// the grant to the admin console client, and client_credentials_enabled on it.
	if err := r.db.CreateClientPermission(ctx, tx, &models.ClientPermission{
		ClientId:     client.Id,
		PermissionId: permissions[constants.BrowserSessionsPermissionIdentifier].Id,
	}); err != nil {
		return err
	}

	for _, identifier := range []string{constants.ManageAccountPermissionIdentifier, constants.ManagePermissionIdentifier} {
		if err := r.db.CreateUserPermission(ctx, tx, &models.UserPermission{
			UserId:       user.Id,
			PermissionId: permissions[identifier].Id,
		}); err != nil {
			return err
		}
	}

	// Copies, because CreateKeyPair sets the id on the struct it is given and these two were
	// built before the transaction, once for every attempt.
	for _, prebuilt := range []*models.KeyPair{values.currentKey, values.nextKey} {
		keyPair := *prebuilt
		if err := r.db.CreateKeyPair(ctx, tx, &keyPair); err != nil {
			return err
		}
	}

	// Last, and at the id IsEmpty reads, so the database reads as seeded exactly when the
	// transaction holding this row commits (#424 decision 14).
	return r.db.CreateInitialSettings(ctx, tx, &models.Settings{
		AppName:                 values.appName,
		Issuer:                  r.cfg.AuthServerBaseURL,
		UITheme:                 "",
		SelfRegistrationEnabled: true,
		SelfRegistrationRequiresEmailVerification: false,
		PasswordPolicy: models.PasswordPolicyLow,
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
	})
}

// stageBootstrapEnvFile writes content to a new file beside target and answers its path: in the
// target's own directory, so the rename that publishes it is atomic, and at 0600, which
// os.CreateTemp gives every file it creates, so the credentials are never readable by anyone but
// the owner even for a moment. The directory is created 0700 if absent. Nothing is left behind on
// a failure.
func stageBootstrapEnvFile(target, content string) (string, error) {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", errs.Wrap(err, "unable to create the bootstrap file's directory")
	}

	f, err := os.CreateTemp(dir, "."+filepath.Base(target)+".*")
	if err != nil {
		return "", errs.Wrap(err, "unable to create the bootstrap file")
	}
	staged := f.Name()

	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(staged)
		return "", errs.Wrap(err, "unable to write the bootstrap file")
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(staged)
		return "", errs.Wrap(err, "unable to write the bootstrap file")
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(staged)
		return "", errs.Wrap(err, "unable to write the bootstrap file")
	}
	return staged, nil
}

// logBootstrapCredentialsGenerated reports the legacy two-step bootstrap file the seed has just
// published, which is the one place the generated credentials are ever readable.
//
// One record where a 12-line banner used to be, and a named function rather than a block inside
// seed so the record it writes can be asserted: the ruled box, the blank lines and the inventory
// of what the file contains were unparseable in a JSON stream and said less than the message and
// the two attributes do (#320 decision 6).
func logBootstrapCredentialsGenerated(ctx context.Context, bootstrapEnvOutFile string) {
	slog.InfoContext(ctx, "bootstrap credentials generated: open the file and copy the OAuth client secret and the session keys into the deployment configuration",
		"bootstrap_file", bootstrapEnvOutFile,
		"file_mode", "0600")
}

// bootstrapEnvContent renders the legacy two-step bootstrap file. It carries no client id: the
// admin console always authenticates as constants.AdminConsoleClientIdentifier, which the seed
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

// checkAdminPasswordLength refuses an admin password bcrypt cannot hash, naming the variable it
// came from and the bound, in bytes because bcrypt counts bytes. The seed is the one path that
// hashes a password no validator has seen, so without this the refusal surfaced as a hashing
// failure, and before #409 not at all: the error was discarded and the admin was stored with an
// empty password hash, an account nobody could sign in to.
func checkAdminPasswordLength(password string) error {
	if len(password) > passwordhash.MaxPasswordBytes {
		return errs.Errorf("the admin password in GOIABADA_ADMIN_PASSWORD is %d bytes long, and bcrypt accepts "+
			"at most %d bytes: shorten it, counting two to four bytes for each non-ASCII character",
			len(password), passwordhash.MaxPasswordBytes)
	}
	return nil
}
