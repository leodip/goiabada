package accounthandlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/handlers/accounthandlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
)

// The activation handlers over a real SQLite database migrated to head, for the two properties
// the Database mock can only show were asked for: that an expired link's delete leaves a row a
// registration replaced meanwhile, and that a failed activation leaves no account behind (#207).
// The mock shows which transaction a call named; only an engine shows what a rollback undid.

func newActivationSQLiteDB(t *testing.T) *sqlitedb.Database {
	t.Helper()
	db, err := sqlitedb.New(context.Background(), "file:"+filepath.Join(t.TempDir(), "activation_test.db"), false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.DB.Close() })

	m, err := db.NewMigrator(context.Background())
	require.NoError(t, err)
	if err := m.Up(context.Background()); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head")
	}
	return db
}

// replacingDB is the real database with one interleaving forced into it: the first lookup of a
// pending registration by code hash returns the row it read, but only after a registration has
// replaced that row's code, which is the window between the expired link's lookup and its delete.
type replacingDB struct {
	*sqlitedb.Database
	afterLookup func(read *record.PreRegistration)
}

func (d *replacingDB) GetPreRegistrationByVerificationCodeHash(ctx context.Context, tx *sql.Tx,
	codeHash string) (*record.PreRegistration, error) {

	read, err := d.Database.GetPreRegistrationByVerificationCodeHash(ctx, tx, codeHash)
	if err == nil && read != nil && d.afterLookup != nil {
		run := d.afterLookup
		d.afterLookup = nil
		run(read)
	}
	return read, err
}

func TestHandleActivateGet_ExpiredLink_OnSQLite(t *testing.T) {
	const expiredCode = "the-expired-activation-code"
	const freshCode = "the-fresh-activation-code"

	// The agreed behavior the fence must keep: an expired code nobody replaced is deleted, so the
	// refusal page's "register again" works at once.
	t.Run("an unchanged expired code is deleted", func(t *testing.T) {
		db := newActivationSQLiteDB(t)
		ctx := context.Background()

		row, codeHash := preRegistrationWithCode(t, 0, activateTestEmail, expiredCode, time.Now().UTC().Add(-11*time.Minute))
		require.NoError(t, db.CreatePreRegistration(ctx, nil, row))

		pageRenderer := handlersmocks.NewPageRenderer(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectRenderedLinkExpired(pageRenderer)
		expectAuditFailedActivationCode(auditLogger, "code_expired", row.Id)

		HandleActivateGet(pageRenderer, newMarkerTestStore(), db, auditLogger, testDataCipher).
			ServeHTTP(httptest.NewRecorder(), activationLinkFollowedRequest(expiredCode))

		gone, err := db.GetPreRegistrationByVerificationCodeHash(ctx, nil, codeHash)
		require.NoError(t, err)
		assert.Nil(t, gone, "the expired pending registration is deleted")
		pageRenderer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	// A registration for the address replaces the dead row's code, keeping its id, between the
	// expired link's lookup and its delete. The fresh link must survive: it was just mailed, and
	// its code and form windows have only started (#207 decision 6).
	t.Run("a code replaced after the lookup survives the expired link's delete", func(t *testing.T) {
		db := newActivationSQLiteDB(t)
		ctx := context.Background()

		row, _ := preRegistrationWithCode(t, 0, activateTestEmail, expiredCode, time.Now().UTC().Add(-11*time.Minute))
		require.NoError(t, db.CreatePreRegistration(ctx, nil, row))

		freshEncrypted, err := testDataCipher.Encrypt(freshCode)
		require.NoError(t, err)
		freshHash := hashutil.HashString(freshCode)

		raced := &replacingDB{Database: db, afterLookup: func(read *record.PreRegistration) {
			replaced, replaceErr := db.TryReplacePreRegistrationCode(ctx, nil, read.Id, read.VerificationCodeHash,
				freshEncrypted, freshHash, time.Now().UTC())
			require.NoError(t, replaceErr)
			require.True(t, replaced, "the registration's replacement takes effect between the lookup and the delete")
		}}

		pageRenderer := handlersmocks.NewPageRenderer(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectRenderedLinkExpired(pageRenderer)
		expectAuditFailedActivationCode(auditLogger, "code_expired", row.Id)

		rr := httptest.NewRecorder()
		HandleActivateGet(pageRenderer, newMarkerTestStore(), raced, auditLogger, testDataCipher).
			ServeHTTP(rr, activationLinkFollowedRequest(expiredCode))

		assert.Equal(t, http.StatusOK, rr.Code, "the expired link is refused as any expired link is")
		fresh, err := db.GetPreRegistrationByVerificationCodeHash(ctx, nil, freshHash)
		require.NoError(t, err)
		require.NotNil(t, fresh, "an expired link must not delete the fresh link that replaced it")
		assert.Equal(t, row.Id, fresh.Id)
		pageRenderer.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}

// consumptionFailingDB is the real database whose consumption of the pending registration fails,
// the last write of an activation, after the user row and its permission.
type consumptionFailingDB struct {
	*sqlitedb.Database
}

func (d *consumptionFailingDB) DeletePreRegistrationHoldingCode(context.Context, *sql.Tx, int64, string) (bool, error) {
	return false, errs.New("the engine refused the pending registration's delete")
}

func TestHandleActivatePost_OnSQLite(t *testing.T) {
	const code = "the-outstanding-activation-code"
	const chosenPassword = "Chosen-At-Activation-1!"

	// arrange writes what a seeded server and one registration leave: the auth server resource,
	// its account permission, and the pending registration the link was mailed for.
	arrange := func(t *testing.T, db *sqlitedb.Database) (*record.PreRegistration, string) {
		t.Helper()
		ctx := context.Background()
		resource := &record.Resource{ResourceIdentifier: builtin.AuthServerResourceIdentifier}
		require.NoError(t, db.CreateResource(ctx, nil, resource))
		require.NoError(t, db.CreatePermission(ctx, nil, &record.Permission{
			PermissionIdentifier: builtin.ManageAccountPermissionIdentifier,
			ResourceId:           resource.Id,
		}))
		row, codeHash := preRegistrationWithCode(t, 0, activateTestEmail, code, time.Now().UTC())
		require.NoError(t, db.CreatePreRegistration(ctx, nil, row))
		return row, codeHash
	}

	t.Run("a completed activation commits the account and consumes the registration", func(t *testing.T) {
		db := newActivationSQLiteDB(t)
		ctx := context.Background()
		row, codeHash := arrange(t, db)

		pageRenderer := handlersmocks.NewPageRenderer(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		passwordValidator.On("ValidatePassword", record.PasswordPolicyMedium, chosenPassword).Return(nil).Once()
		auditLogger.On("Log", mock.Anything, audit.EventCreatedUser, mock.Anything).Return().Once()
		auditLogger.On("Log", mock.Anything, audit.EventActivatedAccount, mock.Anything).Return().Once()
		pageRenderer.On("RenderTemplate", mock.Anything, mock.Anything, "/layouts/auth_layout.html",
			"/account_register_activation_result.html", mock.Anything).Return(nil).Once()

		store := newMarkerTestStore()
		HandleActivatePost(pageRenderer, store, db, usercreation.New(db), passwordValidator, auditLogger, testAdminConsoleBaseURL).
			ServeHTTP(httptest.NewRecorder(), postActivationWithMarker(t, store, chosenPassword, chosenPassword, row.Id, codeHash))

		user, err := db.GetUserByEmail(ctx, nil, activateTestEmail)
		require.NoError(t, err)
		require.NotNil(t, user, "the account is committed")
		assert.True(t, user.EmailVerified)
		permissions, err := db.GetUserPermissionsByUserId(ctx, nil, user.Id)
		require.NoError(t, err)
		assert.Len(t, permissions, 1, "with its account permission")
		pending, err := db.GetPreRegistrationById(ctx, nil, row.Id)
		require.NoError(t, err)
		assert.Nil(t, pending, "and the pending registration is consumed with it")
		auditLogger.AssertExpectations(t)
		pageRenderer.AssertExpectations(t)
	})

	// The account used to commit in its own transaction before the consumption, so a failure
	// after it answered the 500 page over a verified, enabled account (AGENTS.md pattern 9).
	t.Run("a consumption that fails after the account insert commits no account", func(t *testing.T) {
		db := newActivationSQLiteDB(t)
		ctx := context.Background()
		row, codeHash := arrange(t, db)

		pageRenderer := handlersmocks.NewPageRenderer(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		passwordValidator := accounthandlersmocks.NewPasswordValidator(t)
		passwordValidator.On("ValidatePassword", record.PasswordPolicyMedium, chosenPassword).Return(nil).Once()
		pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Once()

		store := newMarkerTestStore()
		HandleActivatePost(pageRenderer, store, &consumptionFailingDB{Database: db}, usercreation.New(db), passwordValidator,
			auditLogger, testAdminConsoleBaseURL).
			ServeHTTP(httptest.NewRecorder(), postActivationWithMarker(t, store, chosenPassword, chosenPassword, row.Id, codeHash))

		user, err := db.GetUserByEmail(ctx, nil, activateTestEmail)
		require.NoError(t, err)
		assert.Nil(t, user, "a failed activation must leave no account")
		var permissionRows int
		require.NoError(t, db.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM users_permissions").Scan(&permissionRows))
		assert.Zero(t, permissionRows, "and no account permission")
		pending, err := db.GetPreRegistrationById(ctx, nil, row.Id)
		require.NoError(t, err)
		require.NotNil(t, pending, "a failed activation must leave the pending registration")
		assert.Equal(t, codeHash, pending.VerificationCodeHash)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		pageRenderer.AssertExpectations(t)
	})
}
