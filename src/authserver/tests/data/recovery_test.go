package datatests

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/recovery"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The `recover` subcommand's operation, recovery.Run, on every engine: whatever it is asked, the
// user's authentication generation advances by one and their sessions and refresh tokens end, and
// each action changes what it names and nothing else (#498, its Done-when: "the data tier shows it
// on all four engines"). The two forced interleavings at the end show the user, the authenticator
// and the held grant are read under the user's row, so a credential change holding that row when
// the recovery starts is what the recovery decides on.

// recoveryPassword passes every password policy, so the test does not depend on which policy the
// shared database's settings row holds.
const recoveryPassword = "Recovery-Passw0rd!2026"

// recoveryAuditRecorder records the events recovery.Run writes.
type recoveryAuditRecorder struct {
	events  []string
	details []map[string]interface{}
}

func (r *recoveryAuditRecorder) Log(_ context.Context, auditEvent string, details map[string]interface{}) {
	r.events = append(r.events, auditEvent)
	r.details = append(r.details, details)
}

// recoveryFixture is a user as a recovery finds one: enabled, with an authenticator, a generation
// past zero, a permission of their own, a session, a refresh token bound to that session and an
// offline one, beside another user's session and token the recovery must leave alone.
type recoveryFixture struct {
	user                       *record.User
	manage                     *record.Permission
	otherPermission            *record.Permission
	session                    *record.UserSession
	sessionToken, offlineToken *record.RefreshToken
	bystanderSession           *record.UserSession
	bystanderToken             *record.RefreshToken
}

func seedRecoveryFixture(t *testing.T) recoveryFixture {
	t.Helper()
	ctx := context.Background()
	ensureSettingsRowOne(t)

	f := recoveryFixture{manage: managePermissionRow(t)}

	user := createTestUser(t)
	user.Email = strings.ToLower(user.Email)
	user.Enabled = true
	user.OTPEnabled = true
	user.OTPSecretEncrypted = []byte("the authenticator's seed")
	require.NoError(t, database.UpdateUser(ctx, nil, user))
	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		for range 2 {
			if _, err := database.IncrementUserAuthStateGeneration(ctx, tx, user.Id); err != nil {
				return err
			}
		}
		return nil
	}))
	var err error
	f.user, err = database.GetUserById(ctx, nil, user.Id)
	require.NoError(t, err)
	require.Equal(t, int64(2), f.user.AuthStateGeneration)

	f.otherPermission = createTestPermission(t, createTestResource(t))
	require.NoError(t, database.CreateUserPermission(ctx, nil, &record.UserPermission{
		UserId: f.user.Id, PermissionId: f.otherPermission.Id,
	}))

	client := createTestClient(t)
	f.session = createTestUserSession(t, f.user.Id)
	code := createTestCodeInSession(t, client.Id, f.user.Id, f.session.SessionIdentifier)
	f.sessionToken = createRecoveryTokenOfCode(t, client.Id, code.Id, f.session.SessionIdentifier)
	f.offlineToken = createRecoveryTokenOfCode(t, client.Id, code.Id, "")

	bystander := createTestUser(t)
	f.bystanderSession = createTestUserSession(t, bystander.Id)
	bystanderCode := createTestCodeInSession(t, client.Id, bystander.Id, f.bystanderSession.SessionIdentifier)
	f.bystanderToken = createRecoveryTokenOfCode(t, client.Id, bystanderCode.Id, f.bystanderSession.SessionIdentifier)
	return f
}

// createRecoveryTokenOfCode is createTokenOfCode in the shape issuance writes a code's token in:
// the user is reached through the code alone, user_id left null. The sweep's read unions the two
// shapes, so a token carrying both would be read, and reported, twice.
func createRecoveryTokenOfCode(t *testing.T, clientId, codeId int64, sessionIdentifier string) *record.RefreshToken {
	t.Helper()
	tokenType := "Refresh"
	if sessionIdentifier == "" {
		tokenType = "Offline"
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	token := &record.RefreshToken{
		CodeId:            sql.NullInt64{Int64: codeId, Valid: true},
		ClientId:          sql.NullInt64{Int64: clientId, Valid: true},
		RefreshTokenJti:   fake.UUID(),
		SessionIdentifier: sessionIdentifier,
		RefreshTokenType:  tokenType,
		Scope:             "openid profile offline_access",
		IssuedAt:          sql.NullTime{Time: now, Valid: true},
		ExpiresAt:         sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		MaxLifetime:       sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
	}
	require.NoError(t, database.CreateRefreshToken(context.Background(), nil, token))
	return token
}

// ensureSettingsRowOne writes the settings row the password policy is read from when the shared
// database holds none yet: the tier's database is migrated but not seeded, and which test writes
// settings first depends on the order the files run in.
func ensureSettingsRowOne(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	settings, err := database.GetSettingsById(ctx, nil, 1)
	require.NoError(t, err)
	if settings != nil {
		return
	}
	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return database.CreateInitialSettings(ctx, tx, &record.Settings{
			AppName:                "recovery",
			Issuer:                 "https://localhost:8080",
			PasswordPolicy:         record.PasswordPolicyLow,
			AESEncryptionKeyLegacy: []byte{},
		})
	}))
}

// heldPermissionIds answers the permission ids the user holds, one entry per row.
func heldPermissionIds(t *testing.T, userId int64) []int64 {
	t.Helper()
	grants, err := database.GetUserPermissionsByUserId(context.Background(), nil, userId)
	require.NoError(t, err)
	ids := make([]int64, 0, len(grants))
	for _, grant := range grants {
		ids = append(ids, grant.PermissionId)
	}
	return ids
}

// assertRevokedEverything holds what every recovery does, whatever it was asked: the generation
// moved by exactly one, the user's session is gone, both of their refresh tokens are revoked, and
// another user's session and token are untouched.
func assertRevokedEverything(t *testing.T, f recoveryFixture, outcome recovery.Outcome) {
	t.Helper()
	ctx := context.Background()

	after, err := database.GetUserById(ctx, nil, f.user.Id)
	require.NoError(t, err)
	assert.Equal(t, f.user.AuthStateGeneration+1, after.AuthStateGeneration, "the generation moved by exactly one")
	assert.Equal(t, f.user.AuthStateGeneration, outcome.Revocation.OldGeneration)
	assert.Equal(t, f.user.AuthStateGeneration+1, outcome.Revocation.NewGeneration)

	session, err := database.GetUserSessionById(ctx, nil, f.session.Id)
	require.NoError(t, err)
	assert.Nil(t, session, "the user's session ended")
	assert.Equal(t, []string{f.session.SessionIdentifier}, outcome.Revocation.TerminatedSessionIdentifiers)
	assertTokenRevoked(t, f.sessionToken.Id, true, "the session-bound refresh token")
	assertTokenRevoked(t, f.offlineToken.Id, true, "the offline refresh token")
	assert.ElementsMatch(t, []string{f.sessionToken.RefreshTokenJti, f.offlineToken.RefreshTokenJti},
		outcome.Revocation.RevokedRefreshTokenJtis)

	bystander, err := database.GetUserSessionById(ctx, nil, f.bystanderSession.Id)
	require.NoError(t, err)
	assert.NotNil(t, bystander, "another user's session is untouched")
	assertTokenRevoked(t, f.bystanderToken.Id, false, "another user's refresh token")
}

func TestRecovery_EachActionAloneAndAllTogether(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		request func(email string) recovery.Request
	}{
		{"grant manage", func(email string) recovery.Request {
			return recovery.Request{Email: email, GrantManage: true}
		}},
		{"set a password", func(email string) recovery.Request {
			return recovery.Request{Email: email, Password: recoveryPassword}
		}},
		{"remove the authenticator", func(email string) recovery.Request {
			return recovery.Request{Email: email, RemoveOTP: true}
		}},
		{"all three", func(email string) recovery.Request {
			return recovery.Request{Email: email, Password: recoveryPassword, GrantManage: true, RemoveOTP: true}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := seedRecoveryFixture(t)
			req := tc.request(f.user.Email)
			recorder := &recoveryAuditRecorder{}

			outcome, err := recovery.Run(ctx, database, recorder, req)
			require.NoError(t, err)

			assertRevokedEverything(t, f, outcome)
			after, err := database.GetUserById(ctx, nil, f.user.Id)
			require.NoError(t, err)

			// Each action changed what it names, and nothing it does not.
			if req.Password != "" {
				assert.True(t, outcome.PasswordSet)
				assert.True(t, passwordhash.Verify(after.PasswordHash, recoveryPassword), "the new password verifies")
			} else {
				assert.False(t, outcome.PasswordSet)
				assert.Equal(t, f.user.PasswordHash, after.PasswordHash, "the password is untouched")
			}
			if req.RemoveOTP {
				assert.True(t, outcome.OTPRemoved)
				assert.False(t, after.OTPEnabled, "the authenticator is removed")
				assert.Equal(t, f.user.OtpConfigGeneration+1, after.OtpConfigGeneration)
			} else {
				assert.False(t, outcome.OTPRemoved)
				assert.True(t, after.OTPEnabled, "the authenticator is untouched")
				assert.Equal(t, f.user.OTPSecretEncrypted, after.OTPSecretEncrypted)
				assert.Equal(t, f.user.OtpConfigGeneration, after.OtpConfigGeneration)
			}
			if req.GrantManage {
				assert.True(t, outcome.ManageGranted)
				assert.ElementsMatch(t, []int64{f.otherPermission.Id, f.manage.Id}, heldPermissionIds(t, f.user.Id),
					"manage is granted beside the permission the user held")
			} else {
				assert.False(t, outcome.ManageGranted)
				assert.Equal(t, []int64{f.otherPermission.Id}, heldPermissionIds(t, f.user.Id), "the permissions are untouched")
			}
			assert.True(t, after.Enabled)
			assert.Equal(t, f.user.Email, after.Email)

			// What was done is recorded, and only that, the revocation last.
			var want []string
			if req.Password != "" {
				want = append(want, audit.EventUpdatedUserAuthentication)
			}
			if req.RemoveOTP {
				want = append(want, audit.EventDisabledOTP)
			}
			if req.GrantManage {
				want = append(want, audit.EventAddedUserPermission, audit.EventAdministrativePermissionChanged)
			}
			want = append(want, audit.EventRevokedUserAuthState)
			assert.Equal(t, want, recorder.events)
			revoked := recorder.details[len(recorder.details)-1]
			assert.Equal(t, revocation.ReasonRecoveryCommand, revoked["reason"])
			assert.Equal(t, recovery.Actor, revoked["command"])
		})
	}
}

// A second grant-only run finds manage held, writes no second row and records no grant, and still
// ends what was signed in since the first (#498 decision D2).
func TestRecovery_ASecondGrantWritesNoSecondRow(t *testing.T) {
	ctx := context.Background()
	f := seedRecoveryFixture(t)
	req := recovery.Request{Email: f.user.Email, GrantManage: true}

	_, err := recovery.Run(ctx, database, &recoveryAuditRecorder{}, req)
	require.NoError(t, err)

	afterFirst, err := database.GetUserById(ctx, nil, f.user.Id)
	require.NoError(t, err)
	session := createTestUserSession(t, f.user.Id)
	recorder := &recoveryAuditRecorder{}

	outcome, err := recovery.Run(ctx, database, recorder, req)
	require.NoError(t, err)

	assert.False(t, outcome.ManageGranted)
	assert.ElementsMatch(t, []int64{f.otherPermission.Id, f.manage.Id}, heldPermissionIds(t, f.user.Id),
		"one manage row, not two")
	assert.Equal(t, []string{audit.EventRevokedUserAuthState}, recorder.events)
	afterSecond, err := database.GetUserById(ctx, nil, f.user.Id)
	require.NoError(t, err)
	assert.Equal(t, afterFirst.AuthStateGeneration+1, afterSecond.AuthStateGeneration)
	ended, err := database.GetUserSessionById(ctx, nil, session.Id)
	require.NoError(t, err)
	assert.Nil(t, ended, "the session started after the first run ended with the second")
}

// A refusal writes nothing: a password the policy refuses leaves the generation, the sessions, the
// tokens and every credential as they were.
func TestRecovery_ARefusalWritesNothing(t *testing.T) {
	ctx := context.Background()
	f := seedRecoveryFixture(t)
	recorder := &recoveryAuditRecorder{}

	_, err := recovery.Run(ctx, database, recorder, recovery.Request{
		Email: f.user.Email, Password: "x", GrantManage: true, RemoveOTP: true,
	})

	var refusal *recovery.RefusedError
	require.ErrorAs(t, err, &refusal)
	assert.Contains(t, refusal.Reason, "the password is refused by the stored password policy")
	assert.Empty(t, recorder.events)
	after, err := database.GetUserById(ctx, nil, f.user.Id)
	require.NoError(t, err)
	assert.Equal(t, f.user.AuthStateGeneration, after.AuthStateGeneration)
	assert.True(t, after.OTPEnabled)
	assert.Equal(t, []int64{f.otherPermission.Id}, heldPermissionIds(t, f.user.Id))
	session, err := database.GetUserSessionById(ctx, nil, f.session.Id)
	require.NoError(t, err)
	assert.NotNil(t, session)
	assertTokenRevoked(t, f.sessionToken.Id, false, "the session-bound refresh token")
}

// A removal and a new enrolment of the authenticator hold the user's row when the recovery starts.
// The recovery waits for the row and removes the authenticator the change left. Read before the
// transaction, it compared against the generation the change moved past, removed nothing, and said
// none had been enrolled, leaving the new authenticator in place (#498 review F5).
func TestRecovery_RemovesTheAuthenticatorAChangeHoldingTheRowLeft(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	ctx := context.Background()
	other := secondDatabase(t)
	f := seedRecoveryFixture(t)

	holder := beginTx(t)
	require.NoError(t, database.AcquireUserRow(ctx, holder, f.user.Id))
	removed, err := otpcredential.RemoveTx(ctx, database, holder, f.user)
	require.NoError(t, err)
	require.True(t, removed)
	established, err := database.TryEstablishUserOTP(ctx, holder, f.user.Id, f.user.OtpConfigGeneration+1,
		[]byte("the new authenticator's seed"))
	require.NoError(t, err)
	require.True(t, established)
	_, err = database.IncrementUserOtpConfigGeneration(ctx, holder, f.user.Id)
	require.NoError(t, err)

	recorder := &recoveryAuditRecorder{}
	recovering := goBlocked(t, "the recovery", holder, func(reached func()) error {
		reached()
		_, runErr := recovery.Run(ctx, other, recorder, recovery.Request{Email: f.user.Email, RemoveOTP: true})
		return runErr
	})
	recovering.requireBlocked(t)
	recovering.requireStillWaiting(t)
	require.NoError(t, database.CommitTransaction(ctx, holder))
	require.NoError(t, recovering.await(t))

	after, err := database.GetUserById(ctx, nil, f.user.Id)
	require.NoError(t, err)
	assert.False(t, after.OTPEnabled, "the authenticator enrolled while the recovery waited is removed")
	assert.Equal(t, f.user.OtpConfigGeneration+3, after.OtpConfigGeneration)
	assert.Equal(t, []string{audit.EventDisabledOTP, audit.EventRevokedUserAuthState}, recorder.events)
}

// A grant of manage holds the user's row when the recovery starts. The recovery waits for the row,
// finds manage held, and writes no second row. Read before the transaction, it found none and wrote
// a second, since users_permissions has no unique key on the pair (#498 review F5).
func TestRecovery_FindsAGrantHoldingTheRowAndWritesNoSecond(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	ctx := context.Background()
	other := secondDatabase(t)
	f := seedRecoveryFixture(t)

	holder := beginTx(t)
	require.NoError(t, database.AcquireUserRow(ctx, holder, f.user.Id))
	require.NoError(t, database.CreateUserPermission(ctx, holder, &record.UserPermission{
		UserId: f.user.Id, PermissionId: f.manage.Id,
	}))

	recorder := &recoveryAuditRecorder{}
	recovering := goBlocked(t, "the recovery", holder, func(reached func()) error {
		reached()
		_, runErr := recovery.Run(ctx, other, recorder, recovery.Request{Email: f.user.Email, GrantManage: true})
		return runErr
	})
	recovering.requireBlocked(t)
	recovering.requireStillWaiting(t)
	require.NoError(t, database.CommitTransaction(ctx, holder))
	require.NoError(t, recovering.await(t))

	assert.ElementsMatch(t, []int64{f.otherPermission.Id, f.manage.Id}, heldPermissionIds(t, f.user.Id),
		"one manage row, the one granted while the recovery waited")
	assert.Equal(t, []string{audit.EventRevokedUserAuthState}, recorder.events)
}
