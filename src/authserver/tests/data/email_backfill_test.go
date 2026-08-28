package datatests

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emailBackfillCase is one seeded users row and what BackfillLowercaseEmails must do to it.
//
// ONE set of expectations, on all four engines, and that is the point rather than a
// simplification. It carried two until migration 000040 landed: MySQL and SQL Server folded
// case in the UNIQUE index on email, so a case-variant pair could not be seeded there at all
// and the second member's insert was refused, while SQLite and PostgreSQL accepted both rows.
// 000040 pins every string column to a case-sensitive collation, so the pair is now permitted
// on all four and the collision policy runs on all four.
type emailBackfillCase struct {
	seed        string
	want        string
	wantEnabled bool

	why string
}

// TestBackfillLowercaseEmails exercises the startup pass that brings every stored address down
// to its lowercase form and settles a pair that differs only by case (#221, #283). It runs
// against an ISOLATED database of the configured dialect (see migration_testdb_helper.go).
//
// The data tier is the tier that matters for it. The rule is written once in Go precisely
// because SQL cannot express it identically on four engines, and the fact that claim rests on is
// a fact about an engine: SQLite's own LOWER() maps ASCII only through modernc.org/sqlite, so
// the Ädmin case below is untouched there by any LOWER()-based statement. That is not
// observable from any other tier.
//
// The properties, in the order they appear below:
//
//  1. Every seeded shape lands on its stated address and its stated enabled flag, and a
//     disabled non-survivor keeps its address exactly as it was stored.
//
//  2. The pair can be seeded on EVERY engine, which is #283's own goal read from the other
//     side: before migration 000040 the insert was refused on MySQL and SQL Server. Asserted
//     rather than assumed, because if it stopped holding the collision expectations below
//     would be unreachable on two engines and nothing else would say so.
//
//  3. The counts returned match the rows that moved, so a pass that reported work it did not
//     do would fail here as well as one that did work it did not report.
//
//  4. A second run reports nothing and moves nothing. That is not decoration: a disabled
//     non-survivor deliberately KEEPS its mixed-case address, so it is selected by every later
//     scan, and only the enabled check stops it being counted again on every restart.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestBackfillLowercaseEmails
func TestBackfillLowercaseEmails(t *testing.T) {
	h := newIsolatedDB(t)
	if err := h.Migrator.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding")
	}

	// Seeded in this order on purpose: the mixed-case member of each pair is written FIRST, so
	// it holds the lower id. A rule that fell back to the lowest id unconditionally would then
	// keep the row that cannot sign in, which is the outcome the survivor rule exists to avoid,
	// and a fixture seeded the other way round would agree with both rules.
	cases := []emailBackfillCase{
		{
			seed: "carol@x.com", want: "carol@x.com", wantEnabled: true,
			why: "already lowercase and alone, so nothing may touch it",
		},
		{
			seed: "Dave@x.com", want: "dave@x.com", wantEnabled: true,
			why: "mixed case and alone, the unambiguous repair",
		},
		{
			seed: "Bob@x.com", want: "Bob@x.com", wantEnabled: false,
			why: "the non-survivor of a pair: disabled, address untouched, because nothing here deletes, renames or merges an account",
		},
		{
			seed: "bob@x.com", want: "bob@x.com", wantEnabled: true,
			why: "the survivor of the pair: it is the row that signs in today and it keeps the address",
		},
		{
			seed: "ERIN@x.com", want: "erin@x.com", wantEnabled: true,
			why: "no member of this group is already lowercase, so the lowest id takes the address",
		},
		{
			seed: "Erin@x.com", want: "Erin@x.com", wantEnabled: false,
			why: "the loser of the fallback, disabled with its address intact",
		},
		{
			seed: "Ädmin@x.com", want: "ädmin@x.com", wantEnabled: true,
			why: "the case that separates Go's lowercase mapping from SQL's: SQLite's LOWER() is ASCII-only through modernc.org/sqlite, so a LOWER()-based statement would leave this row exactly as it is and the address would still be unreachable",
		},
	}

	ids := make(map[string]int64, len(cases))
	for i, c := range cases {
		user := &models.User{
			Enabled:  true,
			Subject:  uuid.New(),
			Username: fmt.Sprintf("emailbackfill%d", i),
			Email:    c.seed,
		}
		// 2. Every seed lands, on every engine, the case-variant pairs included. Before
		// migration 000040 the second member of a pair was refused on MySQL and SQL Server,
		// because idx_email folded case there.
		require.NoErrorf(t, h.DB.CreateUser(nil, user),
			"seed %q: since 000040 every engine holds a case-variant pair, so this insert must succeed on %s too",
			c.seed, dbType())
		ids[c.seed] = user.Id
	}

	lowercased, disabled, err := h.DB.BackfillLowercaseEmails()
	require.NoError(t, err, "BackfillLowercaseEmails")

	// 1 and 3.
	wantLowercased, wantDisabled := 0, 0
	for _, c := range cases {
		id, seeded := ids[c.seed]
		if !seeded {
			continue
		}

		want, wantEnabled := c.want, c.wantEnabled
		if want != c.seed {
			wantLowercased++
		}
		if !wantEnabled {
			wantDisabled++
		}

		got, err := h.DB.GetUserById(nil, id)
		require.NoErrorf(t, err, "read back the row seeded as %q", c.seed)
		require.NotNilf(t, got, "the row seeded as %q must still exist: this pass never deletes", c.seed)
		assert.Equalf(t, want, got.Email, "%q must end up as %q: %s", c.seed, want, c.why)
		assert.Equalf(t, wantEnabled, got.Enabled, "%q must end up enabled=%v: %s", c.seed, wantEnabled, c.why)
	}

	assert.Equalf(t, wantLowercased, lowercased,
		"the pass must report the rows it lowercased, and %d rows changed address on %s", wantLowercased, dbType())
	assert.Equalf(t, wantDisabled, disabled,
		"the pass must report the rows it disabled, and %d rows lost enabled on %s", wantDisabled, dbType())

	// 4. Idempotent and resumable, on BackfillEncryptedOTPSecrets' terms.
	lowercased2, disabled2, err := h.DB.BackfillLowercaseEmails()
	require.NoError(t, err, "second BackfillLowercaseEmails")
	assert.Zerof(t, lowercased2, "a second run has nothing left to lowercase on %s", dbType())
	assert.Zerof(t, disabled2, "a second run must not re-disable the non-survivors it already disabled on %s: they keep their mixed-case address on purpose, so they are selected by every later scan", dbType())

	for _, c := range cases {
		id, seeded := ids[c.seed]
		if !seeded {
			continue
		}
		want, wantEnabled := c.want, c.wantEnabled

		got, err := h.DB.GetUserById(nil, id)
		require.NoErrorf(t, err, "read back %q after the second run", c.seed)
		require.NotNil(t, got)
		assert.Equalf(t, want, got.Email, "%q must be unchanged by a second run", c.seed)
		assert.Equalf(t, wantEnabled, got.Enabled, "%q must be unchanged by a second run", c.seed)
	}
}

// TestBackfillLowercaseEmails_DisablingALoserRevokesItsAuthState pins the invariant #106
// established, which the collision backfill is the newest site obliged to uphold: enabled
// going true-to-false is the moment a user's outstanding credentials die.
//
// Writing enabled = false on its own invalidates nothing durable. A session, an authorization
// code and a refresh token each carry the auth_state_generation they were issued under, and
// that value still equals the user's, so the only thing between a stale credential and its old
// access is the disabled flag that every credential path also checks. Turn the flag back on,
// which an administrator most plausibly does immediately after resolving the email collision by
// hand, and every pre-backfill credential is authoritative again. The administrative disable
// path never had that hole: it pairs the flag with RevokeUserAuthState in one transaction.
//
// So the assertions come in two halves. Before the re-enable: disabled, generation advanced,
// sessions gone, refresh tokens revoked. After it: still nothing usable, which is the half that
// says the first half was durable rather than a consequence of the flag.
//
// The survivor is asserted throughout as the control. A pass that revoked the whole colliding
// group would satisfy every assertion in the first half and would have logged out the one
// account the collision policy exists to protect.
//
// The data tier is the tier for it. The claim is about rows in four tables written inside one
// transaction, on four engines, and no other tier can see whether the transaction happened.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestBackfillLowercaseEmails_DisablingALoserRevokesItsAuthState
func TestBackfillLowercaseEmails_DisablingALoserRevokesItsAuthState(t *testing.T) {
	h := newIsolatedDB(t)
	if err := h.Migrator.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding")
	}

	// The loser is seeded first, so it holds the lower id and the survivor rule has to reach
	// past id order to pick the lowercase row. Both rows exist on every engine only because
	// migration 000040 made idx_email case-sensitive.
	loser := &models.User{Enabled: true, Subject: uuid.New(), Username: "revokeloser", Email: "Revoke@x.com"}
	require.NoError(t, h.DB.CreateUser(nil, loser), "seed the mixed-case loser")
	survivor := &models.User{Enabled: true, Subject: uuid.New(), Username: "revokesurvivor", Email: "revoke@x.com"}
	require.NoError(t, h.DB.CreateUser(nil, survivor), "seed the lowercase survivor")

	clientId := seedClient000035(t, h, "revoke-backfill-client")

	// Everything the loser authenticated under, in every shape that carries a generation.
	loserSession := seedSessionForBackfill(t, h, loser.Id)
	loserCode := seedCodeForBackfill(t, h, clientId, loser.Id)
	loserAuthCodeToken := seedRefreshTokenForBackfill(t, h, clientId, loser.Id, loserCode.Id)
	loserRopcToken := seedRefreshTokenForBackfill(t, h, clientId, loser.Id, 0)

	// And the same for the survivor, which none of it may touch.
	survivorSession := seedSessionForBackfill(t, h, survivor.Id)
	survivorRopcToken := seedRefreshTokenForBackfill(t, h, clientId, survivor.Id, 0)

	before, err := h.DB.GetUserById(nil, loser.Id)
	require.NoError(t, err, "read the loser's generation before the pass")
	generationBefore := before.AuthStateGeneration
	require.Equalf(t, generationBefore, loserSession.AuthStateGeneration,
		"the fixture is only meaningful if the session starts out matching the user: it does not, so nothing below would prove anything")

	_, disabled, err := h.DB.BackfillLowercaseEmails()
	require.NoError(t, err, "BackfillLowercaseEmails")
	require.Equalf(t, 1, disabled, "exactly the loser must be disabled on %s", dbType())

	// Half one: the disable took the credentials with it.
	got, err := h.DB.GetUserById(nil, loser.Id)
	require.NoError(t, err, "read the loser back")
	assert.False(t, got.Enabled, "the loser must be disabled")
	assert.Equalf(t, generationBefore+1, got.AuthStateGeneration,
		"disabling must advance the authentication generation, which is what invalidates the code and any token that outlives this pass; it is at %d and the loser's credentials were issued at %d",
		got.AuthStateGeneration, generationBefore)

	sessions, err := h.DB.GetUserSessionsByUserId(nil, loser.Id)
	require.NoError(t, err, "read the loser's sessions")
	assert.Emptyf(t, sessions, "every session of a disabled loser must be deleted; session %d survived", loserSession.Id)

	for _, tok := range []struct {
		id   int64
		what string
	}{
		{loserAuthCodeToken.Id, "the authorization-code shape, linked through codes.user_id"},
		{loserRopcToken.Id, "the ROPC shape, linked through refresh_tokens.user_id"},
	} {
		read, err := h.DB.GetRefreshTokenById(nil, tok.id)
		require.NoErrorf(t, err, "read refresh token %d back", tok.id)
		require.NotNilf(t, read, "refresh token %d must still exist; nothing here deletes tokens", tok.id)
		assert.Truef(t, read.Revoked,
			"a disabled loser's refresh token must be revoked, and the sweep is user-scoped precisely so it reaches both linkage shapes: %s", tok.what)
	}

	// The control. The survivor keeps its session, its token and its generation, because
	// nothing was taken away from it.
	survivorAfter, err := h.DB.GetUserById(nil, survivor.Id)
	require.NoError(t, err, "read the survivor back")
	assert.True(t, survivorAfter.Enabled, "the survivor must stay enabled")
	assert.Equalf(t, survivor.AuthStateGeneration, survivorAfter.AuthStateGeneration,
		"the survivor's generation must not move: advancing it would log out the one account the collision policy exists to keep working")
	survivorSessions, err := h.DB.GetUserSessionsByUserId(nil, survivor.Id)
	require.NoError(t, err, "read the survivor's sessions")
	require.Lenf(t, survivorSessions, 1, "the survivor's session must survive")
	assert.Equal(t, survivorSession.SessionIdentifier, survivorSessions[0].SessionIdentifier)
	survivorTokenAfter, err := h.DB.GetRefreshTokenById(nil, survivorRopcToken.Id)
	require.NoError(t, err, "read the survivor's token back")
	require.NotNil(t, survivorTokenAfter)
	assert.False(t, survivorTokenAfter.Revoked, "the survivor's refresh token must not be revoked")

	// Half two: an administrator re-enables the loser, which is what the collision leaves them
	// to do, and the enabling path deliberately revokes nothing because there is nothing to
	// take away. Every pre-backfill credential must STILL be dead, and it is dead because the
	// generation moved rather than because the flag was off.
	transitioned, err := h.DB.TrySetUserEnabled(nil, loser.Id, false, true)
	require.NoError(t, err, "re-enable the loser")
	require.True(t, transitioned, "the loser must have been disabled for this to be a re-enable")

	reenabled, err := h.DB.GetUserById(nil, loser.Id)
	require.NoError(t, err, "read the re-enabled loser")
	require.True(t, reenabled.Enabled, "the loser must be enabled again")

	sessionsAfter, err := h.DB.GetUserSessionsByUserId(nil, loser.Id)
	require.NoError(t, err, "read the loser's sessions after the re-enable")
	assert.Emptyf(t, sessionsAfter, "a session deleted by the backfill cannot come back, and one that was never deleted would be usable now")

	codeAfter, err := h.DB.GetCodeById(nil, loserCode.Id)
	require.NoError(t, err, "read the loser's authorization code after the re-enable")
	require.NotNil(t, codeAfter, "nothing deletes codes, which is why the generation has to be what invalidates them")
	assert.Lessf(t, codeAfter.AuthStateGeneration, reenabled.AuthStateGeneration,
		"the code was issued at generation %d and the user is at %d; equal would mean this code is redeemable again on a re-enabled account",
		codeAfter.AuthStateGeneration, reenabled.AuthStateGeneration)

	for _, id := range []int64{loserAuthCodeToken.Id, loserRopcToken.Id} {
		read, err := h.DB.GetRefreshTokenById(nil, id)
		require.NoErrorf(t, err, "read refresh token %d after the re-enable", id)
		require.NotNil(t, read)
		assert.Truef(t, read.Revoked, "refresh token %d must stay revoked across a re-enable", id)
		assert.Lessf(t, read.AuthStateGeneration, reenabled.AuthStateGeneration,
			"and it must also be behind the user's generation, so revoked = false written by hand would not resurrect it")
	}
}

// seedSessionForBackfill gives a user one session at whatever generation they currently hold,
// which is what makes it a credential the backfill has to invalidate rather than a row.
func seedSessionForBackfill(t *testing.T, h *isolatedDB, userId int64) *models.UserSession {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Microsecond)
	session := &models.UserSession{
		SessionIdentifier: uuid.NewString(),
		Started:           now,
		LastAccessed:      now,
		AuthMethods:       "pwd",
		AcrLevel:          enums.AcrLevel1.String(),
		AuthTime:          now,
		IpAddress:         "192.0.2.10",
		DeviceName:        "backfill-fixture",
		DeviceType:        "desktop",
		DeviceOS:          "Linux",
		UserId:            userId,
	}
	require.NoErrorf(t, h.DB.CreateUserSession(nil, session), "seed a session for user %d", userId)
	return session
}

// seedCodeForBackfill gives a user one authorization code. It is never deleted by anything in
// this pass, deliberately: the generation is what invalidates a code, so a surviving row at a
// stale generation is exactly the evidence the assertions want.
func seedCodeForBackfill(t *testing.T, h *isolatedDB, clientId, userId int64) *models.Code {
	t.Helper()

	suffix := uuid.NewString()
	code := &models.Code{
		ClientId:            clientId,
		UserId:              userId,
		Code:                "backfill_" + suffix,
		CodeHash:            "backfillhash_" + suffix,
		CodeChallenge:       sql.NullString{String: "backfillchallenge", Valid: true},
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: true},
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "backfillstate",
		Nonce:               "backfillnonce",
		IpAddress:           "192.0.2.10",
		UserAgent:           "backfill-fixture",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   uuid.NewString(),
		AcrLevel:            enums.AcrLevel1.String(),
		AuthMethods:         "pwd",
	}
	require.NoErrorf(t, h.DB.CreateCode(nil, code), "seed a code for user %d", userId)
	return code
}

// seedRefreshTokenForBackfill gives a user one refresh token in one of the two linkage shapes:
// codeId non-zero is the authorization-code shape, where the user is reached through the code,
// and codeId zero is the ROPC shape, where the user is on the token itself. Both exist because
// the revocation sweep is user-scoped in order to cover both, and a sweep that covered one
// would pass a test that seeded only the other.
func seedRefreshTokenForBackfill(t *testing.T, h *isolatedDB, clientId, userId, codeId int64) *models.RefreshToken {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Microsecond)
	token := &models.RefreshToken{
		ClientId:         sql.NullInt64{Int64: clientId, Valid: true},
		RefreshTokenJti:  uuid.NewString(),
		RefreshTokenType: "Bearer",
		Scope:            "openid profile offline_access",
		IssuedAt:         sql.NullTime{Time: now, Valid: true},
		ExpiresAt:        sql.NullTime{Time: now.Add(time.Hour), Valid: true},
		MaxLifetime:      sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
	}
	if codeId != 0 {
		token.CodeId = sql.NullInt64{Int64: codeId, Valid: true}
	} else {
		token.UserId = sql.NullInt64{Int64: userId, Valid: true}
	}
	require.NoErrorf(t, h.DB.CreateRefreshToken(nil, token), "seed a refresh token for user %d", userId)
	return token
}

// TestBackfillLowercaseEmails_DisablingALoserIsAudited pins the OTHER half of the invariant
// #106 decision 7 established. Its sibling above proves the backfill revokes; this proves it
// attests to having revoked.
//
// The distinction is the whole reason the event exists. constants.AuditRevokedUserAuthState is
// documented as emitted by every site that invalidates a user's live authentication state,
// "even when nothing was found to revoke, so the event attests that the action happened rather
// than that something was there to sweep". Four credential endpoints uphold that through
// handlers.LogRevokedUserAuthState. The collision backfill is the fifth site and the only one
// nobody asked for: it disables an account and destroys every credential it held, at startup,
// because two stored addresses differed only by case. An operator who finds an account disabled
// has audit_logs to ask, and a slog line in a process a rolling deployment may already have
// replaced is not the same record.
//
// The data tier is the tier for it. The claim is that a row lands in audit_logs on four
// engines, carrying a details payload that survived a round trip through JSON and the column
// type each engine gives it, and no other tier writes that row at all: the AuditLogger the
// handlers use lives in the authserver module, and this site cannot reach it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
func TestBackfillLowercaseEmails_DisablingALoserIsAudited(t *testing.T) {
	// revokedUserAuthStateDetails is the payload as a consumer parses it. Typed rather than
	// map[string]interface{} so a number that arrived as a JSON float is compared as the id it
	// is meant to be, and so a field renamed on one side of the wire fails here.
	type revokedUserAuthStateDetails struct {
		UserId                       int64    `json:"userId"`
		Reason                       string   `json:"reason"`
		LoggedInUser                 string   `json:"loggedInUser"`
		TerminatedSessionIdentifiers []string `json:"terminatedSessionIdentifiers"`
		RevokedRefreshTokenJtis      []string `json:"revokedRefreshTokenJtis"`
		PreservedSessionIdentifier   string   `json:"preservedSessionIdentifier"`
		OldGeneration                int64    `json:"oldGeneration"`
		NewGeneration                int64    `json:"newGeneration"`
	}

	// seedAuditFixture builds the collision this test is about, on a database whose audit
	// settings are whatever the caller asks for. Returns the two users and the credentials the
	// loser held, so both subtests assert against the same shape.
	seedAuditFixture := func(t *testing.T, auditToDatabase bool) (*isolatedDB, *models.User, *models.User, *models.UserSession, *models.RefreshToken) {
		t.Helper()
		h := newIsolatedDB(t)
		if err := h.Migrator.Up(); err != nil && !errors.Is(err, gomigrate.ErrNoChange) {
			require.NoError(t, err, "migrate to head before seeding")
		}

		// No migration writes a settings row: the SEEDER does, and it runs after the backfill,
		// so an isolated migrated database has none. The pass reads settings to decide where
		// the event goes, exactly as AuditLogger.Log does, so the row is a precondition of
		// this test rather than incidental fixture.
		settings := &models.Settings{
			// Empty rather than absent: aes_encryption_key is NOT NULL on MySQL, so a nil
			// slice is refused. Empty and not 32 bytes on purpose, because that length is what
			// runStartupDataTasks reads as a legacy data key still to be migrated.
			AESEncryptionKeyLegacy:     []byte{},
			AuditLogsInConsoleEnabled:  true,
			AuditLogsInDatabaseEnabled: auditToDatabase,
		}
		require.NoError(t, h.DB.CreateSettings(nil, settings), "seed the settings row")
		require.Equalf(t, int64(1), settings.Id,
			"the pass reads settings id 1, so a fixture whose row landed at %d would prove nothing", settings.Id)

		loser := &models.User{Enabled: true, Subject: uuid.New(), Username: "auditloser", Email: "Audited@x.com"}
		require.NoError(t, h.DB.CreateUser(nil, loser), "seed the mixed-case loser")
		survivor := &models.User{Enabled: true, Subject: uuid.New(), Username: "auditsurvivor", Email: "audited@x.com"}
		require.NoError(t, h.DB.CreateUser(nil, survivor), "seed the lowercase survivor")

		clientId := seedClient000035(t, h, "audit-backfill-client")
		session := seedSessionForBackfill(t, h, loser.Id)
		token := seedRefreshTokenForBackfill(t, h, clientId, loser.Id, 0)

		// The survivor holds credentials too, so a payload that swept the whole group rather
		// than the loser would name them and fail below.
		seedSessionForBackfill(t, h, survivor.Id)
		seedRefreshTokenForBackfill(t, h, clientId, survivor.Id, 0)

		return h, loser, survivor, session, token
	}

	t.Run("the disable writes one revoked_user_auth_state row naming the loser", func(t *testing.T) {
		h, loser, survivor, session, token := seedAuditFixture(t, true)

		before, err := h.DB.GetUserById(nil, loser.Id)
		require.NoError(t, err, "read the loser's generation before the pass")

		_, disabled, err := h.DB.BackfillLowercaseEmails()
		require.NoError(t, err, "BackfillLowercaseEmails")
		require.Equalf(t, 1, disabled, "exactly the loser must be disabled on %s", dbType())

		logs, total, err := h.DB.GetAuditLogsPaginated(nil, 1, 50, constants.AuditRevokedUserAuthState)
		require.NoError(t, err, "read audit_logs back")
		require.Equalf(t, 1, total,
			"disabling one account must leave exactly one %s row; got %d",
			constants.AuditRevokedUserAuthState, total)
		require.Len(t, logs, 1)

		var details revokedUserAuthStateDetails
		require.NoError(t, json.Unmarshal([]byte(logs[0].Details), &details),
			"the details column must hold the payload as JSON: %q", logs[0].Details)

		assert.Equalf(t, loser.Id, details.UserId,
			"the event must name the account that lost its credentials, not the one that kept them (survivor is id %d)", survivor.Id)
		assert.NotEqual(t, survivor.Id, details.UserId, "the survivor was never revoked, so nothing may attest that it was")
		assert.Equal(t, constants.RevocationReasonEmailCollisionBackfill, details.Reason,
			"the reason field is what tells this site apart from the four credential sites sharing the event")
		assert.Empty(t, details.LoggedInUser, "no administrator is acting during a startup pass")
		assert.Empty(t, details.PreservedSessionIdentifier,
			"the preservation exception exists so an administrator does not sign themselves out; nobody is signed in here")

		// The lists name what this call TRANSITIONED. Asserted against the seeded credentials
		// rather than for non-emptiness, so a payload that reported the wrong user's sweep
		// would fail even though it was well-formed.
		assert.Equal(t, []string{session.SessionIdentifier}, details.TerminatedSessionIdentifiers,
			"the deleted session must be named")
		assert.Equal(t, []string{token.RefreshTokenJti}, details.RevokedRefreshTokenJtis,
			"the revoked token must be named")

		assert.Equalf(t, before.AuthStateGeneration, details.OldGeneration,
			"oldGeneration must be the generation this call invalidated")
		assert.Equalf(t, before.AuthStateGeneration+1, details.NewGeneration,
			"newGeneration must be the value that landed")

		// The pass is idempotent, and so is its trace. A second run disables nobody, so a
		// second event would be attesting to an action that did not happen: an auditor
		// counting these rows would read one forced logout per restart.
		_, disabledAgain, err := h.DB.BackfillLowercaseEmails()
		require.NoError(t, err, "second BackfillLowercaseEmails")
		require.Equal(t, 0, disabledAgain, "the second run must disable nobody")

		_, totalAfter, err := h.DB.GetAuditLogsPaginated(nil, 1, 50, constants.AuditRevokedUserAuthState)
		require.NoError(t, err, "re-read audit_logs")
		assert.Equalf(t, 1, totalAfter,
			"a run that disabled nobody must audit nothing; the count went %d to %d", 1, totalAfter)
	})

	t.Run("the operator's audit settings decide the database target", func(t *testing.T) {
		h, loser, _, _, _ := seedAuditFixture(t, false)

		_, disabled, err := h.DB.BackfillLowercaseEmails()
		require.NoError(t, err, "BackfillLowercaseEmails")
		require.Equal(t, 1, disabled, "the disable happens whatever the audit settings say")

		_, total, err := h.DB.GetAuditLogsPaginated(nil, 1, 50, constants.AuditRevokedUserAuthState)
		require.NoError(t, err, "read audit_logs back")
		assert.Equalf(t, 0, total,
			"with audit_logs_in_database_enabled off this event must not be written; it is the one event an operator could not turn off otherwise, and %d rows say it is", total)

		// And the revocation still happened, which is the half that must never depend on the
		// audit configuration.
		got, err := h.DB.GetUserById(nil, loser.Id)
		require.NoError(t, err, "read the loser back")
		assert.False(t, got.Enabled, "the loser must be disabled whether or not the event was recorded")
		sessions, err := h.DB.GetUserSessionsByUserId(nil, loser.Id)
		require.NoError(t, err, "read the loser's sessions")
		assert.Empty(t, sessions, "the sweep must not depend on the audit configuration either")
	})
}
