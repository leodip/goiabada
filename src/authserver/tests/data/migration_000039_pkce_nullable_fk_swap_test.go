package datatests

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 000039 carries two of #282's divergences at once, because both need the same SQLite
// table rebuild: codes.code_challenge and code_challenge_method become nullable there
// (divergence 3), and refresh_tokens.user_id and client_id come down to ON DELETE NO
// ACTION on the three engines that still cascade (divergence 5). SQL Server has been at
// the final state on both counts since its own 000007 and 000011, so it gets no file.
//
// predecessor000039 is the version this migration follows ON THIS ENGINE. The histories
// are sparse and golang-migrate's read() calls versionExists(to) before doing anything,
// so Migrate(38) fails outright on sqlite, mysql and postgres rather than migrating to
// the nearest version they do have.
func predecessor000039() uint {
	switch dbType() {
	case "mysql":
		return 37 // 000037 is MySQL's own, the audit_logs default
	case "postgres":
		return 35 // PostgreSQL has none of 000036 to 000038
	case "mssql":
		return 38 // 000038 is SQL Server's own, the nvarchar columns; its head
	default: // sqlite
		return 36 // 000036 is SQLite's own, the refresh_tokens(client_id) index
	}
}

// hasMigration000039 is false on SQL Server alone, which needs no file.
func hasMigration000039() bool { return dbType() != "mssql" }

func isSQLite000039() bool { return dbType() == "" || dbType() == "sqlite" }

// TestMigration000039_ShapeDifferenceIsExactlyIntended is decision 5's whole purpose. The
// SQLite half of this migration hand-writes codes (22 columns, 2 foreign keys, 3 indexes)
// and refresh_tokens (17 columns, 3 foreign keys, 5 indexes) in the up file and again in
// the down, and a dropped column, a lost index or a changed foreign key action would be
// silent: PRAGMA foreign_key_check does not see any of them.
//
// So the assertion is not a list of things someone remembered to check. It builds the
// EXPECTED after-shape by applying only the intended edits to the before-shape, and
// requires the real after-shape to equal it. Anything else that moved fails, including
// something the test author never thought of.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000039_ShapeDifferenceIsExactlyIntended
func TestMigration000039_ShapeDifferenceIsExactlyIntended(t *testing.T) {
	h := newIsolatedDB(t)

	pred := predecessor000039()
	require.NoErrorf(t, h.Migrator.Migrate(pred), "migrate to %06d", pred)

	codesBefore := dumpTable(t, h, "codes")
	rtBefore := dumpTable(t, h, "refresh_tokens")

	codesWant := intendedCodes000039(codesBefore)
	rtWant := intendedRefreshTokens000039(rtBefore)

	if !hasMigration000039() {
		// SQL Server: the intended edit set is empty on both tables, so the shape at its
		// head IS the final shape. Asserting that here is what stops "no file needed"
		// being taken on trust.
		require.Equal(t, codesBefore, codesWant, "the intended edit set must be empty on mssql")
		require.Equal(t, rtBefore, rtWant, "the intended edit set must be empty on mssql")
		assertFinalShape000039(t, "at 000038", codesBefore, rtBefore)
		return
	}

	require.NoError(t, h.Migrator.Migrate(39), "apply 000039")
	assertShape000039(t, h, "after apply", codesWant, rtWant)
	assertFinalShape000039(t, "after apply", dumpTable(t, h, "codes"), dumpTable(t, h, "refresh_tokens"))

	require.NoErrorf(t, h.Migrator.Migrate(pred), "roll back to %06d", pred)
	assertShape000039(t, h, "after down", codesBefore, rtBefore)

	require.NoError(t, h.Migrator.Migrate(39), "re-apply 000039")
	assertShape000039(t, h, "after down/up round trip", codesWant, rtWant)
	assertFinalShape000039(t, "after round trip", dumpTable(t, h, "codes"), dumpTable(t, h, "refresh_tokens"))
}

// intendedCodes000039 is the before-shape with divergence 3's edit applied and nothing
// else: both PKCE columns nullable. On the three engines where they already are, the edit
// changes nothing, which is the correct expectation there rather than a special case.
func intendedCodes000039(before tableShape) tableShape {
	want := copyShape000039(before)
	for i := range want.Columns {
		switch want.Columns[i].Name {
		case "code_challenge", "code_challenge_method":
			want.Columns[i].Nullable = true
		}
	}
	return want
}

// intendedRefreshTokens000039 is the before-shape with divergence 5's edit applied and
// nothing else: user_id and client_id move to NO ACTION. code_id is deliberately left
// alone; its cascade is the one action all four engines already agree on, and a rebuild
// that dropped it would delete a token's row when its code expired for a different
// reason than the one intended.
func intendedRefreshTokens000039(before tableShape) tableShape {
	want := copyShape000039(before)
	for i := range want.ForeignKeys {
		switch want.ForeignKeys[i].Column {
		case "user_id", "client_id":
			want.ForeignKeys[i].OnDelete = "NO ACTION"
		}
	}
	return want
}

// copyShape000039 deep-copies a tableShape so the intended-edit helpers cannot mutate the
// before-shape they are handed. Without this the down leg would compare the after-shape
// against itself and pass whatever the down did.
func copyShape000039(s tableShape) tableShape {
	out := tableShape{
		Columns:     append([]columnShape(nil), s.Columns...),
		Indexes:     append([]indexShape(nil), s.Indexes...),
		ForeignKeys: append([]foreignKeyShape(nil), s.ForeignKeys...),
	}
	for i := range out.Indexes {
		out.Indexes[i].Columns = append([]string(nil), s.Indexes[i].Columns...)
	}
	return out
}

func assertShape000039(t *testing.T, h *isolatedDB, phase string, codesWant, rtWant tableShape) {
	t.Helper()
	assert.Equalf(t, codesWant, dumpTable(t, h, "codes"),
		"[%s] codes must differ from the previous version by exactly the intended edit on %s", phase, dbType())
	assert.Equalf(t, rtWant, dumpTable(t, h, "refresh_tokens"),
		"[%s] refresh_tokens must differ from the previous version by exactly the intended edit on %s", phase, dbType())
}

// assertFinalShape000039 states goals 3 and 6 in absolute terms rather than as a
// difference, on all four engines. It is what gives the empty edit set on SQL Server a
// meaning: that engine is already here, and the other three arrive.
func assertFinalShape000039(t *testing.T, phase string, codes, rt tableShape) {
	t.Helper()

	assert.Truef(t, codes.column(t, "code_challenge").Nullable,
		"[%s] codes.code_challenge must be nullable on %s (goal 3)", phase, dbType())
	assert.Truef(t, codes.column(t, "code_challenge_method").Nullable,
		"[%s] codes.code_challenge_method must be nullable on %s (goal 3)", phase, dbType())

	assert.Equalf(t, "NO ACTION", rt.foreignKey(t, "user_id").OnDelete,
		"[%s] refresh_tokens.user_id must be NO ACTION on %s (goal 6)", phase, dbType())
	assert.Equalf(t, "NO ACTION", rt.foreignKey(t, "client_id").OnDelete,
		"[%s] refresh_tokens.client_id must be NO ACTION on %s (goal 6)", phase, dbType())
	assert.Equalf(t, "CASCADE", rt.foreignKey(t, "code_id").OnDelete,
		"[%s] refresh_tokens.code_id keeps its cascade on %s: it is the action all four engines already agree on",
		phase, dbType())

	// The index 000036 added, checked here as well as in its own test, because the
	// SQLite rebuild recreates all five by hand and dropping this one from that list
	// would undo the previous migration in the same change without failing anything else.
	clientIdx := rt.index("idx_refresh_tokens_client_id")
	require.Truef(t, clientIdx.Exists,
		"[%s] idx_refresh_tokens_client_id must survive the rebuild on %s", phase, dbType())
	assert.Equalf(t, []string{"client_id"}, clientIdx.Columns,
		"[%s] idx_refresh_tokens_client_id must still cover exactly client_id", phase)
}

// TestMigration000039_RowValuesSurviveTheRebuild covers what a shape dump cannot see. The
// SQLite rebuild copies both tables through hand-written INSERT ... SELECT column lists,
// and two columns of the same type swapped between them produces an identical shape and
// corrupted data. Variant E of the probe proved the ROWS survive; this proves their
// COLUMNS do.
//
// Whole-struct equality against a baseline read back at the predecessor, rather than
// field-by-field, so a column added to either model later is covered without anyone
// remembering to extend this.
//
//	--run TestMigration000039_RowValuesSurviveTheRebuild
func TestMigration000039_RowValuesSurviveTheRebuild(t *testing.T) {
	h := newIsolatedDB(t)

	pred := predecessor000039()
	require.NoErrorf(t, h.Migrator.Migrate(pred), "migrate to %06d", pred)

	client := seedClient000039(t, h)
	user := seedUser000039(t, h)
	code := seedCode000039(t, h, client, user, sql.NullString{String: "challenge-value", Valid: true})

	// The two shapes a refresh token comes in, which are also the two variant E used: one
	// issued through the authorization code flow, carrying a CodeId and no user or client,
	// and one ROPC-shaped, carrying a UserId and ClientId and no code.
	authCodeToken := seedRefreshToken000039(t, h, models.RefreshToken{
		CodeId: sql.NullInt64{Int64: code.Id, Valid: true},
	})
	ropcToken := seedRefreshToken000039(t, h, models.RefreshToken{
		UserId:   sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId: sql.NullInt64{Int64: client.Id, Valid: true},
	})

	baselineCode := readCode000039(t, h, code.Id)
	baselineAuth := readRefreshToken000039(t, h, authCodeToken.Id)
	baselineRopc := readRefreshToken000039(t, h, ropcToken.Id)

	assertRows000039 := func(phase string) {
		t.Helper()
		assert.Equalf(t, baselineCode, readCode000039(t, h, code.Id),
			"[%s] every codes column must still hold its own value on %s", phase, dbType())
		assert.Equalf(t, baselineAuth, readRefreshToken000039(t, h, authCodeToken.Id),
			"[%s] every refresh_tokens column must still hold its own value (auth code shape) on %s", phase, dbType())
		assert.Equalf(t, baselineRopc, readRefreshToken000039(t, h, ropcToken.Id),
			"[%s] every refresh_tokens column must still hold its own value (ROPC shape) on %s", phase, dbType())
	}

	if !hasMigration000039() {
		// SQL Server rebuilds nothing, so there is no round trip to run. The baseline
		// read above is still worth keeping: it is the same seeding path the other three
		// engines use, so a model or driver problem shows up on all four.
		assertRows000039("at 000038, no migration to apply")
		return
	}

	require.NoError(t, h.Migrator.Migrate(39), "apply 000039")
	assertRows000039("after apply")

	require.NoErrorf(t, h.Migrator.Migrate(pred), "roll back to %06d", pred)
	assertRows000039("after down")

	require.NoError(t, h.Migrator.Migrate(39), "re-apply 000039")
	assertRows000039("after down/up round trip")
}

// TestMigration000039_ChallengelessCodeIsStorable is the probe's failing insert turned
// into a test, at seam 3. It is goal 3 stated at the boundary a caller actually crosses:
// CodeIssuer.CreateAuthCode leaves both NullStrings at Valid:false when the authorization
// request carried no challenge, and on SQLite that insert has been failing with a 500 at
// /auth/issue for every confidential client configured for PKCE-optional.
//
//	--run TestMigration000039_ChallengelessCodeIsStorable
func TestMigration000039_ChallengelessCodeIsStorable(t *testing.T) {
	h := newIsolatedDB(t)

	pred := predecessor000039()
	require.NoErrorf(t, h.Migrator.Migrate(pred), "migrate to %06d", pred)

	client := seedClient000039(t, h)
	user := seedUser000039(t, h)

	err := createChallengelessCode000039(t, h, client, user, nil)
	if isSQLite000039() {
		require.Errorf(t, err, "at %06d SQLite still holds codes.code_challenge NOT NULL: that failure is the defect", pred)
	} else {
		require.NoErrorf(t, err, "the other three engines have accepted a NULL challenge since their own 000007 (%s)", dbType())
	}

	if !hasMigration000039() {
		return // SQL Server is already at the final state, asserted above
	}

	require.NoError(t, h.Migrator.Migrate(39), "apply 000039")

	var applied models.Code
	require.NoErrorf(t, createChallengelessCode000039(t, h, client, user, &applied),
		"a challenge-less code must be storable on %s after 000039 (goal 3)", dbType())
	stored := readCode000039(t, h, applied.Id)
	assert.False(t, stored.CodeChallenge.Valid, "the stored challenge must be NULL, not an empty string")
	assert.False(t, stored.CodeChallengeMethod.Valid, "the stored method must be NULL, not an empty string")

	require.NoErrorf(t, h.Migrator.Migrate(pred), "roll back to %06d", pred)

	if isSQLite000039() {
		// The down's UPDATE, doing its job: the row written while 000039 was applied
		// survives the rollback as '' rather than blocking it. Lossless for every reader,
		// since all three tests in ValidateTokenRequest's downgrade mitigation treat ''
		// and NULL alike.
		afterDown := readCode000039(t, h, applied.Id)
		assert.True(t, afterDown.CodeChallenge.Valid, "the down converts NULL to '' rather than losing the row")
		assert.Equal(t, "", afterDown.CodeChallenge.String, "the down writes an empty string")
		assert.True(t, afterDown.CodeChallengeMethod.Valid, "the down converts the method column too")
		assert.Equal(t, "", afterDown.CodeChallengeMethod.String, "the down writes an empty string")

		require.Error(t, createChallengelessCode000039(t, h, client, user, nil),
			"after the down SQLite must refuse a NULL challenge again: the constraint is back")
	} else {
		require.NoError(t, createChallengelessCode000039(t, h, client, user, nil),
			"the down does not touch nullability on %s, which was never the divergence there", dbType())
	}

	require.NoError(t, h.Migrator.Migrate(39), "re-apply 000039")
	require.NoErrorf(t, createChallengelessCode000039(t, h, client, user, nil),
		"a challenge-less code must be storable again after the round trip on %s", dbType())
}

// TestMigration000039_RopcTokenBlocksUserDelete is NO ACTION in effect rather than in the
// catalog, at seam 4. A shape dump reads what the catalog says; this reads what the engine
// does, which is the assertion the whole change is actually making.
//
// It also states the property that makes levelling down unobservable: DeleteUser clears
// the user's refresh tokens first, so the Go path still succeeds where a raw DELETE is
// now refused. That is why SQL Server has run this way since 000011 with nobody noticing.
//
//	--run TestMigration000039_RopcTokenBlocksUserDelete
func TestMigration000039_RopcTokenBlocksUserDelete(t *testing.T) {
	h := newIsolatedDB(t)

	pred := predecessor000039()
	require.NoErrorf(t, h.Migrator.Migrate(pred), "migrate to %06d", pred)

	client := seedClient000039(t, h)

	if hasMigration000039() {
		// At the predecessor the cascade is still in force on these three, so a raw
		// DELETE takes the token with it. Asserting the OLD behaviour is what makes the
		// assertion after the apply mean the migration did something.
		doomed := seedUser000039(t, h)
		token := seedRefreshToken000039(t, h, models.RefreshToken{
			UserId:   sql.NullInt64{Int64: doomed.Id, Valid: true},
			ClientId: sql.NullInt64{Int64: client.Id, Valid: true},
		})
		_, err := h.SQL.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %d", doomed.Id))
		require.NoErrorf(t, err, "at %06d the cascade lets a raw user delete through on %s", pred, dbType())
		assert.Zerof(t, countRefreshTokens000039(t, h, token.Id),
			"at %06d the cascade removes the token with its user on %s", pred, dbType())

		require.NoError(t, h.Migrator.Migrate(39), "apply 000039")
	}

	user := seedUser000039(t, h)
	token := seedRefreshToken000039(t, h, models.RefreshToken{
		UserId:   sql.NullInt64{Int64: user.Id, Valid: true},
		ClientId: sql.NullInt64{Int64: client.Id, Valid: true},
	})

	_, err := h.SQL.Exec(fmt.Sprintf("DELETE FROM users WHERE id = %d", user.Id))
	require.Errorf(t, err,
		"a raw user delete must be REFUSED on %s once refresh_tokens.user_id is NO ACTION (goal 6)", dbType())
	assert.Equalf(t, 1, countRefreshTokens000039(t, h, token.Id),
		"the refused delete must leave the token in place on %s", dbType())

	// And the invariant that makes all of this unobservable: DeleteUser clears the
	// user's refresh tokens inside the same transaction, so the supported path still
	// works. cascade_delete_test.go asserts the same thing across every dependent table.
	require.NoErrorf(t, h.DB.DeleteUser(nil, user.Id),
		"DeleteUser clears refresh tokens first, so it must still succeed on %s", dbType())
	assert.Zerof(t, countRefreshTokens000039(t, h, token.Id),
		"DeleteUser must have removed the token on %s", dbType())
}

// --- seeding -------------------------------------------------------------------------
//
// Through the repository's own CRUD rather than raw SQL, unlike the older migration tests
// here: the point of the row-value case is that every column arrives where the Go model
// says it should, and hand-written INSERTs per dialect would be asserting the test's own
// column list rather than the migration's.

func seedClient000039(t *testing.T, h *isolatedDB) *models.Client {
	t.Helper()
	client := &models.Client{
		ClientIdentifier:         "c-" + uuid.NewString()[:8],
		Description:              "seeded by migration 000039's test",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		DefaultAcrLevel:          "urn:goiabada:level1",
	}
	require.NoError(t, h.DB.CreateClient(nil, client), "seed client")
	return client
}

func seedUser000039(t *testing.T, h *isolatedDB) *models.User {
	t.Helper()
	user := &models.User{
		Subject:      uuid.New(),
		Enabled:      true,
		Email:        uuid.NewString() + "@example.com",
		Username:     "u-" + uuid.NewString()[:8],
		PasswordHash: "x",
	}
	require.NoError(t, h.DB.CreateUser(nil, user), "seed user")
	return user
}

// seedCode000039 gives every column its own recognisable value, so a copy that crossed two
// of them is visible in the comparison rather than hidden behind two equal defaults.
func seedCode000039(t *testing.T, h *isolatedDB, client *models.Client, user *models.User,
	challenge sql.NullString) *models.Code {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Microsecond)
	code := &models.Code{
		CodeHash:            "hash-" + uuid.NewString(),
		ClientId:            client.Id,
		UserId:              user.Id,
		CodeChallenge:       challenge,
		CodeChallengeMethod: sql.NullString{String: "S256", Valid: challenge.Valid},
		Scope:               "openid profile scope-value",
		State:               "state-value",
		Nonce:               "nonce-value",
		RedirectURI:         "https://example.com/redirect-uri-value",
		IpAddress:           "203.0.113.7",
		UserAgent:           "user-agent-value",
		ResponseMode:        "form_post",
		AuthenticatedAt:     now.Add(-3 * time.Minute),
		SessionIdentifier:   "session-identifier-value",
		AcrLevel:            "urn:goiabada:level2_mandatory",
		AuthMethods:         "pwd otp",
		Used:                true,
		Revoked:             true,
		AuthStateGeneration: 7,
	}
	require.NoError(t, h.DB.CreateCode(nil, code), "seed code")
	return code
}

// seedRefreshToken000039 fills every column that is not part of the caller's chosen shape,
// for the same reason seedCode000039 does.
func seedRefreshToken000039(t *testing.T, h *isolatedDB, shape models.RefreshToken) *models.RefreshToken {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Microsecond)
	token := shape
	token.RefreshTokenJti = "jti-" + uuid.NewString()
	token.PreviousRefreshTokenJti = "previous-jti-value"
	token.FirstRefreshTokenJti = "first-jti-value"
	token.SessionIdentifier = "session-identifier-value"
	token.RefreshTokenType = "Offline"
	token.Scope = "openid offline_access"
	token.IssuedAt = sql.NullTime{Time: now.Add(-2 * time.Minute), Valid: true}
	token.ExpiresAt = sql.NullTime{Time: now.Add(time.Hour), Valid: true}
	token.MaxLifetime = sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true}
	token.Revoked = true
	token.AuthStateGeneration = 11

	require.NoError(t, h.DB.CreateRefreshToken(nil, &token), "seed refresh token")
	return &token
}

// createChallengelessCode000039 builds exactly what CodeIssuer.CreateAuthCode builds when
// the authorization request carried no challenge: both NullStrings at their zero value,
// which is Valid:false. It returns the error rather than requiring success, because being
// refused is the assertion on one side of this migration.
func createChallengelessCode000039(t *testing.T, h *isolatedDB, client *models.Client,
	user *models.User, out *models.Code) error {
	t.Helper()

	code := &models.Code{
		CodeHash:            "hash-" + uuid.NewString(),
		ClientId:            client.Id,
		UserId:              user.Id,
		CodeChallenge:       sql.NullString{},
		CodeChallengeMethod: sql.NullString{},
		Scope:               "openid",
		RedirectURI:         "https://example.com/cb",
		ResponseMode:        "query",
		AuthenticatedAt:     time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier:   uuid.NewString(),
		AcrLevel:            "urn:goiabada:level1",
		AuthMethods:         "pwd",
	}
	err := h.DB.CreateCode(nil, code)
	if err == nil && out != nil {
		*out = *code
	}
	return err
}

func readCode000039(t *testing.T, h *isolatedDB, id int64) *models.Code {
	t.Helper()
	code, err := h.DB.GetCodeById(nil, id)
	require.NoErrorf(t, err, "read code %d back", id)
	require.NotNilf(t, code, "code %d is gone", id)
	return code
}

func readRefreshToken000039(t *testing.T, h *isolatedDB, id int64) *models.RefreshToken {
	t.Helper()
	token, err := h.DB.GetRefreshTokenById(nil, id)
	require.NoErrorf(t, err, "read refresh token %d back", id)
	require.NotNilf(t, token, "refresh token %d is gone", id)
	return token
}

func countRefreshTokens000039(t *testing.T, h *isolatedDB, id int64) int {
	t.Helper()
	var n int
	require.NoError(t,
		h.SQL.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM refresh_tokens WHERE id = %d", id)).Scan(&n),
		"count refresh tokens")
	return n
}
