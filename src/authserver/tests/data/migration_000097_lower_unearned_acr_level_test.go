package datatests

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two versions migration 000097 sits between. Literals: nothing in production code names this
// number.
const (
	beforeLowerUnearnedLevel000097 = 96
	lowerUnearnedLevel000097       = 97
)

// releaseNoteQuery000097 is the query the release notes give an operator, verbatim (#199
// decision 4), to list before upgrading the stored sign-ins the migration will lower.
const releaseNoteQuery000097 = `SELECT codes.id, users.email, clients.client_identifier, codes.created_at
FROM codes
JOIN users ON users.id = codes.user_id
JOIN clients ON clients.id = codes.client_id
WHERE codes.acr_level = 'urn:goiabada:level2_mandatory'
  AND codes.auth_methods NOT LIKE '%otp%'
  AND codes.auth_methods NOT LIKE '%recovery_code%';`

// signInShape000097 is one stored sign-in: the level and methods it is stored with, and the level
// it must hold once 000097 has run, written out rather than derived.
type signInShape000097 struct {
	level, methods string
	want           string
	// realNames is true when every method the row names is one some release has written: pwd, otp
	// or recovery_code. The release-note query tests for substrings, so it lists exactly the rows
	// the migration lowers only over those (#199 decision 4).
	realNames bool
	why       string
}

func signInShapes000097() []signInShape000097 {
	const (
		level1    = "urn:goiabada:level1"
		optional  = "urn:goiabada:level2_optional"
		mandatory = "urn:goiabada:level2_mandatory"
	)
	return []signInShape000097{
		{mandatory, "pwd", level1, true,
			"the highest level with a password alone: the unearned level this migration exists for"},
		{mandatory, "", level1, true,
			"the highest level with no methods recorded, which claims the most with the least behind it"},
		{mandatory, "pwd otp", mandatory, true, "a one-time code was entered"},
		{mandatory, "pwd recovery_code", mandatory, true, "a recovery code was entered"},
		{mandatory, "otp pwd", mandatory, true, "the methods in another order still name a one-time code"},
		{mandatory, "recovery_code pwd", mandatory, true, "the methods in another order still name a recovery code"},
		{mandatory, "otp", mandatory, true, "a one-time code as the only method still names a second factor"},
		{mandatory, "pwd xotp", level1, false, "xotp is a lookalike that contains otp but is not the name"},
		{mandatory, "pwd otpx", level1, false, "otpx starts with otp but is not the name"},
		{mandatory, "pwd recoveryXcode", level1, false,
			"recoveryXcode matches recovery_code only where _ is read as a wildcard"},
		{mandatory, "pwd recovery_codes", level1, false, "recovery_codes starts with recovery_code but is not the name"},
		{mandatory, "pwd OTP", level1, false, "the name is case-exact, so OTP names no second factor"},
		{mandatory, "pwd Recovery_Code", level1, false, "the name is case-exact, so Recovery_Code names no second factor"},
		{mandatory, "pwd o\u00adtp", level1, false,
			"a soft hyphen inside otp, which a linguistic collation ignores: the name is matched character for character"},
		{mandatory, "pwd recovery\u00ad_code", level1, false,
			"a soft hyphen inside recovery_code, which a linguistic collation ignores"},
		{level1, "pwd", level1, true, "the lowest level is never touched"},
		{optional, "pwd", optional, true, "level2_optional is never touched"},
		{optional, "pwd xotp", optional, false, "level2_optional is never touched, whatever its methods"},
	}
}

// TestMigration000097_LowerUnearnedAcrLevel exercises the migration that lowers to level1 every
// stored sign-in at level2_mandatory whose methods name neither otp nor recovery_code (#199
// decisions 2 and 3), against a REAL engine of the configured dialect: the methods are matched as
// whole, case-exact names, which each engine is asked to do in its own SQL.
//
// The properties:
//
//  1. Each shape holds the level its table entry gives, once 000097 has run, and every other
//     column of every row is as it was.
//  2. The release-note query, run before migrating, lists exactly the rows the migration then
//     lowers among those naming only methods some release has written.
//  3. The down migration leaves every row as the up left it, and 000097 applies again after it,
//     changing nothing more.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000097_LowerUnearnedAcrLevel
func TestMigration000097_LowerUnearnedAcrLevel(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newIsolatedDB(t)

	// Seeded through the ORM at head, then carried down to 000096, on 000062's pattern: the ORM
	// writes every column the record carries, so it can only write at head.
	if err := h.Migrator.Up(ctx); err != nil && !errors.Is(err, migrator.ErrNoChange) {
		require.NoError(t, err, "migrate to head before seeding through the ORM")
	}
	user := &record.User{Subject: fake.UUID(), Email: fake.Email(), Enabled: true}
	require.NoError(t, h.DB.CreateUser(ctx, nil, user))
	client := &record.Client{ClientIdentifier: "m97_" + fake.LetterN(6), Description: "Migration 000097 test client"}
	require.NoError(t, h.DB.CreateClient(ctx, nil, client))

	shapes := signInShapes000097()
	ids := make([]int64, len(shapes))
	for i, s := range shapes {
		ids[i] = createSignIn000097(t, h, client.Id, user.Id, s.level, s.methods)
	}

	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeLowerUnearnedLevel000097), "roll back to 000096 on %s", dbType())

	before := make([]map[string]string, len(shapes))
	for i := range shapes {
		before[i] = codeRow000097(t, h, ids[i])
		require.Equalf(t, shapes[i].level, before[i]["acr_level"], "seeded level of %q", shapes[i].methods)
		require.Equalf(t, shapes[i].methods, before[i]["auth_methods"], "seeded methods of %q", shapes[i].methods)
	}

	// 2, first half: what the release-note query lists before the upgrade.
	listed := releaseNoteQueryIds000097(t, h)

	require.NoErrorf(t, h.Migrator.Migrate(ctx, lowerUnearnedLevel000097), "apply 000097 on %s", dbType())

	// 1.
	after := make([]map[string]string, len(shapes))
	for i, s := range shapes {
		after[i] = codeRow000097(t, h, ids[i])
		assert.Equalf(t, s.want, after[i]["acr_level"],
			"1. on %s a sign-in at %s with methods %q must hold %s: %s", dbType(), s.level, s.methods, s.want, s.why)
		for column, value := range before[i] {
			if column == "acr_level" {
				continue
			}
			assert.Equalf(t, value, after[i][column],
				"1. on %s 000097 changes only the level: codes.%s of the sign-in with methods %q moved", dbType(), column, s.methods)
		}
	}

	// 2, second half: among the rows naming only real methods, the query listed exactly the ones
	// the migration lowered.
	for i, s := range shapes {
		if !s.realNames {
			continue
		}
		lowered := before[i]["acr_level"] != after[i]["acr_level"]
		assert.Equalf(t, lowered, slices.Contains(listed, ids[i]),
			"2. on %s the release-note query must list the sign-in at %s with methods %q exactly when 000097 lowers it (lowered: %v)",
			dbType(), s.level, s.methods, lowered)
	}

	// 3.
	require.NoErrorf(t, h.Migrator.Migrate(ctx, beforeLowerUnearnedLevel000097), "roll back 000097 on %s", dbType())
	for i, s := range shapes {
		assert.Equalf(t, after[i], codeRow000097(t, h, ids[i]),
			"3. on %s the down migration is a no-op: the sign-in with methods %q stays as the up left it", dbType(), s.methods)
	}
	require.NoErrorf(t, h.Migrator.Migrate(ctx, lowerUnearnedLevel000097), "re-apply 000097 on %s", dbType())
	for i, s := range shapes {
		assert.Equalf(t, after[i], codeRow000097(t, h, ids[i]),
			"3. on %s the re-applied up changes nothing more on the sign-in with methods %q", dbType(), s.methods)
	}
}

// createSignIn000097 stores one sign-in of client and user at level with methods, and returns its
// id.
func createSignIn000097(t *testing.T, h *isolatedDB, clientId, userId int64, level, methods string) int64 {
	t.Helper()
	random := fake.LetterN(8)
	code := &record.Code{
		ClientId:          clientId,
		UserId:            userId,
		Code:              "m97code_" + random,
		CodeHash:          "m97hash_" + random,
		RedirectURI:       "https://example.com/callback",
		Scope:             "openid offline_access",
		State:             "m97state_" + random,
		Nonce:             "m97nonce_" + random,
		IpAddress:         "192.0.2.1",
		UserAgent:         "migration 000097 test",
		ResponseMode:      "query",
		AuthenticatedAt:   time.Now().UTC().Truncate(time.Second),
		SessionIdentifier: "m97session_" + random,
		AcrLevel:          record.AcrLevel(level),
		AuthMethods:       methods,
		Used:              true,
	}
	require.NoErrorf(t, h.DB.CreateCode(context.Background(), nil, code), "store the sign-in at %s with methods %q", level, methods)
	return code.Id
}

// codeRow000097 reads every column of one codes row in SQL, as text, so a column the migration
// should not touch is compared whatever it is.
func codeRow000097(t *testing.T, h *isolatedDB, id int64) map[string]string {
	t.Helper()
	rows, err := h.SQL.Query(fmt.Sprintf("SELECT * FROM codes WHERE id = %d", id))
	require.NoErrorf(t, err, "read codes.id=%d on %s", id, dbType())
	defer func() { _ = rows.Close() }()

	columns, err := rows.Columns()
	require.NoError(t, err)
	require.Truef(t, rows.Next(), "codes.id=%d is gone on %s; this migration deletes nothing", id, dbType())
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	require.NoError(t, rows.Scan(pointers...))
	require.NoError(t, rows.Err())

	row := make(map[string]string, len(columns))
	for i, column := range columns {
		switch v := values[i].(type) {
		case []byte:
			row[column] = string(v)
		case nil:
			row[column] = "<NULL>"
		default:
			row[column] = fmt.Sprint(v)
		}
	}
	return row
}

// releaseNoteQueryIds000097 runs the release notes' query and returns the codes ids it lists.
func releaseNoteQueryIds000097(t *testing.T, h *isolatedDB) []int64 {
	t.Helper()
	rows, err := h.SQL.Query(releaseNoteQuery000097)
	require.NoErrorf(t, err, "run the release-note query on %s", dbType())
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var (
			id                      int64
			email, clientIdentifier string
			createdAt               any
		)
		require.NoError(t, rows.Scan(&id, &email, &clientIdentifier, &createdAt))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	return ids
}
