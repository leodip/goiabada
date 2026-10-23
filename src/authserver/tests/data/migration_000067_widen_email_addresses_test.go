package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// column000067 is one of the four columns 000067 widens.
type column000067 struct{ Table, Column string }

func (c column000067) String() string { return c.Table + "." + c.Column }

// columns000067 are the four columns 000067 widens, in the order its up and down files alter them.
var columns000067 = []column000067{
	{"users", "email"},
	{"pre_registrations", "email"},
	{"settings", "smtp_from_email"},
	{"settings", "smtp_username"},
}

// tables000067 are the three tables 000067 alters, in the order its files alter them.
var tables000067 = []string{"users", "pre_registrations", "settings"}

// skipWithout000067 skips on SQLite, which stores all four columns as TEXT and has no 000067.
func skipWithout000067(t *testing.T) {
	t.Helper()
	if dbType() == data.SQLite {
		t.Skip("sqlite stores these columns as TEXT and has no 000067")
	}
}

// emailOfLength254 is an address of exactly 254 characters, the longest RFC 5321 section
// 4.5.3.1.3 lets a path carry (#632): a 64-character local part, the most section 4.5.3.1.1
// allows, and a 189-character domain of labels no longer than 63. The local part is drawn, so two
// calls give two addresses and the unique index on users.email admits both.
func emailOfLength254() string {
	local := strings.ToLower(fake.LetterN(64))
	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 57) + ".com"
	return local + "@" + domain
}

// dumpTables000067 reads the three tables 000067 alters.
func dumpTables000067(t *testing.T, h *isolatedDB) map[string]tableShape {
	t.Helper()
	shapes := map[string]tableShape{}
	for _, table := range tables000067 {
		shapes[table] = dumpTable(t, h, table)
	}
	return shapes
}

// widened000067 is what the tables must read once 000067 has run: the shapes before it with the
// four columns' types replaced and nothing else touched.
func widened000067(t *testing.T, before map[string]tableShape) map[string]tableShape {
	t.Helper()
	want := map[string]tableShape{}
	for table, shape := range before {
		shape.Columns = slices.Clone(shape.Columns)
		for i := range shape.Columns {
			if slices.Contains(columns000067, column000067{table, shape.Columns[i].Name}) {
				shape.Columns[i].Type = varchar000052(t, 254)
			}
		}
		want[table] = shape
	}
	return want
}

// TestEmailAddressColumns_StoreTheLongestAddress holds each of the four columns an email address is
// stored in to taking the longest address SMTP can carry, 254 characters (#632), on every engine:
// on the three that size the columns because 000067 widened them, and on SQLite because TEXT has
// no width. Through the data layer's own writes and reads, on the shared database, since the
// column a value lands in is what is under test and not any one migration.
func TestEmailAddressColumns_StoreTheLongestAddress(t *testing.T) {
	ctx := context.Background()

	userEmail, preRegistrationEmail := emailOfLength254(), emailOfLength254()
	fromEmail, smtpUsername := emailOfLength254(), emailOfLength254()
	for _, address := range []string{userEmail, preRegistrationEmail, fromEmail, smtpUsername} {
		require.Len(t, address, 254, "the fixture must be the 254 characters the columns are widened to")
	}

	user := &record.User{Subject: fake.UUID(), Username: fake.Username(), Email: userEmail}
	require.NoError(t, database.CreateUser(ctx, nil, user), "create a user with a 254-character address")
	storedUser, err := database.GetUserById(ctx, nil, user.Id)
	require.NoError(t, err)
	assert.Equal(t, userEmail, storedUser.Email, "users.email")

	preRegistration := &record.PreRegistration{
		Email:                     preRegistrationEmail,
		VerificationCodeEncrypted: []byte(fake.UUID()),
		VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		VerificationCodeHash:      codeHashOf(t, fake.UUID()),
	}
	require.NoError(t, database.CreatePreRegistration(ctx, nil, preRegistration),
		"create a pre-registration with a 254-character address")
	storedPreRegistration, err := database.GetPreRegistrationById(ctx, nil, preRegistration.Id)
	require.NoError(t, err)
	assert.Equal(t, preRegistrationEmail, storedPreRegistration.Email, "pre_registrations.email")

	settings := settingsRow000067()
	settings.SMTPFromEmail = fromEmail
	settings.SMTPUsername = smtpUsername
	require.NoError(t, database.CreateSettings(ctx, nil, settings),
		"create a settings row with a 254-character sender address and SMTP username")
	storedSettings, err := database.GetSettingsById(ctx, nil, settings.Id)
	require.NoError(t, err)
	assert.Equal(t, fromEmail, storedSettings.SMTPFromEmail, "settings.smtp_from_email")
	assert.Equal(t, smtpUsername, storedSettings.SMTPUsername, "settings.smtp_username")
}

// settingsRow000067 is a settings row the data layer accepts, its email values short.
func settingsRow000067() *record.Settings {
	return &record.Settings{
		AppName:                                 "Goiabada",
		Issuer:                                  "https://example.com",
		PasswordPolicy:                          record.PasswordPolicyMedium,
		TokenExpirationInSeconds:                3600,
		RefreshTokenOfflineIdleTimeoutInSeconds: 86400,
		RefreshTokenOfflineMaxLifetimeInSeconds: 604800,
		UserSessionIdleTimeoutInSeconds:         1800,
		UserSessionMaxLifetimeInSeconds:         43200,
		MaxUserSessionsPerUser:                  35,
		AESEncryptionKeyLegacy:                  []byte("testaes"),
		SMTPHost:                                "smtp.example.com",
		SMTPPort:                                587,
		SMTPUsername:                            "username",
		SMTPFromName:                            "Goiabada",
		SMTPFromEmail:                           "sender@example.com",
		SMTPEncryption:                          "starttls",
	}
}

// TestMigration000067_WidensTheFourColumnsAndNothingElse holds the migration to its claim (#632):
// users.email, pre_registrations.email, settings.smtp_from_email and settings.smtp_username go from
// 64 to 254 and nothing else about the three tables moves. ALTER COLUMN and MODIFY replace a
// column's whole definition, so a file that forgot to restate the collation pin or the column's
// NULL would widen it and quietly change another thing; comparing whole table shapes, indexes
// included, is what shows the restatement is complete, which the golden files cannot.
//
// It then runs the up file a second time over the widened columns, which is what an operator does
// after clearing a dirty version (MySQL's DDL is not transactional, so a part-applied file is a
// real state), and steps down and up again, the down restoring the 000066 shape exactly: on SQL
// Server that includes the two indexes it takes off around the narrowing.
//
// Skipped on SQLite, which has no 000067.
func TestMigration000067_WidensTheFourColumnsAndNothingElse(t *testing.T) {
	skipWithout000067(t)
	ctx := context.Background()
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Migrate(ctx, 66), "migrate to 66")

	before := dumpTables000067(t, h)
	for _, c := range columns000067 {
		require.Equalf(t, varchar000052(t, 64), before[c.Table].column(t, c.Column).Type,
			"%s is 64 wide at 000066, so the comparison below observes a widening", c)
	}

	require.NoError(t, h.Migrator.Migrate(ctx, 67), "migrate to 67")
	widened := dumpTables000067(t, h)
	want := widened000067(t, before)
	for _, table := range tables000067 {
		assert.Equalf(t, want[table], widened[table],
			"%s must differ from its 000066 shape in the widths of the columns 000067 widens and nowhere else, "+
				"the collation, nullability, defaults, indexes and foreign keys included", table)
	}

	// Running the file again over columns already 254 wide completes without change.
	require.NoError(t, h.Migrator.Force(ctx, 66), "clear the version, as an operator does after a dirty run")
	require.NoError(t, h.Migrator.Migrate(ctx, 67), "the up file must run again over the widened columns")
	for _, table := range tables000067 {
		assert.Equalf(t, widened[table], dumpTable(t, h, table), "a second run of the up file must change nothing in %s", table)
	}

	// Down restores the 000066 shape exactly, the collation pin and the indexes included, and up
	// widens again.
	require.NoError(t, h.Migrator.Migrate(ctx, 66), "step down to 66")
	for _, table := range tables000067 {
		assert.Equalf(t, before[table], dumpTable(t, h, table), "the down file must restore %s exactly", table)
	}
	require.NoError(t, h.Migrator.Migrate(ctx, 67), "step up to 67 again")
	for _, table := range tables000067 {
		assert.Equalf(t, widened[table], dumpTable(t, h, table), "%s after down and up again", table)
	}
}

// rows000067 are the ids of the one users, pre_registrations and settings row the down case
// writes its values into.
type rows000067 map[string]int64

// seedRows000067 creates one row in each table 000067 alters, through the data layer, which the
// isolated database at 000067 matches: it is the head on every engine that carries 000067.
func seedRows000067(t *testing.T, h *isolatedDB) rows000067 {
	t.Helper()
	ctx := context.Background()

	user := &record.User{Subject: fake.UUID(), Username: fake.Username(), Email: fake.Email()}
	require.NoError(t, h.DB.CreateUser(ctx, nil, user), "seed a user")

	preRegistration := &record.PreRegistration{
		Email:                     fake.Email(),
		VerificationCodeEncrypted: []byte(fake.UUID()),
		VerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		VerificationCodeHash:      codeHashOf(t, fake.UUID()),
	}
	require.NoError(t, h.DB.CreatePreRegistration(ctx, nil, preRegistration), "seed a pre-registration")

	settings := settingsRow000067()
	require.NoError(t, h.DB.CreateSettings(ctx, nil, settings), "seed a settings row")

	return rows000067{"users": user.Id, "pre_registrations": preRegistration.Id, "settings": settings.Id}
}

// write sets c to value on its seeded row, with literal SQL, since the value is what the down
// file is about and no data layer write should shape it.
func (r rows000067) write(t *testing.T, h *isolatedDB, c column000067, value string) {
	t.Helper()
	mustExec(t, h.SQL, fmt.Sprintf("UPDATE %s SET %s = '%s' WHERE id = %d", c.Table, c.Column, value, r[c.Table]))
}

// read answers c's value on its seeded row. The phase is written into the statement as a comment
// so each phase sends a text of its own: pgx prepares a statement once per text and connection,
// and a prepared SELECT whose column a migration has since narrowed answers "cached plan must
// not change result type" instead of the value.
func (r rows000067) read(t *testing.T, h *isolatedDB, c column000067, phase string) string {
	t.Helper()
	var value string
	q := fmt.Sprintf("SELECT %s FROM %s WHERE id = %d /* %s */", c.Column, c.Table, r[c.Table], phase)
	require.NoErrorf(t, h.SQL.QueryRow(q).Scan(&value), "read %s %s", c, phase)
	return value
}

// refusal000067 is how each engine says it will not narrow c over a value longer than 64,
// lowercased: MySQL 8's error 1265 under its default strict sql_mode, PostgreSQL's SQLSTATE 22001,
// which names the type rather than the column, and SQL Server's Msg 2628. Asserted because the down
// has to fail on the value written for it; any other failure would prove nothing about the value.
func refusal000067(c column000067) string {
	switch dbType() {
	case data.MySQL:
		return fmt.Sprintf("data truncated for column '%s'", c.Column)
	case data.Postgres:
		return "value too long for type character varying(64)"
	default: // SQL Server
		return fmt.Sprintf(".dbo.%s', column '%s'", c.Table, c.Column)
	}
}

// TestMigration000067_DownRefusesAnAddressThatNoLongerFits holds the down file to narrowing the
// four columns back to 64 only when every stored value fits, and to failing otherwise rather than
// cutting the value (#632). An address between 65 and 254 characters is the one a person was let
// in with after 000067, so cutting it would leave an account under an address that is not theirs.
//
// Each column in turn holds a 65-character value, the shortest that no longer fits, and the down
// must fail with that value stored whole and its column still 254 wide. On PostgreSQL and SQL
// Server the file is one transaction, so the refusal must leave all three tables as they were:
// on SQL Server that is what puts back an index the file had already taken off, and refusing on
// the LAST column is what shows it, since everything else in the file ran before it. MySQL's DDL
// is not transactional, so there the earlier columns are left narrowed, the version dirty, and
// the operator's own step, fixing the value, clearing the version and running the file again,
// completes it, which this case takes too. Once every column holds exactly 64 characters, the down
// completes and keeps each whole.
//
// Skipped on SQLite, which has no 000067.
func TestMigration000067_DownRefusesAnAddressThatNoLongerFits(t *testing.T) {
	skipWithout000067(t)
	ctx := context.Background()
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Migrate(ctx, 67), "migrate to 67")
	rows := seedRows000067(t, h)
	widened := dumpTables000067(t, h)

	tooLong := strings.Repeat("x", 65)
	fits := strings.Repeat("y", 64)

	for _, c := range columns000067 {
		rows.write(t, h, c, tooLong)

		err := h.Migrator.Migrate(ctx, 66)
		require.Errorf(t, err, "the down must refuse while %s holds 65 characters", c)
		assert.Containsf(t, strings.ToLower(err.Error()), refusal000067(c),
			"the refusal must be the engine's refusal to cut %s's value: %v", c, err)

		assert.Equalf(t, tooLong, rows.read(t, h, c, "after the refused down"), "the refused down must leave %s's value whole, not cut to 64", c)
		assert.Equalf(t, varchar000052(t, 254), dumpTable(t, h, c.Table).column(t, c.Column).Type,
			"%s must still be 254 wide after the down refused it", c)
		if dbType() != data.MySQL {
			for _, table := range tables000067 {
				assert.Equalf(t, widened[table], dumpTable(t, h, table),
					"the refused down must leave %s exactly as it found it, refused on %s", table, c)
			}
		}

		// The operator's recovery: the value made to fit, the dirty version cleared, the up run
		// again over whatever the refusal left, so the next column starts from 000067 whole.
		rows.write(t, h, c, fits)
		require.NoError(t, h.Migrator.Force(ctx, 66), "clear the dirty version the refusal left")
		require.NoError(t, h.Migrator.Migrate(ctx, 67), "run the up file again after the refusal on %s", c)
		for _, table := range tables000067 {
			require.Equalf(t, widened[table], dumpTable(t, h, table), "%s widened again after the refusal on %s", table, c)
		}
	}

	require.NoError(t, h.Migrator.Migrate(ctx, 66), "the down must complete once every value fits in 64")
	for _, c := range columns000067 {
		assert.Equalf(t, varchar000052(t, 64), dumpTable(t, h, c.Table).column(t, c.Column).Type, "%s after the down", c)
		assert.Equalf(t, fits, rows.read(t, h, c, "after the down"), "the down must keep %s's 64 characters whole", c)
	}
}

// TestMigration000067_UpRollsBackALateFailure holds SQL Server's 000067 to being atomic, for the
// reason 000049's case gives: the runner hands the file to one Exec and opens no transaction, so
// each ALTER COLUMN would autocommit on its own, and a failure on the last would leave the first
// three widened and the version dirty. The file opens its own transaction under SET XACT_ABORT ON.
//
// The other engines skip: MySQL has no transactional DDL, and its file says so and is idempotent
// instead, which the first case shows, and PostgreSQL runs a file in one statement batch.
//
// On its own isolated database, as 000049's is, because its first attempt ends dirty.
func TestMigration000067_UpRollsBackALateFailure(t *testing.T) {
	if dbType() != data.MSSQL {
		t.Skipf("%s has no transactional 000067 up file to roll back", dbType())
	}
	ctx := context.Background()
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Migrate(ctx, 66), "migrate to 66")

	// The failure, injected as a dependency the migration knows nothing about: a schema-bound view
	// over settings.smtp_username, which SQL Server refuses to ALTER a column under (Msg 4922). On
	// the LAST column the file alters, deliberately, so the refusal lands after users.email,
	// pre_registrations.email and settings.smtp_from_email have all been widened. A failure on the
	// first statement would pass against an unwrapped file too.
	const unmanagedView = "v_operators_own_000067"
	mustExec(t, h.SQL, "CREATE VIEW ["+unmanagedView+"] WITH SCHEMABINDING AS SELECT [smtp_username] FROM [dbo].[settings]")

	before := dumpTables000067(t, h)

	err := h.Migrator.Migrate(ctx, 67)
	require.Error(t, err, "an ALTER COLUMN under a schema-bound view must fail")
	// Msg 4922 names the column. Asserted because the failure has to be the one injected here;
	// any other error would prove the rollback of something else.
	assert.Containsf(t, strings.ToLower(err.Error()), "alter column smtp_username",
		"the failure must be the injected one, on the last column the file alters: %v", err)

	for _, table := range tables000067 {
		assert.Equalf(t, before[table], dumpTable(t, h, table),
			"the failed up must leave %s exactly as it found it, including a column it had already widened before the failure", table)
	}

	// And the recovery works: resolve the dependency, clear the dirty version, run it again.
	mustExec(t, h.SQL, "DROP VIEW ["+unmanagedView+"]")
	require.NoError(t, h.Migrator.Force(ctx, 66),
		"clear the dirty version the deliberate failure left, which is the operator's own step")
	require.NoError(t, h.Migrator.Migrate(ctx, 67),
		"the retry must reach 67; if it does not, the first attempt left something it cannot redo")

	want := widened000067(t, before)
	for _, table := range tables000067 {
		assert.Equalf(t, want[table], dumpTable(t, h, table), "%s after the retry", table)
	}
}
