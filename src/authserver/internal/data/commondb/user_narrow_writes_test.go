package commondb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The users' narrow writes, held on all four engines to the columns each writes and the condition
// it writes them on (#644).
//
// A narrow write exists for what it leaves alone: it writes its own few columns and no other, so a
// request holding a stale read of the user cannot write an authentication generation, an OTP claim
// or an enabled flag back, and most of them write only while the row still holds what the caller
// read. Both are in the statement's text and nowhere else, so this reads the text, with each
// placeholder rendered as the value it binds. The rendering is the same on every engine, so one
// expected statement holds all four versions to saying the same thing, and holds each version's
// placeholders to binding the arguments that belong where they stand: a misnumbered PostgreSQL or
// SQL Server placeholder, two same-typed arguments swapped, or a column written beyond the write's
// own shows here as a different statement.
//
// The data tier shows what the statements do to a real row on each engine. This shows, in seconds,
// what each engine is asked to do.

// narrowUserId is the user every narrow write here addresses.
const narrowUserId = 7

var (
	issuedAt       = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	issuedNotAfter = time.Date(2002, 2, 2, 0, 0, 0, 0, time.UTC)
	staleBefore    = time.Date(2003, 3, 3, 0, 0, 0, 0, time.UTC)

	anyPlaceholder = regexp.MustCompile(`\?|\$[0-9]+|@p[0-9]+`)
)

// narrowWrite is one call of a narrow write and the statements it must send, rendered.
type narrowWrite struct {
	name string
	// execs scripts each UPDATE's rows affected, in order; an UPDATE past the end changes one row.
	execs []*scriptedExec
	// rows scripts each read-back, in order.
	rows []*scriptedRows
	run  func(ctx context.Context, d *Database) (any, error)
	// answer is what run must answer: the method's bool or int64, or nil for one answering only an
	// error.
	answer     any
	statements []string
}

// inTx runs write inside a transaction, for the writes that refuse to run outside one.
func inTx(ctx context.Context, d *Database, write func(tx *sql.Tx) (any, error)) (any, error) {
	tx, err := d.BeginTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return write(tx)
}

func narrowWrites() []narrowWrite {
	limit := record.OtpConsecutiveFailureLimit
	return []narrowWrite{
		{
			name: "IncrementUserAuthStateGeneration",
			rows: []*scriptedRows{{cols: []string{"auth_state_generation"}, values: [][]driver.Value{{int64(12)}}}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return inTx(ctx, d, func(tx *sql.Tx) (any, error) {
					return d.IncrementUserAuthStateGeneration(ctx, tx, narrowUserId)
				})
			},
			answer: int64(12),
			statements: []string{
				"UPDATE users SET auth_state_generation = auth_state_generation + 1, updated_at = <now> WHERE id = 7",
				"SELECT auth_state_generation FROM users WHERE id = 7",
			},
		},
		{
			name: "IncrementUserOtpConfigGeneration",
			rows: []*scriptedRows{{cols: []string{"otp_config_generation"}, values: [][]driver.Value{{int64(13)}}}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return inTx(ctx, d, func(tx *sql.Tx) (any, error) {
					return d.IncrementUserOtpConfigGeneration(ctx, tx, narrowUserId)
				})
			},
			answer: int64(13),
			statements: []string{
				"UPDATE users SET otp_config_generation = otp_config_generation + 1, updated_at = <now> WHERE id = 7",
				"SELECT otp_config_generation FROM users WHERE id = 7",
			},
		},
		{
			name: "SetUserPasswordHash",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.SetUserPasswordHash(ctx, nil, narrowUserId, "new-hash")
			},
			statements: []string{
				"UPDATE users SET password_hash = 'new-hash', forgot_password_code_encrypted = NULL, " +
					"forgot_password_code_issued_at = NULL, forgot_password_code_hash = '', updated_at = <now> WHERE id = 7",
			},
		},
		{
			name: "SetUserProfile",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.SetUserProfile(ctx, nil, &record.User{
					Id: narrowUserId, Username: "u-name", GivenName: "g-name", MiddleName: "m-name",
					FamilyName: "f-name", Nickname: "n-name", Website: "w-site", Gender: "gen",
					BirthDate:           sql.NullTime{Time: issuedAt, Valid: true},
					ZoneInfoCountryName: "z-country", ZoneInfo: "z-info", Locale: "loc",
					// Columns of the other groups, which the write must leave alone.
					Enabled: true, PasswordHash: "untouched", Email: "untouched@example.com",
				})
			},
			statements: []string{
				"UPDATE users SET username = 'u-name', given_name = 'g-name', middle_name = 'm-name', " +
					"family_name = 'f-name', nickname = 'n-name', website = 'w-site', gender = 'gen', " +
					"birth_date = 2001-01-01T00:00:00Z, zone_info_country_name = 'z-country', zone_info = 'z-info', " +
					"locale = 'loc', updated_at = <now> WHERE id = 7",
			},
		},
		{
			name: "SetUserAddress",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.SetUserAddress(ctx, nil, &record.User{
					Id: narrowUserId, AddressLine1: "line-1", AddressLine2: "line-2", AddressLocality: "loc",
					AddressRegion: "reg", AddressPostalCode: "post", AddressCountry: "ctry",
					Enabled: true, Username: "untouched",
				})
			},
			statements: []string{
				"UPDATE users SET address_line1 = 'line-1', address_line2 = 'line-2', address_locality = 'loc', " +
					"address_region = 'reg', address_postal_code = 'post', address_country = 'ctry', " +
					"updated_at = <now> WHERE id = 7",
			},
		},
		{
			name: "SetUserPhone",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.SetUserPhone(ctx, nil, &record.User{
					Id: narrowUserId, PhoneNumberCountryUniqueId: "BRA_0", PhoneNumberCountryCallingCode: "+55",
					PhoneNumber: "555", PhoneNumberVerified: true,
					Enabled: true, EmailVerified: true,
				})
			},
			statements: []string{
				"UPDATE users SET phone_number_country_uniqueid = 'BRA_0', phone_number_country_callingcode = '+55', " +
					"phone_number = '555', phone_number_verified = true, updated_at = <now> WHERE id = 7",
			},
		},
		{
			name: "SetUserEmail",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.SetUserEmail(ctx, nil, &record.User{
					Id: narrowUserId, Email: "to@example.com", EmailVerified: true,
					Enabled: true, PhoneNumberVerified: true,
				})
			},
			// The three CASEs come before the email assignment: MySQL reads a single-table UPDATE's
			// assignments left to right.
			statements: []string{
				"UPDATE users SET " +
					"forgot_password_code_encrypted = CASE WHEN email = 'to@example.com' THEN forgot_password_code_encrypted ELSE NULL END, " +
					"forgot_password_code_issued_at = CASE WHEN email = 'to@example.com' THEN forgot_password_code_issued_at ELSE NULL END, " +
					"forgot_password_code_hash = CASE WHEN email = 'to@example.com' THEN forgot_password_code_hash ELSE '' END, " +
					"email = 'to@example.com', email_verified = true, email_verification_code_encrypted = NULL, " +
					"email_verification_code_issued_at = NULL, updated_at = <now> WHERE id = 7",
			},
		},
		{
			name: "TrySetUserEmail",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TrySetUserEmail(ctx, nil, narrowUserId, "from@example.com", true, "to@example.com")
			},
			answer: true,
			statements: []string{
				"UPDATE users SET email = 'to@example.com', email_verified = false, email_verification_code_encrypted = NULL, " +
					"forgot_password_code_encrypted = NULL, forgot_password_code_issued_at = NULL, forgot_password_code_hash = '', " +
					"updated_at = <now> WHERE id = 7 AND email = 'from@example.com' AND email_verified = true",
			},
		},
		{
			name: "TryStoreEmailVerificationCode",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryStoreEmailVerificationCode(ctx, nil, narrowUserId, "at@example.com",
					[]byte("cipher"), issuedAt, issuedNotAfter)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET email_verification_code_encrypted = bytes(cipher), " +
					"email_verification_code_issued_at = 2001-01-01T00:00:00Z, updated_at = <now> " +
					"WHERE id = 7 AND email = 'at@example.com' AND email_verified = false AND " +
					"(email_verification_code_issued_at IS NULL OR email_verification_code_issued_at <= 2002-02-02T00:00:00Z)",
			},
		},
		{
			name: "TryIssueEmailVerificationCode",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryIssueEmailVerificationCode(ctx, nil, narrowUserId, "at@example.com", []byte("cipher"), issuedAt)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET email_verified = false, email_verification_code_encrypted = bytes(cipher), " +
					"email_verification_code_issued_at = 2001-01-01T00:00:00Z, updated_at = <now> " +
					"WHERE id = 7 AND email = 'at@example.com'",
			},
		},
		{
			name: "TryVerifyUserEmail",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryVerifyUserEmail(ctx, nil, narrowUserId, "at@example.com", []byte("cipher"))
			},
			answer: true,
			statements: []string{
				"UPDATE users SET email_verified = true, email_verification_code_encrypted = NULL, updated_at = <now> " +
					"WHERE id = 7 AND email = 'at@example.com' AND email_verified = false AND " +
					"email_verification_code_encrypted = bytes(cipher)",
			},
		},
		{
			name: "TryConsumeForgotPasswordCode",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryConsumeForgotPasswordCode(ctx, nil, narrowUserId, "code-hash", "new-hash")
			},
			answer: true,
			statements: []string{
				"UPDATE users SET password_hash = 'new-hash', forgot_password_code_encrypted = NULL, " +
					"forgot_password_code_issued_at = NULL, forgot_password_code_hash = '', email_verified = true, " +
					"email_verification_code_encrypted = NULL, email_verification_code_issued_at = NULL, " +
					"updated_at = <now> WHERE id = 7 AND forgot_password_code_hash = 'code-hash' AND enabled = true",
			},
		},
		{
			name: "TryStoreForgotPasswordCode",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryStoreForgotPasswordCode(ctx, nil, narrowUserId, "at@example.com",
					[]byte("cipher"), "code-hash", issuedAt)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET forgot_password_code_encrypted = bytes(cipher), forgot_password_code_hash = 'code-hash', " +
					"forgot_password_code_issued_at = 2001-01-01T00:00:00Z, updated_at = <now> " +
					"WHERE id = 7 AND email = 'at@example.com' AND enabled = true AND email_verified = true",
			},
		},
		{
			name: "TrySetUserEnabled",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TrySetUserEnabled(ctx, nil, narrowUserId, true, false)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET enabled = false, updated_at = <now> WHERE id = 7 AND enabled = true",
			},
		},
		{
			name: "TryConsumeUserOTPStep",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryConsumeUserOTPStep(ctx, nil, narrowUserId, 5000)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET last_otp_step = 5000, updated_at = <now> WHERE id = 7 AND last_otp_step < 5000",
			},
		},
		{
			name: "TryConsumeEnrolledUserOTPStep",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryConsumeEnrolledUserOTPStep(ctx, nil, narrowUserId, 5000, 3)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET last_otp_step = 5000, updated_at = <now>, otp_consecutive_failures = 0 " +
					"WHERE id = 7 AND last_otp_step < 5000 AND otp_enabled = true AND otp_config_generation = 3 AND " +
					fmt.Sprintf("otp_consecutive_failures < %d", limit),
			},
		},
		{
			name: "ResetUserOTPStep",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.ResetUserOTPStep(ctx, nil, narrowUserId)
			},
			statements: []string{
				"UPDATE users SET last_otp_step = 0, updated_at = <now> WHERE id = 7",
			},
		},
		{
			name: "IncrementUserOtpConsecutiveFailures short of the limit",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.IncrementUserOtpConsecutiveFailures(ctx, nil, narrowUserId, 3)
			},
			// The count advanced, and did not reach the limit: this call disabled nothing.
			answer: false,
			statements: []string{
				"UPDATE users SET otp_consecutive_failures = otp_consecutive_failures + 1 " +
					"WHERE id = 7 AND otp_enabled = true AND otp_config_generation = 3 AND " +
					fmt.Sprintf("otp_consecutive_failures < %d", limit-1),
			},
		},
		{
			name:  "IncrementUserOtpConsecutiveFailures to the limit",
			execs: []*scriptedExec{{rowsAffected: 0}, {rowsAffected: 1}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.IncrementUserOtpConsecutiveFailures(ctx, nil, narrowUserId, 3)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET otp_consecutive_failures = otp_consecutive_failures + 1 " +
					"WHERE id = 7 AND otp_enabled = true AND otp_config_generation = 3 AND " +
					fmt.Sprintf("otp_consecutive_failures < %d", limit-1),
				fmt.Sprintf("UPDATE users SET otp_consecutive_failures = %d ", limit) +
					"WHERE id = 7 AND otp_enabled = true AND otp_config_generation = 3 AND " +
					fmt.Sprintf("otp_consecutive_failures = %d", limit-1),
			},
		},
		{
			name: "ClearUserOtpConsecutiveFailures",
			run: func(ctx context.Context, d *Database) (any, error) {
				return inTx(ctx, d, func(tx *sql.Tx) (any, error) {
					return nil, d.ClearUserOtpConsecutiveFailures(ctx, tx, narrowUserId)
				})
			},
			statements: []string{
				"UPDATE users SET otp_consecutive_failures = 0, updated_at = <now> WHERE id = 7",
			},
		},
		{
			name: "TryInstallPendingOTPEnrollment",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryInstallPendingOTPEnrollment(ctx, nil, narrowUserId, []byte("seed"), issuedAt, staleBefore)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET otp_enrollment_secret_encrypted = bytes(seed), " +
					"otp_enrollment_issued_at = 2001-01-01T00:00:00Z, updated_at = <now> " +
					"WHERE id = 7 AND otp_enabled = false AND (otp_enrollment_secret_encrypted IS NULL OR " +
					"otp_enrollment_issued_at IS NULL OR otp_enrollment_issued_at < 2003-03-03T00:00:00Z)",
			},
		},
		{
			name: "ClearPendingOTPEnrollment",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.ClearPendingOTPEnrollment(ctx, nil, narrowUserId)
			},
			statements: []string{
				"UPDATE users SET otp_enrollment_secret_encrypted = NULL, otp_enrollment_issued_at = NULL, " +
					"updated_at = <now> WHERE id = 7",
			},
		},
		{
			name: "TryEstablishUserOTP",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryEstablishUserOTP(ctx, nil, narrowUserId, 3, []byte("seed"))
			},
			answer: true,
			statements: []string{
				"UPDATE users SET otp_secret_encrypted = bytes(seed), otp_enabled = true, updated_at = <now> " +
					"WHERE id = 7 AND otp_enabled = false AND otp_config_generation = 3",
			},
		},
		{
			name: "TryRemoveUserOTP",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryRemoveUserOTP(ctx, nil, narrowUserId, 3)
			},
			answer: true,
			statements: []string{
				"UPDATE users SET otp_secret_encrypted = NULL, otp_enabled = false, updated_at = <now> " +
					"WHERE id = 7 AND otp_enabled = true AND otp_config_generation = 3",
			},
		},
	}
}

// renderStatement replaces each placeholder in query with the value it binds, holding the
// placeholders to the dialect's style and every argument to being bound.
func renderStatement(dialect data.Dialect, query string, args []driver.Value, started time.Time) (string, []string) {
	var problems []string
	used := make([]bool, len(args))
	reader := &placeholderReader{dialect: dialect}
	rendered := anyPlaceholder.ReplaceAllStringFunc(query, func(ph string) string {
		i, err := reader.read(ph)
		if err != nil {
			problems = append(problems, err.Error())
			return ph
		}
		if i >= len(args) {
			problems = append(problems, fmt.Sprintf("placeholder %s binds argument %d of %d", ph, i+1, len(args)))
			return ph
		}
		used[i] = true
		return renderValue(args[i], started)
	})
	for i, u := range used {
		if !u {
			problems = append(problems, fmt.Sprintf("argument %d, %v, is bound by no placeholder", i+1, args[i]))
		}
	}
	return rendered, problems
}

// renderValue is a bound value as the expected statements spell it. A time the write took from the
// clock is <now>, and the times the caller passes are fixed and far from it.
func renderValue(v driver.Value, started time.Time) string {
	switch v := v.(type) {
	case nil:
		return "<nil>"
	case int64:
		return strconv.FormatInt(v, 10)
	case bool:
		return strconv.FormatBool(v)
	case string:
		return "'" + v + "'"
	case []byte:
		return "bytes(" + string(v) + ")"
	case time.Time:
		if !v.Before(started) && v.Sub(started) < time.Minute {
			return "<now>"
		}
		return v.UTC().Format(time.RFC3339)
	default:
		return fmt.Sprintf("<%T %v>", v, v)
	}
}

func TestUserNarrowWrites_SendTheirStatementOnEveryEngine(t *testing.T) {
	for _, w := range narrowWrites() {
		for _, dialect := range allDialects {
			t.Run(w.name+"/"+string(dialect), func(t *testing.T) {
				script := &scriptedDriver{execs: w.execs, rows: w.rows}
				started := time.Now().UTC()

				answer, err := w.run(context.Background(), scriptedDBFor(t, script, dialect))
				require.NoError(t, err)
				assert.Equal(t, w.answer, answer)

				var got, problems []string
				var execs, queries int
				for _, query := range script.statements {
					var args []driver.Value
					if strings.HasPrefix(query, "SELECT") {
						require.Less(t, queries, len(script.queryArgs))
						args = script.queryArgs[queries]
						queries++
					} else {
						require.Less(t, execs, len(script.execArgs))
						args = script.execArgs[execs]
						execs++
					}
					rendered, found := renderStatement(dialect, query, args, started)
					got = append(got, rendered)
					problems = append(problems, found...)
				}
				assert.Empty(t, problems, "\n%s", strings.Join(problems, "\n"))
				assert.Equal(t, w.statements, got)
			})
		}
	}
}

// The renderer's own cases: without them the test above would pass on a renderer that had stopped
// reading the placeholders.

func TestUserNarrowWrites_TheRendererRefusesAnotherEnginesPlaceholder(t *testing.T) {
	_, problems := renderStatement(data.Postgres, "UPDATE users SET enabled = ? WHERE id = $2",
		[]driver.Value{true, int64(7)}, time.Now())
	assert.NotEmpty(t, problems)
}

func TestUserNarrowWrites_TheRendererRefusesAnArgumentBoundByNothing(t *testing.T) {
	_, problems := renderStatement(data.MSSQL, "UPDATE users SET enabled = @p1 WHERE id = @p1",
		[]driver.Value{true, int64(7)}, time.Now())
	assert.NotEmpty(t, problems)
}

func TestUserNarrowWrites_TheRendererBindsEachNumberedPlaceholderToItsArgument(t *testing.T) {
	rendered, problems := renderStatement(data.Postgres, "UPDATE users SET enabled = $2 WHERE id = $1",
		[]driver.Value{int64(7), true}, time.Now())
	assert.Empty(t, problems)
	assert.Equal(t, "UPDATE users SET enabled = true WHERE id = 7", rendered)
}
