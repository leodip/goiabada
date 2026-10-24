package commondb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The statements of the records the server keeps about itself, held on all four engines to what
// each asks of the engine: the settings row and its two conditional writes, signing keys, audit
// logs, pending registrations, the shared rate-limit counters, re-encryption, the email-case
// pre-flight and the empty-database check (#644).
//
// Most of these exist for their condition: a cleanup run is claimed only while the last one is old
// enough, a key changes state only from the state the caller read, a pending registration is
// replaced or deleted only while it holds the code the caller read, and a refund never takes a
// count below zero. Each is in the statement's text and nowhere else, so this reads the text with
// each placeholder rendered as the value it binds, one expected statement for all four engines, as
// the users' narrow writes are read. The columns of a read of whole records are left to the record
// mapping test.

const (
	serverRecordId = 9
	keyHash        = "key-1"
)

var (
	windowPrevious = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	windowCurrent  = time.Date(2002, 2, 2, 0, 0, 0, 0, time.UTC)
	windowExpires  = time.Date(2003, 3, 3, 0, 0, 0, 0, time.UTC)
)

// rateLimitRows is the key's rows as the engine answers the counters read, at these hits.
func rateLimitCounterRows(previousHits, currentHits int64) *scriptedRows {
	return &scriptedRows{
		cols: []string{"key_hash", "window_start", "hits"},
		values: [][]driver.Value{
			{keyHash, windowPrevious, previousHits},
			{keyHash, windowCurrent, currentHits},
		},
	}
}

// keyPairRow is one current signing key as the engine answers a read of whole records.
func keyPairRow() *scriptedRows {
	return &scriptedRows{
		cols: []string{"id", "created_at", "updated_at", "state", "key_identifier", "type", "algorithm",
			"private_key_pem", "public_key_pem", "public_key_asn1_der", "public_key_jwk"},
		values: [][]driver.Value{{int64(1), issuedAt, issuedAt, record.KeyStateCurrent.String(), "kid",
			"RSA", "RS256", []byte("private"), []byte("public"), []byte("der"), []byte("jwk")}},
	}
}

const rateLimitRead = "SELECT key_hash, window_start, hits FROM rate_limit_counters " +
	"WHERE key_hash = 'key-1' AND window_start >= 2001-01-01T00:00:00Z"

func serverRecordStatements() []narrowWrite {
	return []narrowWrite{
		// The settings row.
		{
			name: "GetSettingsById",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetSettingsById(ctx, nil, serverRecordId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM settings WHERE id = 9"},
		},
		{
			name: "IsEmpty",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.IsEmpty(ctx)
			},
			answer:     true,
			statements: []string{"SELECT <columns> FROM settings WHERE id = 1"},
		},
		{
			name: "AcquireSettingsRow",
			run: func(ctx context.Context, d *Database) (any, error) {
				return inTx(ctx, d, func(tx *sql.Tx) (any, error) {
					return nil, d.AcquireSettingsRow(ctx, tx, serverRecordId)
				})
			},
			statements: []string{"UPDATE settings SET updated_at = <now> WHERE id = 9"},
		},
		{
			name: "TryClaimCleanupRun",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryClaimCleanupRun(ctx, nil, staleBefore, issuedAt)
			},
			answer: true,
			statements: []string{
				"UPDATE settings SET last_cleanup_at = 2003-03-03T00:00:00Z, updated_at = 2003-03-03T00:00:00Z " +
					"WHERE id = 1 AND (last_cleanup_at IS NULL OR last_cleanup_at < 2001-01-01T00:00:00Z)",
			},
		},
		{
			name:  "TryClaimCleanupRun when another instance holds the run",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryClaimCleanupRun(ctx, nil, staleBefore, issuedAt)
			},
			answer: false,
			statements: []string{
				"UPDATE settings SET last_cleanup_at = 2003-03-03T00:00:00Z, updated_at = 2003-03-03T00:00:00Z " +
					"WHERE id = 1 AND (last_cleanup_at IS NULL OR last_cleanup_at < 2001-01-01T00:00:00Z)",
			},
		},

		// Signing keys.
		{
			name: "GetKeyPairById",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetKeyPairById(ctx, nil, serverRecordId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM key_pairs WHERE id = 9"},
		},
		{
			name: "GetAllSigningKeys",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetAllSigningKeys(ctx, nil)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM key_pairs"},
		},
		{
			name: "GetCurrentSigningKey",
			rows: []*scriptedRows{keyPairRow()},
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetCurrentSigningKey(ctx, nil)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM key_pairs WHERE state = 'current'"},
		},
		{
			name: "UpdateKeyPairState",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.UpdateKeyPairState(ctx, nil, serverRecordId, record.KeyStateCurrent.String(), record.KeyStatePrevious.String())
			},
			answer: true,
			statements: []string{
				"UPDATE key_pairs SET state = 'previous', updated_at = <now> WHERE id = 9 AND state = 'current'",
			},
		},
		{
			name:  "UpdateKeyPairState when another rotation moved the key first",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.UpdateKeyPairState(ctx, nil, serverRecordId, record.KeyStateCurrent.String(), record.KeyStatePrevious.String())
			},
			answer: false,
			statements: []string{
				"UPDATE key_pairs SET state = 'previous', updated_at = <now> WHERE id = 9 AND state = 'current'",
			},
		},
		{
			name: "DeleteKeyPair",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteKeyPair(ctx, nil, serverRecordId)
			},
			statements: []string{"DELETE FROM key_pairs WHERE id = 9"},
		},

		// Pending registrations.
		{
			name: "GetPreRegistrationById",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetPreRegistrationById(ctx, nil, serverRecordId)
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM pre_registrations WHERE id = 9"},
		},
		{
			name: "GetPreRegistrationByEmail",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetPreRegistrationByEmail(ctx, nil, "a@example.com")
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM pre_registrations WHERE email = 'a@example.com'"},
		},
		{
			name: "GetPreRegistrationByVerificationCodeHash",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetPreRegistrationByVerificationCodeHash(ctx, nil, "hash-1")
				return nil, err
			},
			statements: []string{"SELECT <columns> FROM pre_registrations WHERE verification_code_hash = 'hash-1'"},
		},
		{
			name: "GetPreRegistrationByVerificationCodeHash with an empty hash",
			run: func(ctx context.Context, d *Database) (any, error) {
				_, err := d.GetPreRegistrationByVerificationCodeHash(ctx, nil, "")
				return nil, err
			},
		},
		{
			name: "DeletePreRegistration",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeletePreRegistration(ctx, nil, serverRecordId)
			},
			statements: []string{"DELETE FROM pre_registrations WHERE id = 9"},
		},
		{
			name: "DeletePreRegistrationHoldingCode",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.DeletePreRegistrationHoldingCode(ctx, nil, serverRecordId, "hash-1")
			},
			answer:     true,
			statements: []string{"DELETE FROM pre_registrations WHERE id = 9 AND verification_code_hash = 'hash-1'"},
		},
		{
			name:  "DeletePreRegistrationHoldingCode when the row holds another code",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.DeletePreRegistrationHoldingCode(ctx, nil, serverRecordId, "hash-1")
			},
			answer:     false,
			statements: []string{"DELETE FROM pre_registrations WHERE id = 9 AND verification_code_hash = 'hash-1'"},
		},
		{
			name: "DeleteDeadPreRegistrations",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteDeadPreRegistrations(ctx, nil, staleBefore)
			},
			statements: []string{
				"DELETE FROM pre_registrations " +
					"WHERE (verification_code_issued_at < 2003-03-03T00:00:00Z OR verification_code_issued_at IS NULL)",
			},
		},
		{
			name: "TryReplacePreRegistrationCode",
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryReplacePreRegistrationCode(ctx, nil, serverRecordId, "dead-hash", []byte("sealed code"), "hash-1", issuedAt)
			},
			answer: true,
			statements: []string{
				"UPDATE pre_registrations SET verification_code_encrypted = bytes(sealed code), " +
					"verification_code_hash = 'hash-1', verification_code_issued_at = 2001-01-01T00:00:00Z, updated_at = <now> " +
					"WHERE id = 9 AND verification_code_hash = 'dead-hash'",
			},
		},
		{
			name:  "TryReplacePreRegistrationCode when another request replaced it first",
			execs: []*scriptedExec{{rowsAffected: 0}},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.TryReplacePreRegistrationCode(ctx, nil, serverRecordId, "dead-hash", []byte("sealed code"), "hash-1", issuedAt)
			},
			answer: false,
			statements: []string{
				"UPDATE pre_registrations SET verification_code_encrypted = bytes(sealed code), " +
					"verification_code_hash = 'hash-1', verification_code_issued_at = 2001-01-01T00:00:00Z, updated_at = <now> " +
					"WHERE id = 9 AND verification_code_hash = 'dead-hash'",
			},
		},
	}
}

// rateLimitStatements are read with their columns written out: the counters read selects three of
// the record's four, which the record mapping test does not read.
func rateLimitStatements() []narrowWrite {
	admitUnderThree := func(curr, prev int) bool { return curr+prev < 3 }
	return []narrowWrite{
		{
			name: "GetRateLimitCounts",
			rows: []*scriptedRows{rateLimitCounterRows(2, 1)},
			run: func(ctx context.Context, d *Database) (any, error) {
				curr, prev, err := d.GetRateLimitCounts(ctx, nil, keyHash, windowCurrent, windowPrevious)
				return [2]int{curr, prev}, err
			},
			answer:     [2]int{1, 2},
			statements: []string{rateLimitRead},
		},
		{
			name: "ReserveRateLimitHit with both windows' rows there",
			rows: []*scriptedRows{rateLimitCounterRows(1, 1), rateLimitCounterRows(1, 2)},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.ReserveRateLimitHit(ctx, keyHash, windowCurrent, windowPrevious, windowExpires, admitUnderThree)
			},
			answer: true,
			statements: []string{
				rateLimitRead,
				"UPDATE rate_limit_counters SET hits = hits WHERE key_hash = 'key-1' AND window_start = 2001-01-01T00:00:00Z",
				"UPDATE rate_limit_counters SET hits = hits + 1 WHERE key_hash = 'key-1' AND window_start = 2002-02-02T00:00:00Z",
				rateLimitRead,
			},
		},
		{
			name: "ReserveRateLimitHit refused under the locks",
			rows: []*scriptedRows{rateLimitCounterRows(1, 1), rateLimitCounterRows(1, 3)},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.ReserveRateLimitHit(ctx, keyHash, windowCurrent, windowPrevious, windowExpires, admitUnderThree)
			},
			answer: false,
			statements: []string{
				rateLimitRead,
				"UPDATE rate_limit_counters SET hits = hits WHERE key_hash = 'key-1' AND window_start = 2001-01-01T00:00:00Z",
				"UPDATE rate_limit_counters SET hits = hits + 1 WHERE key_hash = 'key-1' AND window_start = 2002-02-02T00:00:00Z",
				rateLimitRead,
			},
		},
		{
			// The previous window's row expires one window after the current one began.
			name: "ReserveRateLimitHit creating both windows' rows",
			rows: []*scriptedRows{{cols: []string{"key_hash", "window_start", "hits"}}, rateLimitCounterRows(0, 1)},
			run: func(ctx context.Context, d *Database) (any, error) {
				return d.ReserveRateLimitHit(ctx, keyHash, windowCurrent, windowPrevious, windowExpires, admitUnderThree)
			},
			answer: true,
			statements: []string{
				rateLimitRead,
				"INSERT INTO rate_limit_counters (key_hash, window_start, hits, expires_at) " +
					"VALUES ('key-1', 2001-01-01T00:00:00Z, 0, 2003-03-06T00:00:00Z)",
				"INSERT INTO rate_limit_counters (key_hash, window_start, hits, expires_at) " +
					"VALUES ('key-1', 2002-02-02T00:00:00Z, 0, 2003-03-03T00:00:00Z)",
				"UPDATE rate_limit_counters SET hits = hits WHERE key_hash = 'key-1' AND window_start = 2001-01-01T00:00:00Z",
				"UPDATE rate_limit_counters SET hits = hits + 1 WHERE key_hash = 'key-1' AND window_start = 2002-02-02T00:00:00Z",
				rateLimitRead,
			},
		},
		{
			name: "RefundRateLimitHit",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.RefundRateLimitHit(ctx, nil, keyHash, windowCurrent)
			},
			statements: []string{
				"UPDATE rate_limit_counters SET hits = hits - 1 " +
					"WHERE key_hash = 'key-1' AND window_start = 2002-02-02T00:00:00Z AND hits > 0",
			},
		},
		{
			name: "DeleteExpiredRateLimitCounters",
			run: func(ctx context.Context, d *Database) (any, error) {
				return nil, d.DeleteExpiredRateLimitCounters(ctx, nil, windowExpires)
			},
			statements: []string{"DELETE FROM rate_limit_counters WHERE expires_at < 2003-03-03T00:00:00Z"},
		},
	}
}

func TestServerRecordStatements_SendTheirStatementOnEveryEngine(t *testing.T) {
	assertNarrowWritesOnEveryEngine(t, serverRecordStatements(), true)
}

func TestServerRecordStatements_TheRateLimitCountersSendTheirStatementOnEveryEngine(t *testing.T) {
	assertNarrowWritesOnEveryEngine(t, rateLimitStatements(), false)
}

// TestServerRecordStatements_TheEnginesPageTheAuditLogs holds the audit-log page to each filter it
// is given, to its total order and to each engine's paging, with the page size and the offset each
// bound to the clause that reads it, and the count beside it to the same filters. SQL Server's
// page is mssqldb's own, which this package's version stands in for here.
func TestServerRecordStatements_TheEnginesPageTheAuditLogs(t *testing.T) {
	for _, c := range []struct {
		name                  string
		auditEvent, requestId string
		where                 string
	}{
		{"no filter", "", "", ""},
		{"by event", "user_created", "", " WHERE audit_event = 'user_created'"},
		{"by request id", "", "req-1", " WHERE request_id = 'req-1'"},
		{"by event and request id", "user_created", "req-1", " WHERE audit_event = 'user_created' AND request_id = 'req-1'"},
	} {
		for _, dialect := range allDialects {
			paging := "LIMIT 10 OFFSET 20"
			if dialect == data.MSSQL {
				paging = "OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY"
			}
			t.Run(c.name+"/"+string(dialect), func(t *testing.T) {
				assertNarrowWriteOn(t, narrowWrite{
					run: func(ctx context.Context, d *Database) (any, error) {
						_, _, err := d.GetAuditLogsPaginated(ctx, nil, 3, 10, c.auditEvent, c.requestId)
						return nil, err
					},
					statements: []string{
						"SELECT <columns> FROM audit_logs" + c.where + " ORDER BY created_at DESC, id DESC " + paging,
						"SELECT COUNT(*) FROM audit_logs" + c.where,
					},
				}, dialect, true)
			})
		}
	}
}

// TestServerRecordStatements_TheEmailCasePreFlightAsksTheEngineToLowerEveryAddress holds the
// pre-flight's read, through the pool and through the migration runner's connection, to every
// users row, unfiltered, with the engine's own LOWER(email) beside the address.
func TestServerRecordStatements_TheEmailCasePreFlightAsksTheEngineToLowerEveryAddress(t *testing.T) {
	const want = "SELECT id, email, LOWER(email) FROM users"
	rows := func() []*scriptedRows {
		return []*scriptedRows{{
			cols:   []string{"id", "email", "lower"},
			values: [][]driver.Value{{int64(3), "Ana@Example.com", "ana@example.com"}},
		}}
	}
	wantRows := []record.EmailCaseRow{{Id: 3, Email: "Ana@Example.com", EngineLowered: "ana@example.com"}}

	for _, dialect := range allDialects {
		t.Run("ScanEmailCase/"+string(dialect), func(t *testing.T) {
			assertNarrowWriteOn(t, narrowWrite{
				rows: rows(),
				run: func(ctx context.Context, d *Database) (any, error) {
					return d.ScanEmailCase(ctx)
				},
				answer:     wantRows,
				statements: []string{want},
			}, dialect, false)
		})
		t.Run("ScanEmailCaseOn/"+string(dialect), func(t *testing.T) {
			assertNarrowWriteOn(t, narrowWrite{
				rows: rows(),
				run: func(ctx context.Context, d *Database) (any, error) {
					conn, err := d.DB.Conn(ctx)
					if err != nil {
						return nil, err
					}
					defer func() { _ = conn.Close() }()
					return d.ScanEmailCaseOn(ctx, conn)
				},
				answer:     wantRows,
				statements: []string{want},
			}, dialect, false)
		})
	}
}

// TestServerRecordStatements_ReencryptionRekeysEveryProtectedColumn holds the re-encryption to
// reading each protected column whole, and to writing a row's new ciphertext, under the new key,
// back to that row's column alone.
func TestServerRecordStatements_ReencryptionRekeysEveryProtectedColumn(t *testing.T) {
	oldKey := []byte(strings.Repeat("o", 32))
	newKey := []byte(strings.Repeat("n", 32))
	sealed, err := encryption.EncryptText("smtp secret", oldKey)
	require.NoError(t, err)

	for _, dialect := range allDialects {
		t.Run(string(dialect), func(t *testing.T) {
			script := &scriptedDriver{}
			script.answer = func(query string, _ []driver.Value) *scriptedRows {
				if query == "SELECT id, smtp_password_encrypted FROM settings" {
					return &scriptedRows{cols: []string{"id", "value"}, values: [][]driver.Value{{int64(1), sealed}}}
				}
				return &scriptedRows{cols: []string{"id", "value"}}
			}
			started := time.Now().UTC()
			require.NoError(t, scriptedDBFor(t, script, dialect).ReencryptToKey(context.Background(), oldKey, newKey))

			var reads []string
			for i, query := range script.statements {
				if strings.HasPrefix(query, "SELECT") {
					reads = append(reads, query)
					continue
				}
				// The one row holding a value is written back, its new ciphertext under the new key.
				require.Equal(t, 1, i, "the write follows its own column's read")
				require.Len(t, script.execArgs, 1)
				args := script.execArgs[0]
				rendered, problems := renderStatement(dialect, query, []driver.Value{"<ciphertext>", args[1]}, started)
				assert.Empty(t, problems, "\n%s", strings.Join(problems, "\n"))
				assert.Equal(t, "UPDATE settings SET smtp_password_encrypted = '<ciphertext>' WHERE id = 1", rendered)
				ciphertext, ok := args[0].([]byte)
				require.True(t, ok, "the ciphertext is bound as bytes")
				plaintext, err := encryption.DecryptText(ciphertext, newKey)
				require.NoError(t, err)
				assert.Equal(t, "smtp secret", plaintext)
			}
			assert.Equal(t, []string{
				"SELECT id, smtp_password_encrypted FROM settings",
				"SELECT id, client_secret_encrypted FROM clients",
				"SELECT id, email_verification_code_encrypted FROM users",
				"SELECT id, otp_secret_encrypted FROM users",
				"SELECT id, forgot_password_code_encrypted FROM users",
				"SELECT id, otp_enrollment_secret_encrypted FROM users",
				"SELECT id, verification_code_encrypted FROM pre_registrations",
				"SELECT id, private_key_pem FROM key_pairs",
			}, reads)
		})
	}
}
