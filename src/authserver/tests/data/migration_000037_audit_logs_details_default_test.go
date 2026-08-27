package datatests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000037_AuditLogsDetailsDefault is goal 2 of #282 stated as a test:
// audit_logs.details defaults to '{}' on all four engines. It runs against an ISOLATED
// database of the configured dialect (see migration_testdb_helper.go).
//
// The migration file exists on MySQL alone, which was the engine without the default, so
// this test takes two shapes: MySQL goes 000035 to 000037 and back, and the other three
// assert the state they already have at 000035 without calling Migrate past it, since
// Migrate refuses a target version the engine's source does not carry.
//
// What is asserted, and what deliberately is not:
//
//   - The default's EFFECT: insert a row naming every column except details, read details
//     back, expect {}. §5 of the agreement rejects asserting the recorded text, because
//     MySQL can only carry this default as an expression and stamps it with the DDL
//     connection's charset, so information_schema reports _utf8mb4'{}' where the other
//     three report '{}'. An assertion on the text would encode a driver setting rather
//     than a schema fact.
//   - The before state as "omission cannot yield {}", capturing both the error and the
//     value rather than choosing between them. Under STRICT_TRANS_TABLES, which the dev
//     container's MySQL sets globally and the Go DSN does not override, the insert is
//     refused outright with ERROR 1364; a non-strict server would store an empty string.
//     Either way it is not {}, and that is the whole claim.
//   - The catalog's Default is checked only for EMPTINESS on MySQL, which is the one thing
//     about it that is engine-independent. That is what distinguishes "the migration added
//     a default" from "some other write happened to put {} in the column".
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000037_AuditLogsDetailsDefault
func TestMigration000037_AuditLogsDetailsDefault(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(35), "migrate to 000035")

	if dbType() != "mysql" {
		details, err := insertAuditLogWithoutDetails000037(t, h, "already-defaulted")
		require.NoErrorf(t, err, "on %s, audit_logs.details already carries a default at 000035", dbType())
		assert.Equalf(t, "{}", details,
			"on %s, omitting details at 000035 must already yield {}", dbType())
		return
	}

	// Before: no default in the catalog, and omission cannot produce {}.
	assert.Empty(t, dumpTable(t, h, "audit_logs").column(t, "details").Default,
		"MySQL's audit_logs.details must carry no default at 000035: that absence is the divergence #282 reports")
	assertDetailsOmissionCannotYieldEmptyObject000037(t, h, "at 000035", "before-migration")

	require.NoError(t, h.Migrator.Migrate(37), "apply 000037")

	assert.NotEmpty(t, dumpTable(t, h, "audit_logs").column(t, "details").Default,
		"audit_logs.details must carry a default after 000037; its recorded TEXT is deliberately not asserted")
	assertDetailsOmissionYieldsEmptyObject000037(t, h, "after apply", "after-migration")

	require.NoError(t, h.Migrator.Migrate(35), "roll back 000037")
	assert.Empty(t, dumpTable(t, h, "audit_logs").column(t, "details").Default,
		"the default must be gone after rolling back to 000035")
	assertDetailsOmissionCannotYieldEmptyObject000037(t, h, "after roll back", "after-down")

	require.NoError(t, h.Migrator.Migrate(37), "re-apply 000037")
	assertDetailsOmissionYieldsEmptyObject000037(t, h, "after down/up round trip", "after-reapply")
}

func assertDetailsOmissionYieldsEmptyObject000037(t *testing.T, h *isolatedDB, phase, event string) {
	t.Helper()

	details, err := insertAuditLogWithoutDetails000037(t, h, event)
	require.NoErrorf(t, err, "[%s] an insert omitting details must be accepted once the default exists", phase)
	assert.Equalf(t, "{}", details, "[%s] omitting details must yield {}", phase)
}

func assertDetailsOmissionCannotYieldEmptyObject000037(t *testing.T, h *isolatedDB, phase, event string) {
	t.Helper()

	details, err := insertAuditLogWithoutDetails000037(t, h, event)
	if err != nil {
		return // refused, which is what a strict server does with a NOT NULL column that has no default
	}
	assert.NotEqualf(t, "{}", details,
		"[%s] with no default declared, omitting details must not yield {}; got it from a non-strict server storing ''", phase)
}

// insertAuditLogWithoutDetails000037 inserts an audit_logs row naming every column except
// details and reads details back. Literals rather than placeholders because the dialects
// disagree on placeholder syntax and every value here is test-controlled, following
// seedKeyPair000030. The timestamp literal parses on all four engines.
//
// The insert's error is returned rather than asserted, because whether omission is refused
// or silently stored is exactly what the caller is deciding about.
func insertAuditLogWithoutDetails000037(t *testing.T, h *isolatedDB, event string) (string, error) {
	t.Helper()

	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO audit_logs (created_at, audit_event) VALUES ('2026-01-01 00:00:00', '%s')`, event))
	if err != nil {
		return "", err
	}

	var details string
	require.NoErrorf(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT details FROM audit_logs WHERE audit_event = '%s'`, event)).Scan(&details),
		"read back details for audit event %s", event)
	return details, nil
}
