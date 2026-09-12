package datatests

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000045_AuditLogsRequestId is the storage half of #328 as a test: audit_logs gains
// request_id, NOT NULL with an empty-string default and indexed, on all four engines. It runs
// against an ISOLATED database of the configured dialect (see migration_testdb_helper.go).
//
// What is asserted, and what deliberately is not:
//
//   - The default's EFFECT rather than its recorded text, following
//     TestMigration000037_AuditLogsDetailsDefault. The four engines spell DEFAULT ” four ways
//     and MySQL reports the empty string for it, which is indistinguishable from no default at
//     all in the Default field alone; HasDefault is the engine-independent fact and the read-back
//     of an omitting insert is the behaviour that matters.
//   - That a row written BEFORE the column exists reads ” after it, which is the whole of
//     "existing rows mean not written on a request". A nullable column would have answered NULL
//     here, and decision 7 chose against that.
//   - The index by shape rather than by plan: non-unique, keyed on request_id alone, and named
//     the same on every engine so the next migration to touch it can drop it by name.
//   - Not the column's width or type spelling. That is engine vocabulary and the four
//     schema.golden files already record it, checked by the per-engine schema assertion.
//
// The down is exercised rather than described, because it is the statement most likely to be
// wrong and least likely to be run: on SQL Server the default is a named constraint that has to
// be dropped before the column, and on every engine the index has to go first.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>
//
//	--run TestMigration000045_AuditLogsRequestId
func TestMigration000045_AuditLogsRequestId(t *testing.T) {
	h := newIsolatedDB(t)

	require.NoError(t, h.Migrator.Migrate(44), "migrate to 000044")

	assert.Falsef(t, auditLogsHasRequestId000045(t, h),
		"audit_logs must not carry request_id at 000044 on %s", dbType())
	assert.Falsef(t, describeIndex(t, h, "audit_logs", "idx_audit_logs_request_id").Exists,
		"the index must not exist at 000044 on %s", dbType())

	// A row from before the column, which is every row in an existing deployment.
	seedAuditLogWithoutRequestId000045(t, h, "written-at-000044")

	require.NoError(t, h.Migrator.Migrate(45), "apply 000045")

	column := dumpTable(t, h, "audit_logs").column(t, "request_id")
	assert.Falsef(t, column.Nullable,
		"request_id must be NOT NULL on %s: absence is spelled '' and not NULL (decision 7)", dbType())
	assert.Truef(t, column.HasDefault,
		"request_id must carry a default on %s; its recorded text is deliberately not asserted, since MySQL reports '' for DEFAULT ''", dbType())

	index := describeIndex(t, h, "audit_logs", "idx_audit_logs_request_id")
	require.Truef(t, index.Exists, "idx_audit_logs_request_id must exist after 000045 on %s", dbType())
	assert.Falsef(t, index.Unique,
		"the index must be non-unique: many rows share a request id, and many carry none at all")
	assert.Equalf(t, []string{"request_id"}, index.Columns,
		"the index is keyed on request_id alone on %s", dbType())

	assert.Equalf(t, "", readRequestId000045(t, h, "written-at-000044"),
		"a row written before the column must read '' on %s, which is what the viewer shows as no request", dbType())

	seedAuditLogWithoutRequestId000045(t, h, "omitting-at-000045")
	assert.Equalf(t, "", readRequestId000045(t, h, "omitting-at-000045"),
		"an insert that names no request_id must be accepted and default to '' on %s", dbType())

	require.NoError(t, h.Migrator.Migrate(44), "roll back 000045")
	assert.Falsef(t, auditLogsHasRequestId000045(t, h),
		"the column must be gone after rolling back to 000044 on %s", dbType())
	assert.Falsef(t, describeIndex(t, h, "audit_logs", "idx_audit_logs_request_id").Exists,
		"the index must be gone after rolling back to 000044 on %s", dbType())

	require.NoError(t, h.Migrator.Migrate(45), "re-apply 000045")
	assert.Truef(t, auditLogsHasRequestId000045(t, h),
		"the column must return after a down/up round trip on %s", dbType())
	assert.Truef(t, describeIndex(t, h, "audit_logs", "idx_audit_logs_request_id").Exists,
		"the index must return after a down/up round trip on %s", dbType())
}

// auditLogsHasRequestId000045 reads the catalog rather than attempting a statement, because the
// question is whether the column exists and dumpTable's column accessor fails the test when it
// does not.
func auditLogsHasRequestId000045(t *testing.T, h *isolatedDB) bool {
	t.Helper()

	for _, c := range dumpTable(t, h, "audit_logs").Columns {
		if c.Name == "request_id" {
			return true
		}
	}
	return false
}

// seedAuditLogWithoutRequestId000045 inserts a row naming created_at, audit_event and details and
// nothing else, which is what an insert written before this migration looks like. Literals rather
// than placeholders because the dialects disagree on placeholder syntax and every value here is
// test-controlled, following insertAuditLogWithoutDetails000037.
func seedAuditLogWithoutRequestId000045(t *testing.T, h *isolatedDB, event string) {
	t.Helper()

	_, err := h.SQL.Exec(fmt.Sprintf(
		`INSERT INTO audit_logs (created_at, audit_event, details) VALUES ('2026-01-01 00:00:00', '%s', '{}')`, event))
	require.NoErrorf(t, err, "insert audit event %s on %s", event, dbType())
}

func readRequestId000045(t *testing.T, h *isolatedDB, event string) string {
	t.Helper()

	var requestId string
	require.NoErrorf(t, h.SQL.QueryRow(fmt.Sprintf(
		`SELECT request_id FROM audit_logs WHERE audit_event = '%s'`, event)).Scan(&requestId),
		"read back request_id for audit event %s on %s", event, dbType())
	return requestId
}
