package datafactory

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/core/docsreader"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upgradePage tabulates the records a start writes about the schema, which an operator reads to
// tell a start that is migrating, or waiting for another that is, from one that is hung, and which
// an alert keys on by name (#522 decision 15).
const upgradePage = "site/src/content/docs/deploy/upgrade-goiabada.mdx"

// startRecordsBesideTheSchema are the records a start writes that are about the connection rather
// than the schema, which the page's table leaves out: the start's own two, and those of the engine,
// SQLite for these starts.
var startRecordsBesideTheSchema = map[string]bool{
	"opening the database":     true,
	"database connection pool": true,
	"connected to sqlite database with required PRAGMA settings": true,
	"using database": true,
}

// TestUpgradePage_TheSchemaRecordsAreWhatAStartWrites: every record a start writes about the
// schema has a row naming exactly its attributes, and every row names one a start writes. The
// starts are real ones on SQLite: a first start, a start at head, and a start stopped while it
// migrates. SQLite never waits for the lock, so that record is the start's progress writing it.
func TestUpgradePage_TheSchemaRecordsAreWhatAStartWrites(t *testing.T) {
	rows := upgradeRecordsTable(t, troubleshootingPage(t, upgradePage))
	written := schemaRecordsAStartWrites(t)

	for _, message := range sortedMessages(written) {
		row, ok := rows[message]
		if !ok {
			t.Errorf("%s: ## How migrations run has no row for %q, which a start writes", upgradePage, message)
			continue
		}
		assert.Equalf(t, written[message], row, "%s: ## How migrations run: the row for %q lists the attributes a start writes", upgradePage, message)
	}
	for _, message := range sortedMessages(rows) {
		if _, ok := written[message]; !ok {
			t.Errorf("%s: ## How migrations run has a row for %q, which no start writes", upgradePage, message)
		}
	}
}

// schemaRecordsAStartWrites is each record the starts wrote about the schema, with the sorted
// names of its attributes.
func schemaRecordsAStartWrites(t *testing.T) map[string][]string {
	t.Helper()
	capture := logtest.CaptureSlog(t)
	aesKey := []byte("0123456789abcdef0123456789abcdef")

	dsn := filepath.Join(t.TempDir(), "upgrade.db")
	require.NoError(t, startSQLite(t, dsn), "a first start migrates")
	require.NoError(t, startSQLite(t, dsn), "a start at head migrates nothing")
	(&startupProgress{ctx: context.Background()}).WaitingForLock()

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	stopOnRecord(t, "migrating the database", stop)
	_, err := NewDatabase(ctx, &config.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "stopped.db")}, aesKey, nil, false)
	require.ErrorIs(t, err, context.Canceled, "a start stopped while it migrates")

	written := map[string][]string{}
	for _, record := range capture.Records() {
		if startRecordsBesideTheSchema[record.Message] {
			continue
		}
		attrs := []string{}
		for name := range record.Attrs {
			attrs = append(attrs, name)
		}
		sort.Strings(attrs)
		written[record.Message] = attrs
	}
	require.NotEmpty(t, written, "the starts wrote records about the schema")
	return written
}

// upgradeRecordsTable reads the table headed | Record | When | Attributes | under ## How
// migrations run: each row's record, and the attributes its last cell names, sorted, none being
// an empty list.
func upgradeRecordsTable(t *testing.T, page string) map[string][]string {
	t.Helper()
	section, found := docsreader.SectionText(page, "## How migrations run")
	require.Truef(t, found, "%s has no section headed ## How migrations run", upgradePage)
	rows := map[string][]string{}
	holdsTable := false
	for _, table := range docsreader.Tables(section) {
		if len(table.Header) < 3 || table.Header[0] != "Record" || table.Header[1] != "When" || table.Header[2] != "Attributes" {
			continue
		}
		holdsTable = true
		for _, cells := range table.Rows {
			if len(cells) != 3 {
				continue
			}
			attrs := []string{}
			if cell := cells[2]; cell != "none" {
				for _, name := range strings.Split(cell, ",") {
					attrs = append(attrs, strings.Trim(strings.TrimSpace(name), "`"))
				}
			}
			sort.Strings(attrs)
			rows[strings.Trim(cells[0], "`")] = attrs
		}
	}
	require.Truef(t, holdsTable, "%s: ## How migrations run holds no table headed | Record | When | Attributes |", upgradePage)
	require.NotEmptyf(t, rows, "%s: ## How migrations run holds no table headed | Record | When | Attributes |", upgradePage)
	return rows
}

func sortedMessages(records map[string][]string) []string {
	messages := make([]string, 0, len(records))
	for message := range records {
		messages = append(messages, message)
	}
	sort.Strings(messages)
	return messages
}
