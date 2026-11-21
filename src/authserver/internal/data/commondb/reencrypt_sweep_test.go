package commondb

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The re-encryption sweep's statements on every engine (#492 decision 4): each column read in
// batches of 100 rows after the last id read, with no transaction, and each value written only
// while its row still holds the bytes read, in a transaction of its own. A write that finds other
// bytes reads the row again and takes what it holds now. The data tier runs the same statements on the four engines; this pins
// their text and the paging, which a table smaller than a batch cannot show.
func TestReencryptStoredSecrets_ReadsInBatchesAndWritesOnlyWhatItRead(t *testing.T) {
	oldKey := []byte(strings.Repeat("o", 32))
	newKey := []byte(strings.Repeat("n", 32))
	seal := func(plaintext string, key []byte) []byte {
		sealed, err := encryption.EncryptText(plaintext, key)
		require.NoError(t, err)
		return sealed
	}
	// The first batch is full, so a second is read after its last id; the second is not full, so
	// it is the last.
	firstBatch := make([][]driver.Value, 0, 100)
	for id := int64(1); id <= 100; id++ {
		firstBatch = append(firstBatch, []driver.Value{id, seal("secret", oldKey)})
	}
	secondBatch := [][]driver.Value{{int64(101), seal("secret", oldKey)}}
	// Client 1's row holds other bytes by the time the sweep writes it: a server replaced the
	// secret, under the current key.
	replaced := seal("a replacement", newKey)

	wantRead := map[data.Dialect]string{
		data.SQLite:   "SELECT id, client_secret_encrypted FROM clients WHERE id > %d AND client_secret_encrypted IS NOT NULL ORDER BY id LIMIT 100",
		data.MySQL:    "SELECT id, client_secret_encrypted FROM clients WHERE id > %d AND client_secret_encrypted IS NOT NULL ORDER BY id LIMIT 100",
		data.Postgres: "SELECT id, client_secret_encrypted FROM clients WHERE id > %d AND client_secret_encrypted IS NOT NULL ORDER BY id LIMIT 100",
		data.MSSQL:    "SELECT TOP (100) id, client_secret_encrypted FROM clients WHERE id > %d AND client_secret_encrypted IS NOT NULL ORDER BY id",
	}

	for _, dialect := range allDialects {
		t.Run(string(dialect), func(t *testing.T) {
			script := &scriptedDriver{}
			// The first write, client 1's, finds other bytes; every other write lands.
			script.execs = []*scriptedExec{{rowsAffected: 0}}
			script.answer = func(query string, args []driver.Value) *scriptedRows {
				switch {
				case strings.Contains(query, "id, client_secret_encrypted FROM clients"):
					if args[0] == int64(0) {
						return &scriptedRows{cols: []string{"id", "value"}, values: firstBatch}
					}
					if args[0] == int64(100) {
						return &scriptedRows{cols: []string{"id", "value"}, values: secondBatch}
					}
				case strings.Contains(query, "client_secret_encrypted FROM clients WHERE id"):
					return &scriptedRows{cols: []string{"value"}, values: [][]driver.Value{{replaced}}}
				}
				return &scriptedRows{cols: []string{"id", "value"}}
			}
			started := time.Now().UTC()

			report, err := scriptedDBFor(t, script, dialect).ReencryptStoredSecrets(context.Background(), newKey, oldKey, nil)

			require.NoError(t, err)
			assert.Equal(t, record.Reencryption{Reencrypted: 100, AlreadyCurrent: 1}, report,
				"clients 2 to 101 are re-encrypted, and client 1 holds a secret already under the current key")
			counts := script.settled(t)
			assert.Equal(t, 100, counts.commits, "each write that lands is a transaction of its own, committed")
			assert.Equal(t, 1, counts.rollbacks, "the write that found other bytes changed nothing, and is rolled back")

			var clientReads []string
			for _, query := range script.statements {
				if strings.Contains(query, "FROM clients WHERE id >") {
					clientReads = append(clientReads, query)
				}
			}
			require.Len(t, clientReads, 2, "two batches of clients: %v", clientReads)
			var renderedReads []string
			for i, args := range readArgsOf(script, "FROM clients WHERE id >") {
				rendered, problems := renderStatement(dialect, clientReads[i], args, started)
				assert.Empty(t, problems, "\n%s", strings.Join(problems, "\n"))
				renderedReads = append(renderedReads, rendered)
			}
			assert.Equal(t, []string{
				strings.Replace(wantRead[dialect], "%d", "0", 1),
				strings.Replace(wantRead[dialect], "%d", "100", 1),
			}, renderedReads)

			// Client 1's write names the bytes read, and the re-read after it misses takes the row's.
			require.NotEmpty(t, script.execArgs)
			firstWrite := firstStatement(script, "UPDATE clients")
			args := script.execArgs[0]
			require.Len(t, args, 3)
			readBytes, ok := args[2].([]byte)
			require.True(t, ok, "the bytes read are bound as bytes")
			assert.Equal(t, firstBatch[0][1], readBytes, "the write is conditional on the bytes the sweep read")
			rendered, problems := renderStatement(dialect, firstWrite, []driver.Value{"<new>", args[1], "<read>"}, started)
			assert.Empty(t, problems, "\n%s", strings.Join(problems, "\n"))
			wantWrite := "UPDATE clients SET client_secret_encrypted = '<new>' WHERE id = 1 AND client_secret_encrypted = '<read>'"
			if dialect == data.MSSQL {
				// SQL Server compares VARBINARY values equal when they differ in trailing zero bytes.
				wantWrite += " AND DATALENGTH(client_secret_encrypted) = DATALENGTH('<read>')"
			}
			assert.Equal(t, wantWrite, rendered)
			sealed, ok := args[0].([]byte)
			require.True(t, ok)
			opened, err := encryption.DecryptText(sealed, newKey)
			require.NoError(t, err, "the value written is under the current key")
			assert.Equal(t, "secret", opened)

			reread := firstStatement(script, "SELECT client_secret_encrypted FROM clients")
			rendered, problems = renderStatement(dialect, reread, []driver.Value{int64(1)}, started)
			assert.Empty(t, problems, "\n%s", strings.Join(problems, "\n"))
			assert.Equal(t, "SELECT client_secret_encrypted FROM clients WHERE id = 1", rendered)
		})
	}
}

// readArgsOf answers the arguments of every query whose text contains fragment, in order.
func readArgsOf(script *scriptedDriver, fragment string) [][]driver.Value {
	var args [][]driver.Value
	query := 0
	for _, statement := range script.statements {
		if !strings.HasPrefix(statement, "SELECT") {
			continue
		}
		if strings.Contains(statement, fragment) {
			args = append(args, script.queryArgs[query])
		}
		query++
	}
	return args
}

// firstStatement answers the first statement whose text starts with prefix.
func firstStatement(script *scriptedDriver, prefix string) string {
	for _, statement := range script.statements {
		if strings.HasPrefix(statement, prefix) {
			return statement
		}
	}
	return ""
}

// A stop that reaches a write in flight leaves the run's count equal to what the database holds
// (#492 decision 8). A driver can answer the cancellation of an UPDATE that took effect, as
// SQLite's does while it hands the result back, so a write that answers an error is rolled back and
// not counted; one that answers success is committed whatever the stop did meanwhile, and counted.
// Either way the run then stops, before the next value.
func TestReencryptStoredSecrets_AWriteAStopReachesIsCountedOnlyWhenItCommits(t *testing.T) {
	oldKey := []byte(strings.Repeat("o", 32))
	newKey := []byte(strings.Repeat("n", 32))
	twoClients := func(t *testing.T) [][]driver.Value {
		var rows [][]driver.Value
		for id := int64(1); id <= 2; id++ {
			sealed, err := encryption.EncryptText("secret", oldKey)
			require.NoError(t, err)
			rows = append(rows, []driver.Value{id, sealed})
		}
		return rows
	}

	for _, tc := range []struct {
		name string
		// write is the first write's answer, given the stop it calls inside the statement.
		write              func(stop context.CancelFunc) *scriptedExec
		reencrypted        int
		commits, rollbacks int
	}{
		{"the statement answers the cancellation", func(stop context.CancelFunc) *scriptedExec {
			return &scriptedExec{during: stop, err: context.Canceled}
		}, 0, 0, 1},
		{"the statement lands as the stop arrives", func(stop context.CancelFunc) *scriptedExec {
			return &scriptedExec{during: stop, rowsAffected: 1}
		}, 1, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			clients := twoClients(t)
			script := &scriptedDriver{execs: []*scriptedExec{tc.write(stop)}}
			script.answer = func(query string, args []driver.Value) *scriptedRows {
				if strings.Contains(query, "id, client_secret_encrypted FROM clients") && args[0] == int64(0) {
					return &scriptedRows{cols: []string{"id", "value"}, values: clients}
				}
				return &scriptedRows{cols: []string{"id", "value"}}
			}

			report, err := scriptedDBFor(t, script, data.SQLite).ReencryptStoredSecrets(ctx, newKey, oldKey, nil)

			require.ErrorIs(t, err, context.Canceled, "the run answers the stop")
			assert.Equal(t, tc.reencrypted, report.Reencrypted)
			counts := script.settled(t)
			assert.Equal(t, tc.commits, counts.commits, "commits")
			assert.Equal(t, tc.rollbacks, counts.rollbacks, "rollbacks")
			assert.Equal(t, report.Reencrypted, counts.commits, "the count is what was committed")
			assert.Len(t, script.execArgs, 1, "no write starts after the stop")
		})
	}
}

// The sweep's write is answered as every transaction is (#301, #371): an engine's deadlock victim is
// run again, and the value counted once the rerun commits; a commit that fails for another reason
// has an outcome the sweep cannot know, so the run fails carrying data.ErrCommitOutcomeUnknown, with
// the driver's own error, and counts nothing.
func TestReencryptStoredSecrets_AWriteIsSettledAsEveryTransactionIs(t *testing.T) {
	oldKey := []byte(strings.Repeat("o", 32))
	newKey := []byte(strings.Repeat("n", 32))
	oneClient := func(t *testing.T) func(query string, args []driver.Value) *scriptedRows {
		sealed, err := encryption.EncryptText("secret", oldKey)
		require.NoError(t, err)
		return func(query string, args []driver.Value) *scriptedRows {
			if strings.Contains(query, "id, client_secret_encrypted FROM clients") && args[0] == int64(0) {
				return &scriptedRows{cols: []string{"id", "value"}, values: [][]driver.Value{{int64(1), sealed}}}
			}
			return &scriptedRows{cols: []string{"id", "value"}}
		}
	}

	t.Run("a deadlock victim is written again", func(t *testing.T) {
		logs := logtest.CaptureSlog(t)
		script := &scriptedDriver{execs: []*scriptedExec{{err: errDeadlock}, {rowsAffected: 1}}}
		script.answer = oneClient(t)
		db := retryingDB(t, script)
		backoff := recordBackoff(db)

		report, err := db.ReencryptStoredSecrets(context.Background(), newKey, oldKey, nil)

		require.NoError(t, err)
		assert.Equal(t, record.Reencryption{Reencrypted: 1}, report)
		counts := script.settled(t)
		assert.Equal(t, 1, counts.commits, "the rerun commits")
		assert.Equal(t, 1, counts.rollbacks, "the victim is rolled back")
		assert.Len(t, script.execArgs, 2, "the write is run once more")
		assert.Equal(t, []time.Duration{runInTransactionBackoff[0]}, *backoff)
		assert.Equal(t, 1, retryWarnings(logs))
	})

	t.Run("a commit whose outcome is unknown fails the run", func(t *testing.T) {
		script := &scriptedDriver{commitErrs: []error{io.ErrUnexpectedEOF}}
		script.answer = oneClient(t)

		report, err := retryingDB(t, script).ReencryptStoredSecrets(context.Background(), newKey, oldKey, nil)

		require.ErrorIs(t, err, data.ErrCommitOutcomeUnknown)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF, "the driver's own error stays reachable")
		assert.Equal(t, 0, report.Reencrypted, "a commit not known to have landed is not counted")
		counts := script.settled(t)
		assert.Equal(t, 1, counts.commits, "the commit is asked for once, never replayed")
		assert.Len(t, script.execArgs, 1)
	})

	// pgx answers a statement's cancellation by closing the connection, so the rollback after it
	// fails; the engine rolled the transaction back, and a stop is no fault to warn of.
	t.Run("a rollback failing after a stop is not warned of", func(t *testing.T) {
		logs := logtest.CaptureSlog(t)
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		script := &scriptedDriver{
			execs:        []*scriptedExec{{during: stop, err: context.Canceled}},
			rollbackErrs: []error{errors.New("failed to deallocate cached statement(s): conn closed")},
		}
		script.answer = oneClient(t)

		_, err := retryingDB(t, script).ReencryptStoredSecrets(ctx, newKey, oldKey, nil)

		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, script.settled(t).rollbacks)
		assert.Zero(t, warningsContaining(logs, "rolling back a failed transaction"))
	})
}

// The sweep names each value neither key opens as it reaches it, never holding them to the end of
// the run: the first is named before the table's second batch is read (#492 decisions 4 and 5).
func TestReencryptStoredSecrets_NamesEachUnreadableValueAsItReachesIt(t *testing.T) {
	otherKey := []byte(strings.Repeat("x", 32))
	oldKey := []byte(strings.Repeat("o", 32))
	newKey := []byte(strings.Repeat("n", 32))
	var firstBatch [][]driver.Value
	for id := int64(1); id <= 100; id++ {
		sealed, err := encryption.EncryptText("secret", otherKey)
		require.NoError(t, err)
		firstBatch = append(firstBatch, []driver.Value{id, sealed})
	}
	sealed, err := encryption.EncryptText("secret", otherKey)
	require.NoError(t, err)
	secondBatch := [][]driver.Value{{int64(101), sealed}}

	script := &scriptedDriver{}
	script.answer = func(query string, args []driver.Value) *scriptedRows {
		if strings.Contains(query, "id, client_secret_encrypted FROM clients") {
			switch args[0] {
			case int64(0):
				return &scriptedRows{cols: []string{"id", "value"}, values: firstBatch}
			case int64(100):
				return &scriptedRows{cols: []string{"id", "value"}, values: secondBatch}
			}
		}
		return &scriptedRows{cols: []string{"id", "value"}}
	}
	clientBatchesRead := func() int {
		script.mu.Lock()
		defer script.mu.Unlock()
		n := 0
		for _, statement := range script.statements {
			if strings.Contains(statement, "FROM clients WHERE id >") {
				n++
			}
		}
		return n
	}
	var named []record.StoredSecret
	var batchesReadAtEach []int

	report, err := scriptedDBFor(t, script, data.SQLite).ReencryptStoredSecrets(context.Background(), newKey, oldKey,
		func(value record.StoredSecret) {
			named = append(named, value)
			batchesReadAtEach = append(batchesReadAtEach, clientBatchesRead())
		})

	require.NoError(t, err)
	assert.Equal(t, record.Reencryption{Unreadable: 101}, report)
	require.Len(t, named, 101)
	for i, value := range named {
		assert.Equal(t, record.StoredSecret{Table: "clients", Column: "client_secret_encrypted", ID: int64(i + 1)}, value)
	}
	assert.Equal(t, 1, batchesReadAtEach[0], "the first unreadable value is named before the second batch is read")
	assert.Equal(t, 1, batchesReadAtEach[99], "the first batch's values are all named before the second is read")
	assert.Equal(t, 2, batchesReadAtEach[100])
	assert.Empty(t, script.execArgs, "nothing unreadable is written")
}
