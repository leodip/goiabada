package commondb

import (
	"context"
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

// The re-encryption sweep's statements on every engine (#492 decision 4): each column read in
// batches of 100 rows after the last id read, with no transaction, and each value written only
// while its row still holds the bytes read. A write that finds other bytes reads the row again and
// takes what it holds now. The data tier runs the same statements on the four engines; this pins
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

			report, err := scriptedDBFor(t, script, dialect).ReencryptStoredSecrets(context.Background(), newKey, oldKey)

			require.NoError(t, err)
			assert.Equal(t, record.Reencryption{Reencrypted: 100, AlreadyCurrent: 1}, report,
				"clients 2 to 101 are re-encrypted, and client 1 holds a secret already under the current key")
			assert.Empty(t, script.txOptions, "the sweep opens no transaction")

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
			assert.Equal(t, "UPDATE clients SET client_secret_encrypted = '<new>' WHERE id = 1 AND client_secret_encrypted = '<read>'", rendered)
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
