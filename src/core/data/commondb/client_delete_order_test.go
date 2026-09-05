package commondb

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"testing"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DELETECLIENT'S STATEMENT ORDER IS THE WHOLE OF WHAT IT ADDED, AND NO ENGINE CAN BE ASKED FOR IT.
//
// Since #139 every transaction that ends a session and revokes its grants takes the users row,
// then the user_sessions rows, then the grants, which means it is holding a session's
// user_session_clients rows from its first statement. DeleteClient's cascade wants exactly those
// rows, and by the time it asks for one it already holds that client's codes and its explicitly
// deleted refresh tokens, which the other side is about to sweep. Each holds half of what the
// other wants.
//
// The remedy is that this transaction takes the clients row first, reads the sessions associated
// with it, and takes those session rows before either delete runs. Nothing about the final row
// state records that it did: the same rows are gone either way. The order is only visible on the
// connection, so a scripted driver is the only place to pin it, exactly as the handler's own
// sequence is pinned by a mock in the authserver package. What two real transactions of these
// shapes do to each other on a real catalog is the data tier's, in
// lock_order_client_delete_test.go, on all four engines.

// modelRows is modelRow for a result set with several rows in it, which is what the association
// read returns and what makes the ordering assertion below worth making.
func modelRows(t *testing.T, first interface{}, rest ...interface{}) *scriptedRows {
	t.Helper()

	out := modelRow(t, first)
	for _, model := range rest {
		more := modelRow(t, model)
		require.Equal(t, len(out.cols), len(more.cols), "every row of one result set has the same columns")
		out.values = append(out.values, more.values...)
	}
	return out
}

// statementTargets reduces each recorded statement to "<verb> <table>", which is the only thing
// this test is about. Reading the text at all is a deliberate exception to the rule the rest of
// the scripted-driver tests follow: the table a statement addresses is in its text and nowhere
// else, and a clause rewritten inside one of these statements does not change the pair.
func statementTargets(t *testing.T, statements []string) []string {
	t.Helper()

	out := make([]string, 0, len(statements))
	for _, statement := range statements {
		fields := strings.Fields(statement)
		require.GreaterOrEqual(t, len(fields), 2, "a statement with fewer than two words: %q", statement)
		switch verb := strings.ToUpper(fields[0]); verb {
		case "UPDATE":
			out = append(out, "UPDATE "+fields[1])
		case "DELETE", "SELECT":
			from := -1
			for i, field := range fields {
				if strings.EqualFold(field, "FROM") {
					from = i
					break
				}
			}
			require.GreaterOrEqual(t, from, 0, "a %s with no FROM: %q", verb, statement)
			require.Less(t, from+1, len(fields), "a %s FROM naming nothing: %q", verb, statement)
			out = append(out, verb+" "+fields[from+1])
		default:
			out = append(out, statement)
		}
	}
	return out
}

func TestDeleteClient_TakesItsRowsInTheBranchsOrder(t *testing.T) {
	d := &scriptedDriver{
		rows: []*scriptedRows{
			// The association read. Two sessions, handed back in descending id order, so the
			// ascending sort below is doing something rather than agreeing with the input.
			modelRows(t,
				&models.UserSessionClient{Id: 2, UserSessionId: 71, ClientId: 5},
				&models.UserSessionClient{Id: 1, UserSessionId: 13, ClientId: 5},
			),
		},
	}

	require.NoError(t, scriptedDB(t, d).DeleteClient(nil, 5))

	assert.Equal(t, []string{
		"UPDATE clients",
		"SELECT user_session_clients",
		"UPDATE user_sessions",
		"UPDATE user_sessions",
		"DELETE refresh_tokens",
		"DELETE clients",
	}, statementTargets(t, d.statements),
		"the clients row is taken first, which is what closes the association read's discovery window; "+
			"the session rows follow, so the cascade is not the first statement to want a row a "+
			"session-first transaction is already holding; and only then do the two deletes run")

	// And the session rows are taken in ascending id order. Without that, two overlapping
	// deletions of different clients that share a session take those rows in whatever order the
	// engine returned them, which is a cycle among sessions that no rule about the order of
	// TABLES can reach. The read hands them back descending, so agreeing by accident is ruled out.
	assert.Equal(t, []int64{13, 71}, sessionIdsAcquired(t, d),
		"the session rows are taken in ascending id order, whatever order the read returned them in")

	assert.Equal(t, 1, d.commits, "DeleteClient with a nil transaction opens and commits exactly one")
}

// sessionIdsAcquired reads the id argument of every UPDATE user_sessions the run issued, in
// order. The arguments are (updated_at, id), so the id is the last one.
func sessionIdsAcquired(t *testing.T, d *scriptedDriver) []int64 {
	t.Helper()

	d.mu.Lock()
	defer d.mu.Unlock()

	var ids []int64
	exec := 0
	for _, statement := range d.statements {
		if !strings.HasPrefix(strings.ToUpper(statement), "SELECT") {
			if strings.HasPrefix(statement, "UPDATE user_sessions") {
				require.Less(t, exec, len(d.execArgs), "more statements than recorded arguments")
				args := d.execArgs[exec]
				require.NotEmpty(t, args, "an acquisition with no arguments: %q", statement)
				id, ok := args[len(args)-1].(int64)
				require.Truef(t, ok, "the acquisition's key argument is not an id: %#v", args[len(args)-1])
				ids = append(ids, id)
			}
			exec++
		}
	}
	return ids
}

// TestDeleteClient_TakesNoSessionRowWhenTheClientHasNoSessions is the empty case, and it is worth
// its own test because the acquisition loop is the one part of the sequence that can run zero
// times. A client nobody ever signed in to still has its row taken first, because the read that
// establishes it has no sessions is itself the thing the lock makes complete.
func TestDeleteClient_TakesNoSessionRowWhenTheClientHasNoSessions(t *testing.T) {
	d := &scriptedDriver{rows: []*scriptedRows{{cols: []string{"id"}}}}

	require.NoError(t, scriptedDB(t, d).DeleteClient(nil, 5))

	assert.Equal(t, []string{
		"UPDATE clients",
		"SELECT user_session_clients",
		"DELETE refresh_tokens",
		"DELETE clients",
	}, statementTargets(t, d.statements),
		"no associations means no session acquisitions, and the clients row is still taken first")
}

// TestDeleteClient_TakesEachSessionRowOnce pins the deduplication. Nothing in the schema stops one
// client appearing twice on a session today (#249 is the constraint that would), and a duplicate
// acquisition is a second UPDATE of a row this transaction already holds: harmless, but it makes
// the sequence depend on data rather than on the rule, and the next reader cannot tell which.
func TestDeleteClient_TakesEachSessionRowOnce(t *testing.T) {
	d := &scriptedDriver{
		rows: []*scriptedRows{
			modelRows(t,
				&models.UserSessionClient{Id: 1, UserSessionId: 13, ClientId: 5},
				&models.UserSessionClient{Id: 2, UserSessionId: 13, ClientId: 5},
			),
		},
	}

	require.NoError(t, scriptedDB(t, d).DeleteClient(nil, 5))

	assert.Equal(t, []int64{13}, sessionIdsAcquired(t, d),
		"one session named twice is one row, so it is acquired once")
}

// TestDeleteClient_AFailedAcquisitionStopsIt. Every acquisition in this sequence is a lock this
// transaction is about to depend on, so one that failed cannot be carried past: a transaction
// that went on to delete while holding less than it planned to is writing out of order rather
// than in it, which is the whole thing this stage removed.
func TestDeleteClient_AFailedAcquisitionStopsIt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		execs []*scriptedExec
		want  []string
	}{
		{
			name:  "the client row acquisition fails",
			execs: []*scriptedExec{{err: fmt.Errorf("deadlock found when trying to get lock")}},
			want:  []string{"UPDATE clients"},
		},
		{
			name: "a session row acquisition fails",
			execs: []*scriptedExec{
				{rowsAffected: 1},
				{err: fmt.Errorf("deadlock found when trying to get lock")},
			},
			want: []string{"UPDATE clients", "SELECT user_session_clients", "UPDATE user_sessions"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &scriptedDriver{
				rows: []*scriptedRows{
					modelRows(t,
						&models.UserSessionClient{Id: 1, UserSessionId: 13, ClientId: 5},
						&models.UserSessionClient{Id: 2, UserSessionId: 71, ClientId: 5},
					),
				},
				execs: tc.execs,
			}

			require.Error(t, scriptedDB(t, d).DeleteClient(nil, 5),
				"an acquisition that failed must stop the deletion rather than be carried past")
			assert.Equal(t, tc.want, statementTargets(t, d.statements),
				"nothing below the failed acquisition may run")
			assert.Zero(t, d.commits, "and the transaction it opened must not commit")
			assert.Equal(t, 1, d.rollbacks, "it is rolled back")
		})
	}
}

// TestDeleteClient_EverythingIsOnTheCallersTransaction. The order buys nothing if the statements
// are not on one connection: a row taken on another is released the moment that statement
// autocommits. scriptedDB already fails any test in this package whose statements escape, so this
// one only has to state that DeleteClient is held to it with a transaction it was HANDED, which
// is the shape the admin console uses.
func TestDeleteClient_EverythingIsOnTheCallersTransaction(t *testing.T) {
	d := &scriptedDriver{
		rows: []*scriptedRows{modelRow(t, &models.UserSessionClient{Id: 1, UserSessionId: 13, ClientId: 5})},
	}
	db := sql.OpenDB(d)
	t.Cleanup(func() { _ = db.Close() })
	common := NewCommonDatabase(db, sqlbuilder.SQLite, false)

	tx, err := common.BeginTransaction()
	require.NoError(t, err)
	require.NoError(t, common.DeleteClient(tx, 5))
	require.NoError(t, common.CommitTransaction(tx))

	assertNothingEscapedItsTransaction(t, d)
	assert.Equal(t, 1, d.commits, "the caller's commit, and no commit of DeleteClient's own")
}

var _ driver.Value = int64(0)
