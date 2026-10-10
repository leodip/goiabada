package datatests

import (
	"context"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/datafactory"
	"github.com/stretchr/testify/require"
)

var (
	secondHandleOnce sync.Once
	secondHandle     data.Database
	secondHandleErr  error
)

// secondDatabase returns a SECOND data.Database over the engine this tier is running against,
// so a test can hold two transactions open at the same time and interleave them by hand.
//
// WHY A SECOND HANDLE RATHER THAN TWO TRANSACTIONS ON THE PACKAGE'S SHARED ONE. sqlitedb calls
// SetMaxOpenConns(1), so its pool has exactly one connection: a second BeginTransaction on that
// handle waits for the first to finish and the interleaving can never happen at all. A handle is
// a pool, so a second handle is a second connection on every engine, which is the only shape
// that works on all four (#139 decision 8).
//
// Built once for the package and deliberately never closed, through datafactory.OpenDatabase: a
// second pool over a database the tier has already migrated, not a start. NewDatabase would also
// run the migration chain and the startup data tasks, and those now read the data key's canary at
// every start (#542), which this tier's shared database fails on purpose: its tests store key pairs
// whose PEM is under no key at all.
//
// CALL IT BEFORE OPENING ANY TRANSACTION. Construction connects to the database it is about to
// share with the calling test, and the Once caches an error for every later test in the package, so
// every test here takes the handle on its first line, before it holds anything. (The rule once
// rested on the OTP secret backfill, an UPDATE on users, which #359 deleted, and then on the
// rotation canary's read of key_pairs, which this handle no longer makes.)
//
// What it does NOT give is more concurrency than production has. The authserver builds one
// data.Database, so a SQLite deployment runs the whole process on a single connection and the
// operations these tests interleave can never overlap there at all. Two handles is therefore the
// conservative direction on SQLite and the faithful one on the other three.
func secondDatabase(t *testing.T) data.Database {
	t.Helper()

	secondHandleOnce.Do(func() {
		secondHandle, secondHandleErr = datafactory.OpenDatabase(context.Background(), &appConfig.Database, false)
	})

	require.NoError(t, secondHandleErr, "opening a second database handle")
	require.NotNil(t, secondHandle, "the second database handle must exist")
	return secondHandle
}
