package datatests

import (
	"sync"
	"testing"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data"
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
// Built once for the package and deliberately never closed. NewDatabase re-runs the migration
// chain and the startup data tasks, both idempotent and both no-ops against an already migrated
// catalog, but neither is free and mssql in particular does not enjoy being asked repeatedly.
//
// What it does NOT give is more concurrency than production has. The authserver builds one
// data.Database, so a SQLite deployment runs the whole process on a single connection and the
// operations these tests interleave can never overlap there at all. Two handles is therefore the
// conservative direction on SQLite and the faithful one on the other three.
func secondDatabase(t *testing.T) data.Database {
	t.Helper()

	secondHandleOnce.Do(func() {
		secondHandle, secondHandleErr = data.NewDatabase(config.GetDatabase(), false)
	})

	require.NoError(t, secondHandleErr, "opening a second database handle")
	require.NotNil(t, secondHandle, "the second database handle must exist")
	return secondHandle
}
