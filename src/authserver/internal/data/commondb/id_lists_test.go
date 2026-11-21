package commondb

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// forEachIDBatch is the one place the statement budget lives, and every id-list lookup in the
// package is correct only if it is. The data tier proves each lookup returns its rows against four
// real engines; these are the properties that are the helper's own, where a fixture of 2,101 rows
// would prove them more slowly and no more clearly (#373).

// The split itself, at the three lengths where an off-by-one lives: one short of the budget, the
// budget exactly, and one past it. A helper that used <= where it needs < issues an empty second
// statement at the exact multiple, and an empty IN () is a syntax error on all four engines.
func TestForEachIDBatch_SplitsAtTheBudget(t *testing.T) {
	testCases := []struct {
		name  string
		total int
		want  []int
	}{
		{name: "one id", total: 1, want: []int{1}},
		{name: "one short of the budget", total: maxIDsPerStatement - 1, want: []int{maxIDsPerStatement - 1}},
		{name: "the budget exactly", total: maxIDsPerStatement, want: []int{maxIDsPerStatement}},
		{name: "one past the budget", total: maxIDsPerStatement + 1, want: []int{maxIDsPerStatement, 1}},
		{name: "an exact multiple of the budget", total: 2 * maxIDsPerStatement, want: []int{maxIDsPerStatement, maxIDsPerStatement}},
		{name: "past SQL Server's 2,100 parameter ceiling", total: 2101, want: []int{maxIDsPerStatement, maxIDsPerStatement, 101}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ids := make([]int64, testCase.total)
			for i := range ids {
				ids[i] = int64(i + 1)
			}

			var sizes []int
			var seen []int64
			require.NoError(t, forEachIDBatch(ids, func(batch []int64) error {
				sizes = append(sizes, len(batch))
				seen = append(seen, batch...)
				return nil
			}))

			assert.Equal(t, testCase.want, sizes)
			assert.Equal(t, ids, seen, "every id is handed over exactly once, in order")
			for _, size := range sizes {
				assert.NotZero(t, size, "an empty batch would build IN (), which every engine refuses")
			}
		})
	}
}

// Deduplication is correctness and not economy. One IN list answers a repeated id once; split
// across two statements, the same id on either side of the boundary comes back twice, and the
// caller cannot tell two copies of one row from two rows. The id repeated here sits at the last
// slot of the first batch and the first slot of the second, which is the arrangement a helper
// deduplicating within each batch rather than across the list would still get wrong.
func TestForEachIDBatch_DeduplicatesAcrossTheWholeList(t *testing.T) {
	ids := make([]int64, 0, maxIDsPerStatement+2)
	for i := 0; i < maxIDsPerStatement; i++ {
		ids = append(ids, int64(i+1))
	}
	ids = append(ids, int64(maxIDsPerStatement), int64(maxIDsPerStatement+1))

	var seen []int64
	var sizes []int
	require.NoError(t, forEachIDBatch(ids, func(batch []int64) error {
		sizes = append(sizes, len(batch))
		seen = append(seen, batch...)
		return nil
	}))

	assert.Equal(t, []int{maxIDsPerStatement, 1}, sizes,
		"the repeat is dropped, so the second statement carries the one id that is new")
	assert.Len(t, seen, maxIDsPerStatement+1)
	counts := map[int64]int{}
	for _, id := range seen {
		counts[id]++
	}
	for id, count := range counts {
		assert.Equalf(t, 1, count, "id %d was handed over %d times", id, count)
	}
}

// The first occurrence is what survives, and the order is the caller's. Not a property anything
// depends on today -- no lookup here carries an ORDER BY -- but it is what makes a failure
// readable, and a helper that returned a map's iteration order would make these cases flaky rather
// than wrong.
func TestForEachIDBatch_KeepsTheCallersOrder(t *testing.T) {
	var seen []int64
	require.NoError(t, forEachIDBatch([]int64{9, 4, 9, 7, 4}, func(batch []int64) error {
		seen = append(seen, batch...)
		return nil
	}))

	assert.Equal(t, []int64{9, 4, 7}, seen)
}

// An empty list issues nothing at all. Each lookup answers an empty list its own way -- some
// return nil, GetClientsByIDs returns an empty slice -- and the helper calling the function once
// with an empty batch would turn all of them into IN (), which is a syntax error on all four
// engines and, in the backfill's case, at startup.
func TestForEachIDBatch_CallsNothingForAnEmptyList(t *testing.T) {
	calls := 0
	countCall := func(batch []int64) error {
		calls++
		return nil
	}

	require.NoError(t, forEachIDBatch(nil, countCall))
	require.NoError(t, forEachIDBatch([]int64{}, countCall))

	assert.Zero(t, calls)
}

// A failing statement stops the run and is returned as it was. A helper that carried on would
// issue the rest of the statements after the connection had already refused one, and a caller
// reading the returned rows would get a partial answer reported as success.
func TestForEachIDBatch_StopsAtTheFirstFailure(t *testing.T) {
	boom := errors.New("connection reset by peer")

	ids := make([]int64, 3*maxIDsPerStatement)
	for i := range ids {
		ids[i] = int64(i + 1)
	}

	calls := 0
	err := forEachIDBatch(ids, func(batch []int64) error {
		calls++
		if calls == 2 {
			return boom
		}
		return nil
	})

	require.ErrorIs(t, err, boom, "the error is returned unwrapped, so the caller's own Wrap names the query")
	assert.Equal(t, 2, calls, "the third statement must not be issued")
}
