package apihandlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// storedRow stands in for any stored row a list save reads: an id and the key it is compared on.
type storedRow struct {
	id  int64
	key string
}

func storedRowKey(r storedRow) string { return r.key }
func storedRowId(r storedRow) int64   { return r.id }

// replaceSet is the plan every list save applies inside its transaction, owned here once; each save
// carries one thin case showing a stored duplicate is removed with its original. The two duplicate
// rows are what the plan exists for beyond a plain diff: keyed by value, the saves this replaced held
// one row id per key, so a key stored twice lost one copy on removal and kept the other live (#428).
func TestReplaceSet(t *testing.T) {
	tests := []struct {
		name       string
		stored     []storedRow
		wanted     []string
		wantInsert []string
		wantRemove []int64
	}{
		{
			name:       "nothing stored",
			stored:     nil,
			wanted:     []string{"a", "b"},
			wantInsert: []string{"a", "b"},
		},
		{
			name:       "nothing wanted",
			stored:     []storedRow{{1, "a"}, {2, "b"}},
			wanted:     []string{},
			wantRemove: []int64{1, 2},
		},
		{
			name:   "nothing stored and nothing wanted",
			stored: nil,
			wanted: nil,
		},
		{
			name:   "stored already as wanted",
			stored: []storedRow{{1, "a"}, {2, "b"}},
			wanted: []string{"b", "a"},
		},
		{
			name:       "add only",
			stored:     []storedRow{{1, "a"}},
			wanted:     []string{"a", "b"},
			wantInsert: []string{"b"},
		},
		{
			name:       "remove only",
			stored:     []storedRow{{1, "a"}, {2, "b"}},
			wanted:     []string{"a"},
			wantRemove: []int64{2},
		},
		{
			name:       "add and remove",
			stored:     []storedRow{{1, "a"}, {2, "b"}},
			wanted:     []string{"b", "c"},
			wantInsert: []string{"c"},
			wantRemove: []int64{1},
		},
		{
			name:       "a wanted key stored twice loses the later copy",
			stored:     []storedRow{{1, "a"}, {2, "a"}},
			wanted:     []string{"a"},
			wantRemove: []int64{2},
		},
		{
			name:       "an unwanted key stored twice loses both copies",
			stored:     []storedRow{{1, "a"}, {2, "b"}, {3, "a"}},
			wanted:     []string{"b"},
			wantRemove: []int64{1, 3},
		},
		{
			name:       "a key repeated in the wanted list is inserted once",
			stored:     nil,
			wanted:     []string{"a", "a", "b"},
			wantInsert: []string{"a", "b"},
		},
		{
			name:       "a repeated wanted key that is stored is not inserted",
			stored:     []storedRow{{1, "a"}},
			wanted:     []string{"a", "a"},
			wantInsert: nil,
		},
		{
			name:       "remove follows stored order and insert follows wanted order",
			stored:     []storedRow{{9, "z"}, {3, "y"}, {5, "x"}},
			wanted:     []string{"q", "p", "r"},
			wantInsert: []string{"q", "p", "r"},
			wantRemove: []int64{9, 3, 5},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			insert, remove := replaceSet(test.stored, storedRowKey, storedRowId, test.wanted)
			assert.Equal(t, test.wantInsert, insert)
			assert.Equal(t, test.wantRemove, remove)
		})
	}
}

// sameSet is the loaded-list check every list save makes before planning: the stored rows must carry
// exactly the keys the caller says it loaded, or the save is refused 409 rather than undoing a change
// the caller never saw. Order and repeats are ignored, since the page may list what it loaded in
// another order than the rows were read and a stored duplicate is one value to the page (#428).
func TestSameSet(t *testing.T) {
	tests := []struct {
		name     string
		stored   []storedRow
		expected []string
		want     bool
	}{
		{name: "empty equals empty", stored: nil, expected: []string{}, want: true},
		{name: "the same keys", stored: []storedRow{{1, "a"}, {2, "b"}}, expected: []string{"a", "b"}, want: true},
		{name: "the same keys in another order", stored: []storedRow{{1, "a"}, {2, "b"}}, expected: []string{"b", "a"}, want: true},
		{name: "a repeat in the expected list", stored: []storedRow{{1, "a"}, {2, "b"}}, expected: []string{"a", "b", "a"}, want: true},
		{name: "a repeat in the stored rows", stored: []storedRow{{1, "a"}, {2, "a"}}, expected: []string{"a"}, want: true},
		{name: "one key added since it was loaded", stored: []storedRow{{1, "a"}, {2, "b"}}, expected: []string{"a"}, want: false},
		{name: "one key removed since it was loaded", stored: []storedRow{{1, "a"}}, expected: []string{"a", "b"}, want: false},
		{name: "one key replaced since it was loaded", stored: []storedRow{{1, "a"}, {2, "c"}}, expected: []string{"a", "b"}, want: false},
		{name: "a list loaded empty that is not any more", stored: []storedRow{{1, "a"}}, expected: []string{}, want: false},
		{name: "a list loaded full that is empty now", stored: nil, expected: []string{"a"}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, sameSet(test.stored, storedRowKey, test.expected))
		})
	}
}
