package commondb

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPickEmailSurvivor pins the rule that decides which of two rows spelling the same
// address keeps it: the member already equal to its own lowercased form, and the lowest id
// when no member qualifies (#221).
//
// It is a unit test because the rule is pure Go and engine-independent, and because the
// alternative rules it rejects are only distinguishable on a group whose lowercase member is
// NOT the oldest row, which is exactly the shape a deployment reaches by seeding a mixed-case
// GOIABADA_ADMIN_EMAIL first and creating a working account afterwards.
func TestPickEmailSurvivor(t *testing.T) {
	tests := []struct {
		name  string
		group []emailRow
		want  int64
		why   string
	}{
		{
			name:  "a single mixed-case row is its own survivor",
			group: []emailRow{{id: 2, email: "Dave@x.com", enabled: true}},
			want:  2,
			why:   "a group of one has nothing to lose the address to",
		},
		{
			name: "the lowercase member wins over an older mixed-case one",
			group: []emailRow{
				{id: 3, email: "Bob@x.com", enabled: true},
				{id: 4, email: "bob@x.com", enabled: true},
			},
			want: 4,
			why:  "id 4 is the row that signs in today; lowest-id-always would disable it and keep the one that cannot",
		},
		{
			name: "and the order it is offered in does not decide it",
			group: []emailRow{
				{id: 4, email: "bob@x.com", enabled: true},
				{id: 3, email: "Bob@x.com", enabled: true},
			},
			want: 4,
			why:  "the scan's row order is the engine's business, so the rule may not depend on it",
		},
		{
			name: "an all-mixed-case group falls back to the lowest id",
			group: []emailRow{
				{id: 6, email: "Erin@x.com", enabled: true},
				{id: 5, email: "ERIN@x.com", enabled: true},
			},
			want: 5,
			why:  "no member qualifies, and created_at is nullable on all four engines so it cannot be the tiebreak",
		},
		{
			name: "the lowercase test is Unicode-wide, not ASCII-only",
			group: []emailRow{
				{id: 7, email: "Ädmin@x.com", enabled: true},
				{id: 8, email: "ädmin@x.com", enabled: true},
			},
			want: 8,
			why:  "an ASCII-only fold reads Ädmin@x.com as already lowercase and hands it the address",
		},
		{
			name: "a disabled row can still be the survivor",
			group: []emailRow{
				{id: 9, email: "Frank@x.com", enabled: true},
				{id: 10, email: "frank@x.com", enabled: false},
			},
			want: 10,
			why:  "an administrator disabled that account deliberately; the backfill re-enables nothing and hands the address back to it rather than to one that never worked",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pickEmailSurvivor(tc.group)
			if got.id != tc.want {
				t.Errorf("pickEmailSurvivor() = id %d, want id %d: %s", got.id, tc.want, tc.why)
			}
		})
	}
}

// readEmailGroup's candidate list is the only one in commondb whose IN term shares a WHERE with
// another predicate, so the batching had a choice to make and these two cases are the choice:
// the address term rides in every statement, and a row two statements both answer is kept once.
//
// It has no data tier case, unlike the twelve lookups in id_list_batching_test.go, because its
// list is the users whose address differs from another only by case and a group past the budget
// would need that many accounts. The statement shape is the other lookups', so what the four
// engines have to say about a long IN list is already said there; what is this function's own is
// below (#373).
func TestReadEmailGroup_ReadsALongCandidateListInBatches(t *testing.T) {
	candidates := make([]int64, maxIdsPerStatement+1)
	for i := range candidates {
		// The lowercase row is id 1 and is not a candidate: the opening scan keeps only rows that
		// differ from their own lowercase form, which is what the address term exists to add back.
		candidates[i] = int64(i + 2)
	}

	d := &scriptedDriver{rows: []*scriptedRows{
		// First statement: the address term answers the lowercase row, and this batch's ids
		// answer one candidate.
		groupResult(groupRow(1, "alice@x.com", true), groupRow(2, "Alice@x.com", true)),
		// Second statement: the address term answers the same row again, which is what the
		// deduplication is for, plus the one candidate the first batch could not carry.
		groupResult(groupRow(1, "alice@x.com", true), groupRow(int64(maxIdsPerStatement+2), "ALICE@x.com", true)),
	}}

	members, err := scriptedDB(t, d).readEmailGroup("alice@x.com", candidates)
	require.NoError(t, err)

	assert.Equal(t, 2, d.queryCount, "a candidate list one past the budget is read in two statements")

	ids := make([]int64, 0, len(members))
	for _, member := range members {
		ids = append(ids, member.id)
	}
	assert.Equal(t, []int64{1, 2, int64(maxIdsPerStatement + 2)}, ids,
		"the row both statements answered is kept once, and every other member once each")
}

// An empty candidate list still has to ask for the row already spelled in lowercase. The helper
// calls its function zero times for an empty list, so that statement is issued outside it; a
// version that left it to the helper would answer that the group is empty and converge nothing.
func TestReadEmailGroup_AnEmptyCandidateListStillAsksForTheLowercaseRow(t *testing.T) {
	d := &scriptedDriver{rows: []*scriptedRows{
		groupResult(groupRow(1, "alice@x.com", true)),
	}}

	members, err := scriptedDB(t, d).readEmailGroup("alice@x.com", nil)
	require.NoError(t, err)

	assert.Equal(t, 1, d.queryCount, "exactly one statement, and never an empty IN ()")
	require.Len(t, members, 1)
	assert.Equal(t, int64(1), members[0].id)
}
