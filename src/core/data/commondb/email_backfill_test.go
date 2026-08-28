package commondb

import "testing"

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
