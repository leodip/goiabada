package render

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/core/api"
)

// UserFullName and SessionOwnerFullName write the same three name parts from two different wire
// shapes, and both call core/personname rather than spelling a join out of their own. The table is
// driven through both so the delegation is proven from each side: the case that would expose a
// join of their own is a user with a missing part, where a naive `given + " " + middle + " " +
// family` yields a doubled space (#373), and a name in kanji, which core/personname writes family
// name first (#662).
func TestFullNames_JoinTheSamePartsFromBothShapes(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		givenName, middleName, familyName string
		want                              string
	}{
		{"all three", "Jane", "Q", "Doe", "Jane Q Doe"},
		{"no middle name", "Jane", "", "Doe", "Jane Doe"},
		{"given name only", "Jane", "", "", "Jane"},
		{"family name only", "", "", "Doe", "Doe"},
		{"middle name only", "", "Q", "", "Q"},
		{"nothing at all", "", "", "", ""},
		// core/personname writes it: a name in kanji family name first, with no space (#662).
		{"a name in kanji", "太郎", "", "山田", "山田太郎"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, UserFullName(&api.UserResponse{
				GivenName: tc.givenName, MiddleName: tc.middleName, FamilyName: tc.familyName,
			}))
			assert.Equal(t, tc.want, SessionOwnerFullName(&api.SessionOwnerResponse{
				GivenName: tc.givenName, MiddleName: tc.middleName, FamilyName: tc.familyName,
			}))
		})
	}
}

// Both answer the empty string for a nil record rather than panicking: the client sessions page
// looks its owner up in a map and a session whose owner is absent must leave the cell blank, not
// take the page down.
func TestFullNames_NilRecordIsEmpty(t *testing.T) {
	assert.Empty(t, UserFullName(nil))
	assert.Empty(t, SessionOwnerFullName(nil))
}
