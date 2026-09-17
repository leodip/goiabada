package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/core/api"
)

// UserFullName and SessionOwnerFullName join the same three name parts from two different wire
// shapes, and they delegate to one helper rather than spelling the join out twice. The table is
// driven through both so the delegation is proven from each side: a fourth hand-written copy is
// what this file exists to keep from appearing, and the case that would expose one is a user
// with a missing part, where a naive `given + " " + middle + " " + family` yields a doubled
// space (#373).
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
	assert.Equal(t, "", UserFullName(nil))
	assert.Equal(t, "", SessionOwnerFullName(nil))
}
