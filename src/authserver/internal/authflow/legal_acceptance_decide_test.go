package authflow

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLegalAcceptanceAccepted_OnlyTheAcceptButtonAlone(t *testing.T) {
	testCases := []struct {
		name string
		body url.Values
		want bool
	}{
		{"accept", url.Values{"btnAccept": {"accept"}}, true},
		{"decline", url.Values{"btnDecline": {"decline"}}, false},
		{"both buttons", url.Values{"btnAccept": {"accept"}, "btnDecline": {"decline"}}, false},
		{"neither button", url.Values{}, false},
		{"another value", url.Values{"btnAccept": {"yes"}}, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, legalAcceptanceAccepted(tc.body))
		})
	}
}

func TestSubmittedVersions_TheIdsTheBodyCarriesUnderTheName(t *testing.T) {
	body := url.Values{"legalDocument": {"12", "71", "x", "-3", "0", ""}, "shownVersion": {"12"}}
	assert.Equal(t, map[int64]bool{12: true, 71: true}, submittedVersions(body, "legalDocument"),
		"positive ids alone; anything else is no version")
	assert.Equal(t, map[int64]bool{12: true}, submittedVersions(body, "shownVersion"))
	assert.Empty(t, submittedVersions(body, "missing"))
}

func TestDecideLegalAcceptance(t *testing.T) {
	set := func(ids ...int64) map[int64]bool {
		out := map[int64]bool{}
		for _, id := range ids {
			out[id] = true
		}
		return out
	}
	testCases := []struct {
		name   string
		shown  map[int64]bool
		ticked map[int64]bool
		owed   []int64
		want   legalAcceptanceAnswer
	}{
		{"every version shown is ticked and owed", set(12, 71), set(12, 71), []int64{12, 71}, legalAcceptanceRecorded},
		{"one box left unticked", set(12, 71), set(12), []int64{12, 71}, legalAcceptanceUnticked},
		{"no box ticked", set(12, 71), set(), []int64{12, 71}, legalAcceptanceUnticked},
		{"a box ticked for a version not owed does not stand in for one owed", set(12, 71), set(12, 99), []int64{12, 71}, legalAcceptanceUnticked},
		{"a newer version published since the step was shown", set(12), set(12), []int64{13}, legalAcceptanceChanged},
		{"a document owed since the step was shown", set(12), set(12), []int64{12, 71}, legalAcceptanceChanged},
		{"a document no longer owed since the step was shown", set(12, 71), set(12, 71), []int64{12}, legalAcceptanceChanged},
		{"nothing shown, something owed", set(), set(), []int64{12}, legalAcceptanceChanged},
		{"nothing owed any more, accepted in another tab or retired", set(12), set(12), nil, legalAcceptanceNothingOwed},
		{"nothing owed, whatever was ticked", set(12), set(), nil, legalAcceptanceNothingOwed},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, decideLegalAcceptance(tc.shown, tc.ticked, tc.owed))
		})
	}
}
