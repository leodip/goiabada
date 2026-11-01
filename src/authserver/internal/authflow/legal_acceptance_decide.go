package authflow

import (
	"net/url"
	"strconv"
)

// The form fields of the acceptance step. Each document's checkbox carries the id of the version
// shown, and a hidden field carries every version shown, so the submission says which versions the
// user saw and which boxes they ticked (#622).
const (
	legalAcceptanceTickedField = "legalDocument"
	legalAcceptanceShownField  = "shownVersion"
)

// legalAcceptanceAccepted reports whether the submitted body is the Accept button alone. Anything
// else, Decline, both buttons or neither, is a decline, as the consent screen reads its own: a
// submission that does not plainly accept accepts nothing.
//
// It takes the body alone: a crafted /auth/legal-acceptance?btnAccept=accept must not count.
func legalAcceptanceAccepted(body url.Values) bool {
	return body.Get("btnAccept") == "accept" && !body.Has("btnDecline")
}

// submittedVersions answers the version ids the body carries under name. A value that is not a
// positive id names no version and is left out.
func submittedVersions(body url.Values, name string) map[int64]bool {
	versions := map[int64]bool{}
	for _, value := range body[name] {
		id, err := strconv.ParseInt(value, 10, 64)
		if err == nil && id > 0 {
			versions[id] = true
		}
	}
	return versions
}

// legalAcceptanceAnswer is how an Accept submission of the step is answered.
type legalAcceptanceAnswer int

const (
	// legalAcceptanceNothingOwed: nothing is owed any more (accepted in another tab, retired, or
	// taken off the app), so the ceremony goes on and nothing is recorded.
	legalAcceptanceNothingOwed legalAcceptanceAnswer = iota
	// legalAcceptanceChanged: what is owed is not what was shown, a newer version published or a
	// document added or removed meanwhile, so the step is shown again and nothing is recorded.
	legalAcceptanceChanged
	// legalAcceptanceUnticked: a box was left unticked, so the step is shown again with an error
	// and nothing is recorded.
	legalAcceptanceUnticked
	// legalAcceptanceRecorded: every version owed was shown and ticked, and is recorded.
	legalAcceptanceRecorded
)

// decideLegalAcceptance decides an Accept submission from the versions the step showed, the boxes
// ticked, and the current versions owed now. The versions recorded are the ones shown, which are
// the ones owed now, or the step is shown again (#622: "the step records the version it showed").
func decideLegalAcceptance(shown, ticked map[int64]bool, owed []int64) legalAcceptanceAnswer {
	if len(owed) == 0 {
		return legalAcceptanceNothingOwed
	}
	if len(shown) != len(owed) {
		return legalAcceptanceChanged
	}
	for _, versionId := range owed {
		if !shown[versionId] {
			return legalAcceptanceChanged
		}
	}
	for _, versionId := range owed {
		if !ticked[versionId] {
			return legalAcceptanceUnticked
		}
	}
	return legalAcceptanceRecorded
}
