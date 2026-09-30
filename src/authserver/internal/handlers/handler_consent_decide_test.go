package handlers

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every answer a consent submission can get, and the one fact it loads. The handler cases show each
// answer reaching its act; which answer a submission gets is decided here (#437 seam 1).
func TestDecideConsentSubmission(t *testing.T) {
	held := func(scope string) *string { return &scope }

	testCases := []struct {
		name     string
		facts    consentSubmissionFacts
		want     consentSubmissionAnswer
		wantNeed consentSubmissionFact
	}{
		{
			name:  "a cancel is declined",
			facts: consentSubmissionFacts{approved: false},
			want:  consentSubmissionDeclined,
		},
		{
			// A cancel reads no permission, whatever arrived beside it.
			name:  "a cancel is declined even with scopes ticked and held",
			facts: consentSubmissionFacts{approved: false, ticked: []string{"openid"}, heldScope: held("openid")},
			want:  consentSubmissionDeclined,
		},
		{
			// Decided by what was consented to, not by whether a consent key arrived (#79).
			name:  "an approval ticking nothing is refused before any permission is read",
			facts: consentSubmissionFacts{approved: true, ticked: []string{}},
			want:  consentSubmissionNothingTicked,
		},
		{
			name:  "an approval with a nil selection is refused as ticking nothing",
			facts: consentSubmissionFacts{approved: true},
			want:  consentSubmissionNothingTicked,
		},
		{
			name:     "an approval ticking a scope asks for the held scope",
			facts:    consentSubmissionFacts{approved: true, ticked: []string{"openid"}},
			want:     consentSubmissionUndecided,
			wantNeed: consentSubmissionFactHeldScope,
		},
		{
			// #241 decision 3: a selection an administrator emptied is its own refusal.
			name:  "a selection the filter empties is refused as nothing held",
			facts: consentSubmissionFacts{approved: true, ticked: []string{"res:perm"}, heldScope: held("")},
			want:  consentSubmissionNothingHeld,
		},
		{
			name:  "a selection holding one scope is granted",
			facts: consentSubmissionFacts{approved: true, ticked: []string{"openid", "res:perm"}, heldScope: held("openid")},
			want:  consentSubmissionGranted,
		},
		{
			name:  "a selection holding every ticked scope is granted",
			facts: consentSubmissionFacts{approved: true, ticked: []string{"openid", "profile"}, heldScope: held("openid profile")},
			want:  consentSubmissionGranted,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, need := decideConsentSubmission(tc.facts)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantNeed, need)
		})
	}
}

// The submission's action, read from the body alone (#79).
func TestConsentApproved(t *testing.T) {
	testCases := []struct {
		name string
		form url.Values
		want bool
	}{
		{name: "the submit control approves", form: url.Values{"btnSubmit": {"submit"}}, want: true},
		{name: "the cancel control declines", form: url.Values{"btnCancel": {"cancel"}}, want: false},
		{name: "no control declines", form: url.Values{}, want: false},
		{name: "a submit control with another value declines", form: url.Values{"btnSubmit": {"yes"}}, want: false},
		{
			// No browser sends both; the ambiguity is refused rather than resolved towards granting.
			name: "both controls decline",
			form: url.Values{"btnSubmit": {"submit"}, "btnCancel": {"cancel"}},
			want: false,
		},
		{
			name: "an empty cancel key still declines",
			form: url.Values{"btnSubmit": {"submit"}, "btnCancel": {""}},
			want: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, consentApproved(tc.form))
		})
	}
}

// The ticked selection, matched by exact positional key (#79).
func TestTickedScopes(t *testing.T) {
	scopes := func(names ...string) []ScopeInfo {
		infos := make([]ScopeInfo, 0, len(names))
		for _, name := range names {
			infos = append(infos, ScopeInfo{Scope: name})
		}
		return infos
	}
	eleven := scopes("s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10")

	testCases := []struct {
		name   string
		form   url.Values
		scopes []ScopeInfo
		want   []string
	}{
		{name: "nothing ticked", form: url.Values{}, scopes: scopes("openid", "profile"), want: []string{}},
		{
			name:   "ticks come back in the ceremony's order",
			form:   url.Values{"consent1": {"on"}, "consent0": {"on"}},
			scopes: scopes("openid", "profile", "email"),
			want:   []string{"openid", "profile"},
		},
		{
			// strings.Contains found "consent1" inside "consent10" (#79).
			name:   "consent10 does not tick scope 1",
			form:   url.Values{"consent10": {"on"}},
			scopes: eleven,
			want:   []string{"s10"},
		},
		{
			name:   "a key past the list ticks nothing",
			form:   url.Values{"consent3": {"on"}},
			scopes: scopes("openid", "profile"),
			want:   []string{},
		},
		{
			name:   "a key of another shape ticks nothing",
			form:   url.Values{"consent": {"on"}, "consent01": {"on"}, "xconsent0": {"on"}},
			scopes: scopes("openid", "profile"),
			want:   []string{},
		},
		{
			// A present key ticks whatever its value, as the browser sends a checkbox's own value.
			name:   "an empty value still ticks",
			form:   url.Values{"consent0": {""}},
			scopes: scopes("openid"),
			want:   []string{"openid"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tickedScopes(tc.form, tc.scopes))
		})
	}
}

// When GET /auth/consent renders the screen rather than going on to issuance.
func TestConsentScreenOwed(t *testing.T) {
	consented := []ScopeInfo{{Scope: "openid", AlreadyConsented: true}, {Scope: "profile", AlreadyConsented: true}}
	partial := []ScopeInfo{{Scope: "openid", AlreadyConsented: true}, {Scope: "profile", AlreadyConsented: false}}

	testCases := []struct {
		name          string
		scopes        []ScopeInfo
		scope         string
		promptConsent bool
		want          bool
	}{
		{name: "everything already consented goes on", scopes: consented, scope: "openid profile", want: false},
		{name: "one scope not yet consented is shown", scopes: partial, scope: "openid profile", want: true},
		{
			name:   "offline_access is always re-confirmed",
			scopes: []ScopeInfo{{Scope: "openid", AlreadyConsented: true}, {Scope: "offline_access", AlreadyConsented: true}},
			scope:  "openid offline_access",
			want:   true,
		},
		{name: "prompt=consent forces the screen", scopes: consented, scope: "openid profile", promptConsent: true, want: true},
		{name: "an empty scope list is fully consented", scopes: []ScopeInfo{}, scope: "", want: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, consentScreenOwed(tc.scopes, tc.scope, tc.promptConsent))
		})
	}
}
