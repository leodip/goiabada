package authflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/i18n"
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

func TestBuildScopeInfoArray(t *testing.T) {
	t.Run("Empty scope", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "", nil)
		assert.Empty(t, result)
	})

	t.Run("Single ID token scope", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "openid", nil)
		assert.Len(t, result, 1)
		assert.Equal(t, ScopeInfo{
			Scope:            "openid",
			Description:      "Identify you by an ID unique to your account",
			AlreadyConsented: false,
		}, result[0])
	})

	t.Run("Multiple ID token scopes", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "openid profile email", nil)
		assert.Len(t, result, 3)
		assert.Equal(t, ScopeInfo{
			Scope:            "openid",
			Description:      "Identify you by an ID unique to your account",
			AlreadyConsented: false,
		}, result[0])
		assert.Equal(t, ScopeInfo{
			Scope:            "profile",
			Description:      "Your profile: name, nickname, username, picture, website, gender, birth date, time zone and language",
			AlreadyConsented: false,
		}, result[1])
		assert.Equal(t, ScopeInfo{
			Scope:            "email",
			Description:      "Your email address, and whether it's verified",
			AlreadyConsented: false,
		}, result[2])
	})

	t.Run("Offline access scope", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "openid offline_access", nil)
		assert.Len(t, result, 2)
		assert.Equal(t, ScopeInfo{
			Scope:            "offline_access",
			Description:      "Keep access while you're away, without asking you again",
			AlreadyConsented: false,
		}, result[1])
	})

	t.Run("Custom scope", func(t *testing.T) {
		result := buildScopeInfoArray(context.Background(), "openid custom:read", nil)
		assert.Len(t, result, 2)
		assert.Equal(t, ScopeInfo{
			Scope:            "custom:read",
			Description:      "Permission read on resource custom",
			AlreadyConsented: false,
		}, result[1])
	})

	t.Run("With existing consent", func(t *testing.T) {
		consent := &record.UserConsent{
			Scope: "openid profile",
		}
		result := buildScopeInfoArray(context.Background(), "openid profile email", consent)
		assert.Len(t, result, 3)
		assert.True(t, result[0].AlreadyConsented)
		assert.True(t, result[1].AlreadyConsented)
		assert.False(t, result[2].AlreadyConsented)
	})

	t.Run("Mixed scopes with consent", func(t *testing.T) {
		consent := &record.UserConsent{
			Scope: "openid custom:read",
		}
		result := buildScopeInfoArray(context.Background(), "openid profile custom:read custom:write", consent)
		assert.Len(t, result, 4)
		assert.True(t, result[0].AlreadyConsented)
		assert.False(t, result[1].AlreadyConsented)
		assert.True(t, result[2].AlreadyConsented)
		assert.False(t, result[3].AlreadyConsented)
	})

	// Guards §6.9: consent scope descriptions (OIDC scopes and the
	// resource-permission template) must localize to the active locale, not
	// render hardcoded English.
	t.Run("Localizes descriptions in pt-BR", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/consent", nil)
		req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))

		result := buildScopeInfoArray(req.Context(), "openid offline_access custom:read", nil)
		assert.Len(t, result, 3)
		assert.Equal(t, "Identificar você por um ID exclusivo da sua conta", result[0].Description)
		assert.Equal(t, "Manter o acesso enquanto você estiver ausente, sem pedir de novo", result[1].Description)
		assert.Equal(t, "Permissão read no recurso custom", result[2].Description)
	})
}
