package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestLogoutIdTokenHintPresent is the exhaustive table for the auth server's one conditional CSRF
// exemption. It lived in src/core/middleware until #385 moved the predicate here with the policy
// that names it; core keeps the matching mechanism and its own table is over fixture paths now,
// because core no longer declares a route.
//
// Every row is a POST unless it says otherwise, and each negative row names the gate meant to
// reject it: the method check, the exact-path binding the policy supplies, or the parameter lookup.
func TestLogoutIdTokenHintPresent(t *testing.T) {
	tests := []struct {
		name string
		// method defaults to POST.
		method string
		// target is the request target, so a row can put the hint in the query.
		target string
		// body is sent as application/x-www-form-urlencoded when set, which is how a relying party
		// serializes logout parameters into a POST per OIDC Core's Form Serialization.
		body string
		want bool
	}{
		// Both arrival routes, because an RP may put the parameter in the query or serialize it
		// into the body, and the handler reads both.
		{"a hint in the query", "", "/auth/logout?id_token_hint=abc", "", true},
		{"a hint in the body", "", "/auth/logout", "id_token_hint=abc", true},
		{"a hint in the query beside other parameters", "", "/auth/logout?state=x&id_token_hint=abc", "", true},

		// KEEP THIS PAIR. Its expected value reverses the naive reading, and it is the whole reason
		// the predicate and the handler share one extractor. The handler classifies "id_token_hint="
		// as a hint that was supplied and cannot be confirmed, so it asks the End-User. Were this to
		// read the same parameter as no hint at all, the exempted cross-site POST would take the
		// hintless branch instead, which is the confirmation of the consent page and tears the whole
		// session down without asking anybody (#109 decision 13).
		{"an empty hint in the query is still a hint", "", "/auth/logout?id_token_hint=", "", true},
		{"an empty hint in the body is still a hint", "", "/auth/logout", "id_token_hint=", true},

		// Absent, which is the shape the exemption must never cover: an unconditional entry would
		// let any site force a logout. Rejected by the parameter lookup.
		{"no parameters at all", "", "/auth/logout", "", false},
		{"only other parameters in the body", "", "/auth/logout", "state=abc&client_id=x", false},
		{"only other parameters in the query", "", "/auth/logout?state=abc", "", false},

		// Lookalikes, rejected by the parameter lookup: the name is matched exactly, not by prefix
		// and not case-insensitively.
		{"a suffixed parameter name in the query", "", "/auth/logout?id_token_hintx=abc", "", false},
		{"a suffixed parameter name in the body", "", "/auth/logout", "id_token_hint_x=abc", false},
		{"a prefixed parameter name", "", "/auth/logout?x_id_token_hint=abc", "", false},

		// Methods other than POST, rejected by the method check. GET is a safe method the origin
		// check never applies to, so exempting it would buy nothing; PUT and DELETE are checked and
		// neither is routed to logout, so exempting them would widen the hole for a route that
		// would have to be added deliberately.
		{"GET with a hint", http.MethodGet, "/auth/logout?id_token_hint=abc", "", false},
		{"PUT with a hint", http.MethodPut, "/auth/logout?id_token_hint=abc", "", false},
		{"DELETE with a hint", http.MethodDelete, "/auth/logout?id_token_hint=abc", "", false},
		{"HEAD with a hint", http.MethodHead, "/auth/logout?id_token_hint=abc", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method := tt.method
			if method == "" {
				method = http.MethodPost
			}
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(method, tt.target, body)
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			if got := LogoutIdTokenHintPresent(req); got != tt.want {
				t.Errorf("LogoutIdTokenHintPresent = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLogoutIdTokenHintPresent_LeavesTheBodyForTheHandler is the case #109 decision 9 names as the
// thing that has to be pinned: looking for the hint in a POST body means parsing the form in
// middleware, and a form parse consumes the request body.
//
// It survives because Go caches the parse in r.PostForm and r.Form, and the handler's r.FormValue
// reads the cache rather than the socket. If it ever stopped surviving, the logout handler would
// see a request with no ui_locales, no state and no post_logout_redirect_uri, which is a page in
// the wrong language and a redirect that silently does not happen, so this asserts the siblings and
// not only the hint itself.
func TestLogoutIdTokenHintPresent_LeavesTheBodyForTheHandler(t *testing.T) {
	body := url.Values{
		"id_token_hint":            {"a.b.c"},
		"post_logout_redirect_uri": {"https://rp.example/bye"},
		"state":                    {"opaque+value/=="},
		"ui_locales":               {"pt-BR"},
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if !LogoutIdTokenHintPresent(req) {
		t.Fatal("a POST carrying an id_token_hint in its body must be exempted")
	}

	for key, want := range body {
		if got := req.FormValue(key); got != want[0] {
			t.Errorf("the handler read %s = %q after the predicate parsed the body, want %q", key, got, want[0])
		}
	}
}

// TestLogoutIdTokenHintPresent_DoesNotParseTheBodyWhenTheQueryAnswers is the other half of the
// doc's claim that a hint in the query costs no parse. Without it, the ordering inside the shared
// extractor could be reversed and nothing here would notice.
//
// A body the form parser would reject outright is what makes the claim observable: if the predicate
// parsed it, r.PostForm would be populated with junk rather than left nil.
func TestLogoutIdTokenHintPresent_DoesNotParseTheBodyWhenTheQueryAnswers(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/auth/logout?id_token_hint=abc",
		strings.NewReader("this-is-not-a-form"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if !LogoutIdTokenHintPresent(req) {
		t.Fatal("a hint in the query must be enough")
	}
	if req.PostForm != nil {
		t.Errorf("the body was parsed although the query already answered: PostForm = %v", req.PostForm)
	}
}
