package ceremony

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The id's shape is what the registration page relies on to echo one back into a link, so the table
// holds each way a value can fail it, varying one thing from an id that passes (#246, #437 seam 1).

func TestNewId_IsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id := NewId()
		assert.Len(t, id, IdLength)
		assert.True(t, IsWellFormedId(id), "an id NewId drew must satisfy the shape check: %q", id)
		assert.False(t, seen[id], "two draws produced the same id")
		seen[id] = true
	}
}

func TestIsWellFormedId(t *testing.T) {
	valid := strings.Repeat("a", IdLength)

	testCases := []struct {
		name string
		id   string
		want bool
	}{
		{"an id at the length", valid, true},
		{"digits and lowercase", "0123456789abcdefghijklmnopqrstuv", true},
		{"uppercase and the three punctuation characters", "ABCDEFGHIJKLMNOPQRSTUVWXYZ-_.012", true},
		{"empty", "", false},
		{"one character short", valid[:IdLength-1], false},
		{"one character over", valid + "a", false},
		{"far over", strings.Repeat("a", 4*IdLength), false},
		{"a space in place of a character", valid[:IdLength-1] + " ", false},
		{"a slash", valid[:IdLength-1] + "/", false},
		{"a percent sign", valid[:IdLength-1] + "%", false},
		{"a quote", valid[:IdLength-1] + `"`, false},
		{"an angle bracket", valid[:IdLength-1] + "<", false},
		{"a newline", valid[:IdLength-1] + "\n", false},
		{"a NUL", valid[:IdLength-1] + "\x00", false},
		// Two bytes each, so the byte length is right and every byte is outside the alphabet.
		{"a multibyte character at the byte length", strings.Repeat("é", IdLength/2), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsWellFormedId(tc.id))
		})
	}
}

// RequestedId is a pure function of the request's method and its two sources, so its table pins which
// source counts for which method and nothing else (#437 seam 1). Every reader of the ceremony a
// request names reads it through here: the step boundary and the one-time-code rate limit.
func TestRequestedId(t *testing.T) {
	testCases := []struct {
		name    string
		method  string
		inQuery string
		inForm  string
		want    string
	}{
		{"a GET reads the URL's parameter", http.MethodGet, "from-the-url", "", "from-the-url"},
		{"a GET with no parameter names nothing", http.MethodGet, "", "", ""},
		{"a POST reads the body's field", http.MethodPost, "", "from-the-form", "from-the-form"},
		{"a POST ignores the URL's parameter", http.MethodPost, "from-the-url", "", ""},
		{"a POST prefers nothing from the URL over the body", http.MethodPost, "from-the-url", "from-the-form", "from-the-form"},
		// Any method that is not a POST reads the URL, so a HEAD asking for a step is judged as the GET is.
		{"a HEAD reads the URL's parameter", http.MethodHead, "from-the-url", "", "from-the-url"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RequestedId(namingRequest(tc.method, nil, tc.inQuery, tc.inForm)))
		})
	}

	t.Run("the form field's name in the URL is not the URL's parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/pwd?"+IdField+"=a-ceremony", nil)
		assert.Empty(t, RequestedId(req),
			"the two names differ on purpose, so a URL can never be spelled as the field")
	})

	t.Run("a repeated parameter reads the first copy", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/pwd?ceremony=first&ceremony=second", nil)
		assert.Equal(t, "first", RequestedId(req))
	})
}

// The whole comparison table for the ceremony binding. The function is pure, so the table costs
// nothing and every reader then needs only one accept and one reject (#79 seam 3).
func TestIdMatches(t *testing.T) {
	const stored = "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"

	testCases := []struct {
		name  string
		named string
		held  string
		want  bool
	}{
		{name: "Equal ids", held: stored, named: stored, want: true},
		{name: "Different ids of the same length", held: stored, named: "543210ZyXwVuTsRqPoNmLkJiHgFeDcBa"},
		// The upgrade case. An auth context written before #79 carries no id, and matching "" against
		// "" would make it accept a request naming no ceremony at all.
		{name: "Empty stored id against an empty name", held: "", named: ""},
		{name: "Empty stored id against a real name", held: "", named: stored},
		// What an absent form field looks like: r.PostFormValue answers "".
		{name: "Real stored id against an absent name", held: stored, named: ""},
		{name: "Near miss, one byte differs", held: stored, named: "aBcDeFgHiJkLmNoPqRsTuVwXyZ012346"},
		// A prefix must not match, which is the family of defect #79 is about: the consent selection
		// granted a scope because "consent1" was a prefix of "consent10".
		{name: "Near miss, the name is a prefix of the stored id", held: stored, named: stored[:len(stored)-1]},
		{name: "Near miss, the name extends the stored id", held: stored, named: stored + "x"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, idMatches(tc.held, tc.named))
		})
	}
}
