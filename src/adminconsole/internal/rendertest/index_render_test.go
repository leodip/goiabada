package rendertest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The console's home page through the real renderer, in pt-BR, with and without the notice an
// admin API 401 leaves for it (#427 decision 17, seam 7). HandleIndexGet's own tests assert when it
// binds SessionEnded; this is what the bind renders to.
func TestRender_IndexPage_TheSessionEndedNotice(t *testing.T) {
	const notice = "Seu acesso terminou. Entre novamente."

	testCases := []struct {
		name         string
		sessionEnded bool
	}{
		{name: "with the notice", sessionEnded: true},
		{name: "without it", sessionEnded: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderWithLayout(t, "/layouts/no_menu_layout.html", "/index.html", map[string]interface{}{
				"AuthServerBaseUrl": "https://auth.example",
				"IsAuthenticated":   false,
				"LoggedInUser":      "",
				"LogoutLink":        "",
				"SessionEnded":      tc.sessionEnded,
			})

			if tc.sessionEnded {
				assert.Contains(t, out, notice)
			} else {
				assert.NotContains(t, out, notice)
			}
		})
	}
}
