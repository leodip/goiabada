package render

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Every page of the auth server carries its data-page value on <body>, the value the styling
// contract lists for it, in both layouts its pages are drawn in (#816 decision 7).
func TestRender_APageCarriesItsDataPageOnBody(t *testing.T) {
	for _, tc := range []struct {
		layout, page, want string
	}{
		{"/layouts/auth_layout.html", "/logged_out.html", "signed-out"},
		{"/layouts/auth_layout.html", "/logout_declined.html", "sign-out-declined"},
		{"/layouts/no_menu_layout.html", "/not_found.html", "not-found"},
		{"/layouts/no_menu_layout.html", "/error.html", "error"},
	} {
		t.Run(tc.page, func(t *testing.T) {
			doc := renderFooterPage(t, tc.layout, tc.page, "", &defaultBrandStub{})

			body := doc.Find("body")
			value, ok := body.Attr("data-page")
			assert.True(t, ok, "<body> carries no data-page")
			assert.Equal(t, tc.want, value)
		})
	}
}
