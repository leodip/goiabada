package renderintegration

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An Account page and a card carry their data-page value on <body>, the value the styling
// contract lists for them, in both layouts; an admin page, outside the contract, carries none
// (#816 decisions 6 and 7).

var bodyTagRe = regexp.MustCompile(`<body[^>]*>`)

func TestRender_AConsolePageInTheContractCarriesItsDataPageOnBody(t *testing.T) {
	for _, tc := range []struct {
		layout, page string
		bind         map[string]interface{}
		want         string
	}{
		{consoleLayouts[0].layout, consoleLayouts[0].page, consoleLayouts[0].bind, "account-phone"},
		{"/layouts/no_menu_layout.html", "/account_logout_confirm.html", nil, "console-sign-out"},
		{"/layouts/no_menu_layout.html", "/not_found.html", nil, "console-not-found"},
	} {
		t.Run(tc.page, func(t *testing.T) {
			out := renderWithLayout(t, tc.layout, tc.page, tc.bind)

			body := bodyTagRe.FindString(out)
			require.NotEmpty(t, body, "the page has no body element")
			assert.Equal(t, `<body data-page="`+tc.want+`">`, body)
		})
	}
}

func TestRender_AnAdminPageCarriesNoDataPage(t *testing.T) {
	out := renderMenuPage(t, "/admin_users_phone.html", phoneBind())

	assert.Equal(t, "<body>", bodyTagRe.FindString(out))
}
