package brandkit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// A link is drawn with its label for the page's language, and with its fallback label in a language
// it has none for, a blank one or one no built-in catalog has included (#814 decision 5). The tag is
// the page's lang attribute, compared exactly.
func TestFooterLinkLabel(t *testing.T) {
	labels := map[string]string{"pt-BR": "Privacidade", "de": "Datenschutz", "fr": "  "}
	for _, tc := range []struct{ lang, want string }{
		{"pt-BR", "Privacidade"},
		{"de", "Datenschutz"},
		{"en", "Privacy"},
		{"es", "Privacy"},
		{"fr", "Privacy"},
		{"nl", "Privacy"},
		{"pt", "Privacy"},
		{"", "Privacy"},
	} {
		assert.Equal(t, tc.want, FooterLinkLabel("Privacy", labels, tc.lang), tc.lang)
	}
	assert.Equal(t, "Privacy", FooterLinkLabel("Privacy", nil, "de"), "a link with no labels")
}

// The address is the "to" of a mailto: URI, so what RFC 6068 section 2 says must be percent-encoded
// is: "%" above all, which an account's address may hold, the gen-delims but "@" and ":", "&", ";"
// and "=", and what cannot appear in a URI at all. The rest of an address is written as it stands.
func TestMailtoAddress(t *testing.T) {
	for _, tc := range []struct{ address, want string }{
		{"help@example.com", "help@example.com"},
		{"first.last+tag_1-x~y@sub.example.com", "first.last+tag_1-x~y@sub.example.com"},
		{"100%pure@example.com", "100%25pure@example.com"},
		{"a/b?c#d@example.com", "a%2Fb%3Fc%23d@example.com"},
		{"a&b;c=d@example.com", "a%26b%3Bc%3Dd@example.com"},
		{"[x]@example.com", "%5Bx%5D@example.com"},
		{"o'neil!$*@example.com", "o'neil!$*@example.com"},
		{"a b\"<c>@example.com", "a%20b%22%3Cc%3E@example.com"},
		{"josé@example.com", "jos%C3%A9@example.com"},
	} {
		assert.Equal(t, tc.want, MailtoAddress(tc.address), tc.address)
	}
}
