package render

import (
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderEmail renders one email template for a recipient whose context carries
// a single preference locale, the way the email handlers attach it
// (i18n.WithLocale(ctx, true, user.Locale, "en") in every sender). The layout
// prints the content block, so the body asserts which copy was chosen.
func renderEmail(t *testing.T, templateFS fstest.MapFS, locale string) (string, error) {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
	if locale != "" {
		req = req.WithContext(i18n.WithLocale(req.Context(), true, locale))
	}
	buf, err := New(templateFS).RenderTemplateToBuffer(req, "layouts/email_layout.html", "emails/note.html", nil)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// An email body is picked like the catalog is picked, not by the literal tag the
// context was given. A recipient whose locale is a regional variant of a
// template copy's language gets that copy's body: es-MX resolves to the .es
// copy the same way the subject resolves to the es catalog (#531).
func TestRenderTemplateToBuffer_EmailLocaleFallsBackToTheBaseLanguage(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/email_layout.html": {Data: []byte(`{{template "content" .}}`)},
		"emails/note.html":          {Data: []byte(`{{define "content"}}the english body{{end}}`)},
		"emails/note.es.html":       {Data: []byte(`{{define "content"}}the spanish body{{end}}`)},
	}

	body, err := renderEmail(t, templateFS, "es-MX")

	require.NoError(t, err)
	assert.Contains(t, body, "the spanish body")
	assert.NotContains(t, body, "the english body")
}

// A copy for exactly the request's tag wins over the base language, so an
// operator who ships an es-MX body for es-MX recipients is honoured.
func TestRenderTemplateToBuffer_EmailLocaleExactCopyWinsOverTheBaseLanguage(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/email_layout.html": {Data: []byte(`{{template "content" .}}`)},
		"emails/note.html":          {Data: []byte(`{{define "content"}}the english body{{end}}`)},
		"emails/note.es.html":       {Data: []byte(`{{define "content"}}the spanish body{{end}}`)},
		"emails/note.es-MX.html":    {Data: []byte(`{{define "content"}}the mexican body{{end}}`)},
	}

	body, err := renderEmail(t, templateFS, "es-MX")

	require.NoError(t, err)
	assert.Contains(t, body, "the mexican body")
	assert.NotContains(t, body, "the spanish body")
	assert.NotContains(t, body, "the english body")
}

// No template copy matching the recipient's language at all leaves the English
// base template, which is also what the catalog matcher would answer: a locale
// the catalogs do not carry resolves to the English catalog.
func TestRenderTemplateToBuffer_EmailLocaleUnmatchedFallsBackToEnglish(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/email_layout.html": {Data: []byte(`{{template "content" .}}`)},
		"emails/note.html":          {Data: []byte(`{{define "content"}}the english body{{end}}`)},
		"emails/note.pt-BR.html":    {Data: []byte(`{{define "content"}}the brazilian body{{end}}`)},
	}

	body, err := renderEmail(t, templateFS, "es-MX")

	require.NoError(t, err)
	assert.Contains(t, body, "the english body")
	assert.NotContains(t, body, "the brazilian body")
}

// The exact-tag lookup the renderer always had keeps working, and an English
// recipient never changes shape: "en" is the base file, which stays served for
// every locale that resolves to English.
func TestRenderTemplateToBuffer_EmailLocaleExactAndEnglish(t *testing.T) {
	exactFS := fstest.MapFS{
		"layouts/email_layout.html": {Data: []byte(`{{template "content" .}}`)},
		"emails/note.html":          {Data: []byte(`{{define "content"}}the english body{{end}}`)},
		"emails/note.pt-BR.html":    {Data: []byte(`{{define "content"}}the brazilian body{{end}}`)},
	}

	t.Run("an exact copy is still chosen", func(t *testing.T) {
		body, err := renderEmail(t, exactFS, "pt-BR")
		require.NoError(t, err)
		assert.Contains(t, body, "the brazilian body")
	})

	t.Run("an en-GB recipient gets the English base file", func(t *testing.T) {
		body, err := renderEmail(t, exactFS, "en-GB")
		require.NoError(t, err)
		assert.Contains(t, body, "the english body")
	})

	t.Run("an en recipient gets the English base file", func(t *testing.T) {
		body, err := renderEmail(t, exactFS, "en")
		require.NoError(t, err)
		assert.Contains(t, body, "the english body")
	})

	t.Run("a request with no locale gets the English base file", func(t *testing.T) {
		body, err := renderEmail(t, exactFS, "")
		require.NoError(t, err)
		assert.Contains(t, body, "the english body")
	})
}

// A language that is a base-language match rather than an exact tag also takes
// the copy, because the catalog matcher accepts the same match for the subject:
// a pt recipient's subject comes from the pt-BR catalog, so the body follows.
func TestRenderTemplateToBuffer_EmailLocaleBaseLanguageRequest(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/email_layout.html": {Data: []byte(`{{template "content" .}}`)},
		"emails/note.html":          {Data: []byte(`{{define "content"}}the english body{{end}}`)},
		"emails/note.pt-BR.html":    {Data: []byte(`{{define "content"}}the brazilian body{{end}}`)},
	}

	body, err := renderEmail(t, templateFS, "pt")

	require.NoError(t, err)
	assert.Contains(t, body, "the brazilian body")
	assert.NotContains(t, body, "the english body")
}

// Nothing outside emails/ is localized by this lookup, so a page named like an
// email copy is unaffected: the renderer only rewrites template names under
// emails/ (#531, and the console's twin is covered by its own test).
func TestRenderTemplateToBuffer_EmailLocaleDoesNotTouchOtherPages(t *testing.T) {
	templateFS := fstest.MapFS{
		"layouts/email_layout.html": {Data: []byte(`{{template "content" .}}`)},
		"page.html":                 {Data: []byte(`{{define "content"}}the page body{{end}}`)},
		"page.es.html":              {Data: []byte(`{{define "content"}}never rendered{{end}}`)},
	}

	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "es-MX"))

	buf, err := New(templateFS).RenderTemplateToBuffer(req, "layouts/email_layout.html", "page.html", nil)

	require.NoError(t, err)
	assert.Contains(t, buf.String(), "the page body")
	assert.NotContains(t, buf.String(), "never rendered")
}
