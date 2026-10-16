package render

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderEmail renders one email template for a recipient whose context carries
// the locale the way the five stored-locale senders attach it,
// i18n.WithLocale(ctx, true, user.Locale, "en") (forgot password, the
// existing-account registration notice, the email change, email verification
// and the admin's user creation). The two other registration senders attach the
// page's first tag alone, which renderEmailFirstTagOnly reproduces. The layout
// prints the content block, so the body asserts which copy was chosen.
func renderEmail(t *testing.T, templateFS fstest.MapFS, locale string) (string, error) {
	t.Helper()
	if locale == "" {
		return renderEmailWithTags(t, templateFS)
	}
	return renderEmailWithTags(t, templateFS, locale, "en")
}

// renderEmailFirstTagOnly attaches the locale alone, with no English fallback,
// the way the registration confirmation and activation senders attach the
// page's first tag.
func renderEmailFirstTagOnly(t *testing.T, templateFS fstest.MapFS, locale string) (string, error) {
	t.Helper()
	return renderEmailWithTags(t, templateFS, locale)
}

func renderEmailWithTags(t *testing.T, templateFS fstest.MapFS, tags ...string) (string, error) {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
	if len(tags) > 0 {
		req = req.WithContext(i18n.WithLocale(req.Context(), true, tags...))
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

// A copy the matcher can only guess at, in another language or another script,
// or a stray file whose suffix happens to parse as a language tag (.bak is
// Bashkir, .new Newari), is never sent in place of the English body. Without
// the English fallback the matcher answers sr for ru, uk and bg at confidence
// No, the .bak file for ru and bg, the .new file for hi, and Simplified Chinese
// for zh-TW (#531).
func TestRenderTemplateToBuffer_EmailLocaleUnrelatedCopyKeepsEnglish(t *testing.T) {
	cases := []struct{ suffix, locale string }{
		{"sr", "ru"},
		{"sr", "uk"},
		{"sr", "bg"},
		{"bak", "ru"},
		{"bak", "bg"},
		{"new", "hi"},
		{"zh", "zh-TW"},
	}
	senders := []struct {
		name   string
		render func(*testing.T, fstest.MapFS, string) (string, error)
	}{
		{"stored locale with en", renderEmail},
		{"first tag only", renderEmailFirstTagOnly},
	}
	for _, sender := range senders {
		for _, tc := range cases {
			t.Run(sender.name+"/"+tc.suffix+" for "+tc.locale, func(t *testing.T) {
				templateFS := fstest.MapFS{
					"layouts/email_layout.html":          {Data: []byte(`{{template "content" .}}`)},
					"emails/note.html":                   {Data: []byte(`{{define "content"}}the english body{{end}}`)},
					"emails/note." + tc.suffix + ".html": {Data: []byte(`{{define "content"}}another copy{{end}}`)},
				}

				body, err := sender.render(t, templateFS, tc.locale)

				require.NoError(t, err)
				assert.Equal(t, "the english body", body)
			})
		}
	}
}

// The body is in the language the subject is: with operator catalogs and
// copies for the same languages, the copy rendered for a stored-locale sender
// is the catalog i18n.T renders the subject from. A same-language recipient
// gets that language for both (es-MX takes es, pt and pt-PT take pt-BR), and a
// recipient the catalogs only relate to another language by a guess gets
// English for both (eu and gl near es, ru and uk near sr) (#531).
func TestRenderTemplateToBuffer_EmailBodyFollowsTheSubjectCatalog(t *testing.T) {
	overrides := t.TempDir()
	catalogs := filepath.Join(overrides, "catalogs")
	require.NoError(t, os.Mkdir(catalogs, 0o755))
	templateFS := fstest.MapFS{
		"layouts/email_layout.html": {Data: []byte(`{{template "content" .}}`)},
		"emails/note.html":          {Data: []byte(`{{define "content"}}en{{end}}`)},
		"emails/note.pt-BR.html":    {Data: []byte(`{{define "content"}}pt-BR{{end}}`)},
	}
	for _, lang := range []string{"es", "sr"} {
		require.NoError(t, os.WriteFile(filepath.Join(catalogs, "active."+lang+".toml"),
			[]byte("\"email.forgot_password.subject\" = \"subject\"\n"), 0o600))
		templateFS["emails/note."+lang+".html"] = &fstest.MapFile{Data: []byte(`{{define "content"}}` + lang + `{{end}}`)}
	}
	require.NoError(t, i18n.LoadBundle(overrides))
	t.Cleanup(func() { require.NoError(t, i18n.LoadBundle("")) })

	for _, tc := range []struct{ locale, want string }{
		{"es-MX", "es"},
		{"pt", "pt-BR"},
		{"pt-PT", "pt-BR"},
		{"eu", "en"},
		{"gl", "en"},
		{"ru", "en"},
		{"uk", "en"},
	} {
		t.Run(tc.locale, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req = req.WithContext(reqctx.WithSettings(req.Context(), &record.Settings{}))
			req = req.WithContext(i18n.WithLocale(req.Context(), true, tc.locale, "en"))

			buf, err := New(templateFS).RenderTemplateToBuffer(req, "layouts/email_layout.html", "emails/note.html", nil)

			require.NoError(t, err)
			require.Equal(t, tc.want, i18n.CatalogTag(req.Context()), "the subject's catalog")
			assert.Equal(t, i18n.CatalogTag(req.Context()), buf.String(), "the body's copy")
		})
	}
}
