package emaildelivery

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/emailtemplate"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/i18n"
)

// Every message is sent as two parts, the plain text and the HTML, the text worked out of the HTML
// by the sender (#817 decisions 9 and 10).

// sentPart is one part of a multipart message as it crossed the wire: its header, its bytes as
// written, and its content decoded from quoted-printable, with each CRLF read back as LF.
type sentPart struct {
	header  textproto.MIMEHeader
	raw     string
	decoded string
}

// alternativeParts takes a sent message apart as a multipart/alternative one, answering its
// boundary and its parts in the order they were written.
func alternativeParts(t *testing.T, m sentMessage) (string, []sentPart) {
	t.Helper()

	mediaType, params, err := mime.ParseMediaType(m.headers["Content-Type"])
	require.NoError(t, err, "the Content-Type %q does not parse", m.headers["Content-Type"])
	require.Equal(t, "multipart/alternative", mediaType)
	boundary := params["boundary"]
	require.NotEmpty(t, boundary, "a multipart message names its boundary")

	reader := multipart.NewReader(strings.NewReader(m.body), boundary)
	var parts []sentPart
	for {
		part, err := reader.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		raw, err := io.ReadAll(part)
		require.NoError(t, err)
		decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(string(raw))))
		require.NoError(t, err, "a part is quoted-printable")
		parts = append(parts, sentPart{
			header:  part.Header,
			raw:     string(raw),
			decoded: strings.ReplaceAll(string(decoded), "\r\n", "\n"),
		})
	}
	return boundary, parts
}

// textOf sends html as an email's body and answers the plain text the message carries.
func textOf(t *testing.T, html string) string {
	t.Helper()
	_, parts := alternativeParts(t, send(t, "Goiabada", &SendEmailInput{To: fixtureRecipient, Subject: "Test email", HtmlBody: html}))
	require.Len(t, parts, 2)
	return parts[0].decoded
}

// RFC 2046 section 5.1.4: a sender places the parts in increasing order of preference, the
// plainest format first and the richest last. Both are UTF-8, and quoted-printable as the HTML has
// been, so no line can outgrow RFC 5322's limit and the message stays 7-bit.
func TestSendEmail_AMessageIsItsTextThenItsHTML(t *testing.T) {
	html := "<p>Olá, Ana</p>\n<p>A line with a dot\n.\nat the start</p>"

	m := send(t, "Goiabada", &SendEmailInput{To: fixtureRecipient, Subject: "Test email", HtmlBody: html})
	_, parts := alternativeParts(t, m)

	require.Len(t, parts, 2, "the text and the HTML")
	assert.Equal(t, "text/plain; charset=UTF-8", parts[0].header.Get("Content-Type"), "the text comes first")
	assert.Equal(t, "quoted-printable", parts[0].header.Get("Content-Transfer-Encoding"))
	assert.Equal(t, "text/html; charset=UTF-8", parts[1].header.Get("Content-Type"), "the HTML comes last")
	assert.Equal(t, "quoted-printable", parts[1].header.Get("Content-Transfer-Encoding"))

	assert.Equal(t, "Olá, Ana\n\nA line with a dot . at the start\n", parts[0].decoded)
	assert.Contains(t, parts[0].raw, "Ol=C3=A1, Ana", "the text is UTF-8, quoted-printable")
	assert.Equal(t, html, parts[1].decoded, "the HTML is sent as it was given")

	for i := 0; i < len(m.body); i++ {
		if m.body[i] > 0x7e || (m.body[i] < 0x20 && m.body[i] != '\r' && m.body[i] != '\n') {
			t.Fatalf("the body carries the byte %#x: every part is quoted-printable", m.body[i])
		}
	}
}

// RFC 2046 section 5.1.1: a boundary is 1 to 70 characters of its set, not ending in a space, and
// appears in no part; the message ends with the close delimiter.
func TestSendEmail_TheBoundaryFollowsRFC2046(t *testing.T) {
	// A body that writes what a delimiter line starts with, and the characters a boundary may hold.
	html := "<p>--\n--=_ =_ -- ==</p>"

	m := send(t, "Goiabada", &SendEmailInput{To: fixtureRecipient, Subject: "Test email", HtmlBody: html})
	boundary, parts := alternativeParts(t, m)

	assert.LessOrEqual(t, len(boundary), 70)
	assert.False(t, strings.HasSuffix(boundary, " "), "a boundary does not end in a space")
	for _, r := range boundary {
		assert.True(t, strings.ContainsRune("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'()+_,-./:=? ", r),
			"the boundary %q holds %q", boundary, r)
	}
	require.Len(t, parts, 2)
	for _, part := range parts {
		assert.NotContains(t, part.raw, boundary, "a part never holds the boundary")
	}
	assert.Equal(t, 2, strings.Count(m.body, "--"+boundary+"\r\n"), "a delimiter line opens each of the two parts")
	assert.Contains(t, m.body, "\r\n--"+boundary+"--\r\n", "the close delimiter ends the parts")
	for _, line := range fieldLines(t, m, "Content-Type") {
		assert.LessOrEqual(t, len(line), 78, "RFC 5322 section 2.1.1: the header that names the boundary is no longer than 78: %q", line)
	}

	other := send(t, "Goiabada", &SendEmailInput{To: fixtureRecipient, Subject: "Test email", HtmlBody: html})
	otherBoundary, _ := alternativeParts(t, other)
	assert.NotEqual(t, boundary, otherBoundary, "each message draws a boundary of its own")
}

// The text holds the body's paragraphs, a blank line between two, and the footer under them: bold
// as plain words, a line break as one, a link as its URL, a footer link as its label and its URL,
// the support contact as written. The logo, the app name above the body, the title and the button
// are not in it: the URL under the button is there already.
func TestSendEmail_TheTextIsWorkedOutOfTheHTML(t *testing.T) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Acme Portal - Forgot your password</title>
  <style>p { color: red; }</style>
</head>
<body style="margin: 0;">
  <table role="presentation" width="100%"><tr><td align="center">
    <table role="presentation" width="100%"><tr><td style="padding: 32px 28px;">
      <div style="text-align: center;">
        <img src="https://auth.example.com/brand-assets/7/logo-111111111111.png" alt="">
      </div>
      <p style="text-align: center;">Acme Portal</p>
      <main>
<div>
    <p>Hello Ana,</p>

    <p>You can reset your password by clicking the link below:</p>

    <table role="presentation" data-email-button><tr><td bgcolor="#7a3aa8">
      <a href="https://auth.example.com/reset-password?code=abc&amp;email=ana%40example.com">Reset password</a>
    </td></tr></table>

    <p><a href="https://auth.example.com/reset-password?code=abc&amp;email=ana%40example.com">https://auth.example.com/reset-password?code=abc&amp;email=ana%40example.com</a></p>

    <p><strong>In case you didn't request a password reset,</strong>   kindly
       disregard this email.</p>

    <p style="margin: 0; font-size: 28px; letter-spacing: 4px;">482915</p>

    <p>Best regards,<br />Acme Portal</p>
</div>
      </main>
    </td></tr></table>
    <table role="presentation" width="100%"><tr><td>
      <footer>
        <p style="margin: 0;"><a href="https://acme.example/privacy">Privacy</a> <span aria-hidden="true">&middot;</span> <a href="https://status.acme.example/">Status</a></p>
        <p style="margin: 4px 0 0;">Need help? <a href="mailto:help@acme.example">help@acme.example</a> <span aria-hidden="true">&middot;</span> <a href="tel:+442079460958">+442079460958</a> <span aria-hidden="true">&middot;</span> <a href="https://acme.example/support">Support page</a></p>
      </footer>
    </td></tr></table>
  </td></tr></table>
</body>
<!-- goiabada 1.9 -->
</html>`

	assert.Equal(t, `Hello Ana,

You can reset your password by clicking the link below:

https://auth.example.com/reset-password?code=abc&email=ana%40example.com

In case you didn't request a password reset, kindly disregard this email.

482915

Best regards,
Acme Portal

Privacy <https://acme.example/privacy> · Status <https://status.acme.example/>

Need help? help@acme.example · +442079460958 · Support page <https://acme.example/support>
`, textOf(t, html))
}

// Each rule on its own, in a body with no frame, which is what a templates directory copied from
// an older release sends: its body is read whole.
func TestSendEmail_TheTextOfEachPartOfABody(t *testing.T) {
	for _, tc := range []struct {
		name, html, want string
	}{
		{"two paragraphs", "<p>One</p><p>Two</p>", "One\n\nTwo\n"},
		{"a line break", "<p>Best regards,<br>Acme</p>", "Best regards,\nAcme\n"},
		{"a heading and a list", "<h1>Title</h1><ul><li>first</li><li>second</li></ul>", "Title\n\nfirst\n\nsecond\n"},
		{"bold and italics", "<p>Do <strong>not</strong> <em>share</em> it.</p>", "Do not share it.\n"},
		{"whitespace collapsed", "<p>\n   spread \t over\n   lines  </p>", "spread over lines\n"},
		{"a link written as its URL", `<p>Here: <a href="https://x.example/a?b=1&amp;c=2">https://x.example/a?b=1&amp;c=2</a></p>`, "Here: https://x.example/a?b=1&c=2\n"},
		{"a link with a label", `<p>Read the <a href="https://x.example/terms">terms</a>.</p>`, "Read the terms <https://x.example/terms>.\n"},
		{"a link with no label", `<p><a href="https://x.example/"></a></p>`, "https://x.example/\n"},
		{"a mail address", `<p><a href="mailto:help%2Bdesk@x.example">help+desk@x.example</a></p>`, "help+desk@x.example\n"},
		{"a phone number", `<p><a href="tel:+44 20 7946 0958">+44 20 7946 0958</a></p>`, "+44 20 7946 0958\n"},
		{"an image", `<p>Before<img src="https://x.example/i.png" alt="An image">after</p>`, "Beforeafter\n"},
		{"a script", "<p>Kept</p><script>dropped()</script>", "Kept\n"},
		{"text outside a paragraph", "Hello <b>there</b>", "Hello there\n"},
		{"a non-breaking space kept", "<p>10&nbsp;minutes</p>", "10 minutes\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, textOf(t, tc.html))
		})
	}
}

// No email is sent without its text: a body with nothing to read is refused before the dial.
func TestSendEmail_AnEmailWithNoTextIsNotSent(t *testing.T) {
	for _, html := range []string{"", "<p> \n </p>", `<img src="https://x.example/i.png">`} {
		t.Run(html, func(t *testing.T) {
			f := &fakeSMTP{ext: []string{"8BITMIME"}}
			port := f.start(t)

			_, err := (&Sender{dataCipher: testDataCipher}).SendEmail(context.Background(),
				relayConfig(t, "127.0.0.1", port, "none", "", "", "Goiabada"),
				&SendEmailInput{To: fixtureRecipient, Subject: "Test email", HtmlBody: html})

			require.Error(t, err)
			assert.Contains(t, err.Error(), "the email has no text")
			assertSendFailure(t, err, SendFailureOther)
			assert.False(t, f.sawConnection(), "the message is built before the dial, so nothing should have connected")
		})
	}
}

// brandStub answers one brand for every page, with its assets.
type brandStub struct {
	brand  *record.Brand
	assets []record.BrandAsset
}

func (s brandStub) GetDefaultBrand(context.Context, *sql.Tx) (*record.Brand, error) {
	return s.brand, nil
}

func (s brandStub) GetClientPageBrand(context.Context, *sql.Tx, string) (*record.Brand, error) {
	return s.brand, nil
}

func (s brandStub) GetBrandAssetsByIds(context.Context, *sql.Tx, []int64) ([]record.BrandAsset, error) {
	return s.assets, nil
}

// emailLink is the link every email is rendered with.
const emailLink = "https://auth.example.com/reset-password?code=abc&email=ana%40example.com"

// renderEmail renders the built-in English email body base through the email layout, for a brand
// on Plum with a logo, and with footer links and a support contact when footer is set.
func renderEmail(t *testing.T, base string, footer bool) string {
	t.Helper()
	return renderEmailIn(t, base, "en", footer)
}

// renderEmailIn renders the built-in email body base written in lang, as renderEmail does.
func renderEmailIn(t *testing.T, base, lang string, footer bool) string {
	t.Helper()

	brand := record.NewBrand("Shop", record.BrandAppearanceLight, "plum")
	brand.Id = 7
	brand.LogoAssetId = sql.NullInt64{Int64: 11, Valid: true}
	if footer {
		brand.FooterLinks = record.BrandFooterLinks{
			{URL: "https://acme.example/privacy", Label: "Privacy"},
			{URL: "https://status.acme.example/", Label: "Status"},
		}
		brand.SupportEmail, brand.SupportPhone, brand.SupportURL = "help@acme.example", "+442079460958", "https://acme.example/support"
	}
	brands := brandStub{brand: &brand, assets: []record.BrandAsset{
		{Id: 11, Kind: record.BrandAssetKindLogo, ContentType: "image/png", Fingerprint: "111111111111", Width: 200, Height: 60},
	}}

	ctx := reqctx.WithSettings(context.Background(), &record.Settings{AppName: "Acme Portal"})
	ctx = i18n.WithLocale(ctx, true, lang, "en")
	req := httptest.NewRequest(http.MethodPost, "/", nil).WithContext(ctx)
	renderer := render.New(web.TemplateFS(), web.StaticFS(), brands).WithBaseURL("https://auth.example.com")
	// An email sent from its built-in definition (#818) is named by its identifier.
	for _, email := range emailtemplate.BuiltIns() {
		if email.ID == base {
			message, err := renderer.RenderEmail(req, email, emailtemplate.Values{
				Name: "Ana", Link: emailLink, Code: "482915", Expiry: 5 * time.Minute,
			})
			require.NoError(t, err)
			require.Contains(t, message.HTML, "<img", "the email draws its brand's logo")
			return message.HTML
		}
	}
	buf, err := renderer.RenderTemplateToBuffer(req,
		"/layouts/email_layout.html", "/emails/"+base+".html", map[string]interface{}{
			"name": "Ana", "link": emailLink, "remaining": 3,
		})
	require.NoError(t, err)
	require.Contains(t, buf.String(), "<img", "the email draws its brand's logo")
	return buf.String()
}

// A built-in action email, drawn with its button, its brand's logo and its footer, reads as its
// paragraphs with the URL once, then the footer written out.
func TestSendEmail_TheTextOfABuiltInActionEmail(t *testing.T) {
	assert.Equal(t, `Hello Ana,

You can reset your password by clicking the link below:

https://auth.example.com/reset-password?code=abc&email=ana%40example.com

The link expires in 5 minutes.

If you have trouble clicking the link, you can copy and paste it into your web browser.

In case you didn't request a password reset, kindly disregard this email.

Best regards,
Acme Portal

Privacy <https://acme.example/privacy> · Status <https://status.acme.example/>

Need help? help@acme.example · +442079460958 · Support page <https://acme.example/support>
`, textOf(t, renderEmail(t, "password_reset_link", true)))
}

// The verification code is on a line of its own, followed by how long it lasts, and a brand with no
// footer adds nothing under the body.
func TestSendEmail_TheTextOfTheVerificationEmail(t *testing.T) {
	assert.Equal(t, `Hello Ana,

This is your email verification code:

482915

The code expires in 5 minutes.

You can enter your code here: https://auth.example.com/reset-password?code=abc&email=ana%40example.com

Best regards,
Acme Portal
`, textOf(t, renderEmail(t, "verification_code", false)))
}

// logoSource is the logo an email draws.
var logoSource = regexp.MustCompile(`<img src="([^"]+)"`)

// Every built-in email, in every language it is written in, is sent with its text: the link it
// holds written once, the button left out, no logo, and the footer written out.
func TestSendEmail_EveryBuiltInEmailIsSentWithItsText(t *testing.T) {
	bodies, err := fs.Glob(web.TemplateFS(), "emails/*.html")
	require.NoError(t, err)
	require.NotEmpty(t, bodies)

	// Each email is named by its base name and the language it is written in: a template file's,
	// email_x.html in English and email_x.<tag>.html in tag, and every built-in definition's in
	// each of the six languages.
	type written struct{ base, lang string }
	var emails []written
	for _, body := range bodies {
		base, lang, _ := strings.Cut(strings.TrimSuffix(path.Base(body), ".html"), ".")
		if lang == "" {
			lang = "en"
		}
		emails = append(emails, written{base, lang})
	}
	for _, email := range emailtemplate.BuiltIns() {
		for _, lang := range emailtemplate.Languages {
			emails = append(emails, written{email.ID, lang})
		}
	}

	for _, email := range emails {
		base, lang := email.base, email.lang
		t.Run(base+"."+lang, func(t *testing.T) {
			html := renderEmailIn(t, base, lang, true)
			logo := logoSource.FindStringSubmatch(html)
			require.Len(t, logo, 2)

			text := textOf(t, html)

			assert.Contains(t, text, "Acme Portal", "the body is in the text")
			assert.NotContains(t, text, logo[1], "the logo is not")
			if strings.Contains(html, "reset-password?code=abc") {
				assert.Equal(t, 1, strings.Count(text, emailLink), "the link is written once, as its URL:\n%s", text)
			}
			assert.Contains(t, text, "\n\nPrivacy <https://acme.example/privacy> · Status <https://status.acme.example/>\n\n",
				"the footer's links follow the body:\n%s", text)
			assert.Contains(t, text, " help@acme.example · +442079460958 · ", "then its support contact")
			assert.True(t, strings.HasSuffix(text, " <https://acme.example/support>\n"), "which ends the text:\n%s", text)
		})
	}
}
