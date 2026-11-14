package emailtemplate

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
)

// The format's rules (#818 decisions 2, 3, 5 and 17), each driven with a text an administrator
// could write and checked against HTML written out by hand, never against another renderer's
// output.

// everything is an email offering every placeholder but the codes left, none required, so each
// rule of the format can be driven through one email.
var everything = &Email{
	ID: "everything",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name}, {Name: Link}, {Name: Button}, {Name: Code}, {Name: Expiry},
	},
}

// linkRequired is everything with the link required, as the password reset link requires it.
var linkRequired = &Email{
	ID: "link_required",
	Placeholders: []Placeholder{
		{Name: AppName}, {Name: Name}, {Name: Link, Required: true}, {Name: Button}, {Name: Code}, {Name: Expiry},
	},
}

// notice offers only the app name and the name, as the account notices do.
var notice = &Email{ID: "notice", Placeholders: []Placeholder{{Name: AppName}, {Name: Name}}}

// testLook is a brand's look as the email's frame gives it: Plum's light colors, rounded.
var testLook = Look{
	Link: "#7a3aa8", OnBrand: "#ffffff", ControlRadius: "8px", FontFamily: "system-ui, sans-serif",
	Subtle: "#f0ecf2", Line: "#ddd7e1", BoxRadius: "8px", Ink: "#201a26", CodeFamily: "ui-monospace, monospace",
}

var testValues = Values{
	AppName: "Acme Portal",
	Name:    "Ana",
	Link:    "https://auth.example.com/reset-password?code=abc&ceremony=x",
	Code:    "482915",
	Expiry:  5 * time.Minute,
}

// escapedLink is testValues.Link as HTML writes it.
const escapedLink = "https://auth.example.com/reset-password?code=abc&amp;ceremony=x"

// linkTo is how the body draws a link to href with label: in the brand's color, inline.
func linkTo(href, label string) string {
	return `<a href="` + href + `" style="color: #7a3aa8;">` + label + `</a>`
}

func renderBody(t *testing.T, email *Email, body string) string {
	t.Helper()
	text := Text{Subject: "Subject", Body: body}
	if email.HasButton() {
		text.ButtonLabel = "Reset password"
	}
	rendered, err := email.Render("en", text, testValues, testLook)
	require.NoError(t, err)
	return string(rendered.Body)
}

func TestRender_TheMarkdownSet(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"paragraphs", "First.\n\nSecond.", "<p>First.</p>\n<p>Second.</p>\n"},
		{"a single newline is a line break", "Best regards,\nThe team", "<p>Best regards,<br>\nThe team</p>\n"},
		{"bold and italic", "**Never** share *this* or __that__ _either_.",
			"<p><strong>Never</strong> share <em>this</em> or <strong>that</strong> <em>either</em>.</p>\n"},
		{"a link", "See [our help](https://acme.example/help?a=1&b=2).",
			"<p>See " + linkTo("https://acme.example/help?a=1&amp;b=2", "our help") + ".</p>\n"},
		{"a mailto link", "[Write to us](mailto:help@acme.example)",
			"<p>" + linkTo("mailto:help@acme.example", "Write to us") + "</p>\n"},
		{"a bulleted list", "- one\n- two", "<ul>\n<li>one</li>\n<li>two</li>\n</ul>\n"},
		{"a numbered list", "1. first\n2. second", "<ol>\n<li>first</li>\n<li>second</li>\n</ol>\n"},
		{"a numbered list starting later", "3. third\n4. fourth", "<ol start=\"3\">\n<li>third</li>\n<li>fourth</li>\n</ol>\n"},
		{"text is escaped", "Terms & conditions: 1 < 2 and \"quoted\"",
			"<p>Terms &amp; conditions: 1 &lt; 2 and &quot;quoted&quot;</p>\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, renderBody(t, everything, tc.body))
		})
	}
}

// Syntax outside the set is shown as the characters typed, escaped, and never refused.
func TestRender_SyntaxOutsideTheSetIsShownAsTyped(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"a heading", "# Welcome", "<p># Welcome</p>\n"},
		{"a block quote", "> quoted", "<p>&gt; quoted</p>\n"},
		{"code", "Run `rm -rf` now", "<p>Run `rm -rf` now</p>\n"},
		{"a fenced code block", "```\ncode\n```", "<p>```<br>\ncode<br>\n```</p>\n"},
		{"a table", "| a | b |\n|---|---|", "<p>| a | b |<br>\n|---|---|</p>\n"},
		{"an image", "![logo](https://tracker.example/pixel.png)", "<p>![logo](https://tracker.example/pixel.png)</p>\n"},
		{"raw HTML", "<img src=x onerror=alert(1)>", "<p>&lt;img src=x onerror=alert(1)&gt;</p>\n"},
		{"a script", "<script>alert(1)</script>", "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>\n"},
		{"an autolink", "<https://acme.example>", "<p>&lt;https://acme.example&gt;</p>\n"},
		{"a reference link", "[help][1]\n\n[1]: https://acme.example", "<p>[help][1]</p>\n<p>[1]: https://acme.example</p>\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Empty(t, everything.Check(Text{ButtonLabel: "Go", Subject: "Subject", Body: tc.body}), "syntax outside the set is never refused")
			assert.Equal(t, tc.want, renderBody(t, everything, tc.body))
		})
	}
}

// A link to an address other than the web, mail or a phone number keeps its text and loses its
// address.
func TestRender_ADangerousLinkLosesItsAddress(t *testing.T) {
	for _, destination := range []string{
		"javascript:alert(1)", "JavaScript:alert(1)", "vbscript:msgbox", "data:text/html,<b>x</b>",
		"data:image/png;base64,AAAA", "file:///etc/passwd", "//evil.example/", "relative/path",
	} {
		t.Run(destination, func(t *testing.T) {
			got := renderBody(t, notice, "[click here]("+destination+")")
			assert.Equal(t, "<p>click here</p>\n", got)
		})
	}
}

func TestRender_Placeholders(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"a value is text", "Hello {{name}}, from {{app_name}}.", "<p>Hello Ana, from Acme Portal.</p>\n"},
		{"inner spaces read the same", "Hello {{ name }}.", "<p>Hello Ana.</p>\n"},
		{"an escaped brace writes the braces", `Write \{{name}} to greet.`, "<p>Write {{name}} to greet.</p>\n"},
		{"the expiry in the email's language", "It expires in {{expiry}}.", "<p>It expires in 5 minutes.</p>\n"},
		{"the link alone is drawn as a link to itself", "{{link}}", "<p>" + linkTo(escapedLink, escapedLink) + "</p>\n"},
		{"the link as a link's whole destination", "[Reset your password]({{link}})",
			"<p>" + linkTo(escapedLink, "Reset your password") + "</p>\n"},
		{"the link as a destination with inner spaces", "[Reset](<{{ link }}>)", "<p>" + linkTo(escapedLink, "Reset") + "</p>\n"},
		{"the link inside a link's text is text", "[Open {{link}}](https://acme.example)",
			"<p>" + linkTo("https://acme.example", "Open "+escapedLink) + "</p>\n"},
		{"the code inside a sentence is text", "Your code is {{code}}.", "<p>Your code is 482915.</p>\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, renderBody(t, everything, tc.body))
		})
	}
}

// A value is inserted as text, escaped, and never read as Markdown or HTML.
func TestRender_AValueIsNeverMarkdownOrHTML(t *testing.T) {
	values := testValues
	values.Name = "**Ana** <b onclick=\"x\">[evil](https://evil.example)</b> {{link}}"
	rendered, err := notice.Render("en", Text{Subject: "Hi {{name}}", Body: "Hello {{name}}."}, values, testLook)
	require.NoError(t, err)
	assert.Equal(t, "<p>Hello **Ana** &lt;b onclick=&quot;x&quot;&gt;[evil](https://evil.example)&lt;/b&gt; {{link}}.</p>\n",
		string(rendered.Body))
	assert.Equal(t, "Hi **Ana** <b onclick=\"x\">[evil](https://evil.example)</b> {{link}}", rendered.Subject,
		"the subject is plain text, its values as they are")
}

// {{button}} alone on its line draws the brand's button to the link, labelled with the button
// label, which is plain text.
func TestRender_TheButton(t *testing.T) {
	rendered, err := everything.Render("en", Text{
		Subject: "Subject", ButtonLabel: "Reset <your> **password** {{name}}",
		Body: "Hello,\n  {{ button }}  \n{{link}}",
	}, testValues, testLook)
	require.NoError(t, err)
	assert.Equal(t, "<p>Hello,</p>\n"+
		`<table role="presentation" data-email-button cellpadding="0" cellspacing="0" border="0" style="margin: 0 0 16px; border-collapse: separate;">`+"\n"+
		"<tr>\n"+
		`<td align="center" bgcolor="#7a3aa8" style="background-color: #7a3aa8; border-radius: 8px;">`+"\n"+
		`<a href="`+escapedLink+`" style="display: inline-block; padding: 12px 24px; border: 1px solid #7a3aa8; border-radius: 8px; background-color: #7a3aa8; color: #ffffff; font-family: system-ui, sans-serif; font-size: 16px; font-weight: 600; line-height: 24px; text-decoration: none;">Reset &lt;your&gt; **password** {{name}}</a>`+"\n"+
		"</td>\n</tr>\n</table>\n"+
		"<p>"+linkTo(escapedLink, escapedLink)+"</p>\n", string(rendered.Body))
}

// {{code}} alone in its paragraph draws the boxed code, larger and in a monospace face.
func TestRender_TheBoxedCode(t *testing.T) {
	got := renderBody(t, everything, "Your code:\n\n{{code}}\n\n{{link}}")
	assert.Equal(t, "<p>Your code:</p>\n"+
		`<p style="margin: 0 0 16px; padding: 12px 16px; background-color: #f0ecf2; border: 1px solid #ddd7e1; border-radius: 8px; color: #201a26; font-family: ui-monospace, monospace; font-size: 28px; font-weight: 600; letter-spacing: 4px; line-height: 36px; text-align: center;">482915</p>`+"\n"+
		"<p>"+linkTo(escapedLink, escapedLink)+"</p>\n", got)
}

func TestRender_TheSubject(t *testing.T) {
	for _, tc := range []struct{ subject, want string }{
		{"{{app_name}} - code {{code}}", "Acme Portal - code 482915"},
		{"Hello {{ name }}", "Hello Ana"},
		{`Use \{{name}}`, "Use {{name}}"},
		{`Use \{{ name }} for the name`, "Use {{ name }} for the name"},
		{`Print \{{ to begin a placeholder`, "Print {{ to begin a placeholder"},
		{`Print \{{name to begin one`, "Print {{name to begin one"},
		{`\{{ and {{app_name}}`, "{{ and Acme Portal"},
		{`{{app_name}} then \{{`, "Acme Portal then {{"},
		{`A backslash \ alone`, `A backslash \ alone`},
		{"Valid for {{expiry}}", "Valid for 5 minutes"},
		{"# Not *Markdown* & <b>", "# Not *Markdown* & <b>"},
	} {
		t.Run(tc.subject, func(t *testing.T) {
			rendered, err := everything.Render("en", Text{ButtonLabel: "Go", Subject: tc.subject, Body: "{{link}}"}, testValues, testLook)
			require.NoError(t, err)
			assert.Equal(t, tc.want, rendered.Subject)
		})
	}
}

// The refusals a save gives, one row for each rule.
func TestCheck_TheRefusals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		email *Email
		text  Text
		want  []Problem
	}{
		{"a name the email does not offer, in the body", notice, Text{Subject: "S", Body: "Hello {{full_name}}."},
			[]Problem{{Field: FieldBody, Rule: RuleUnknownPlaceholder, Placeholder: "full_name"}}},
		{"a name the email does not offer, in the subject", notice, Text{Subject: "Code {{code}}", Body: "Hello."},
			[]Problem{{Field: FieldSubject, Rule: RuleUnknownPlaceholder, Placeholder: "code"}}},
		{"a placeholder in capitals is not a name", notice, Text{Subject: "S", Body: "Hello {{Name}}."},
			[]Problem{{Field: FieldBody, Rule: RuleUnknownPlaceholder, Placeholder: "Name"}}},
		{"the link in a notice that offers none", notice, Text{Subject: "S", Body: "Go to {{link}}."},
			[]Problem{{Field: FieldBody, Rule: RuleUnknownPlaceholder, Placeholder: "link"}}},
		{"a required placeholder missing", linkRequired, Text{ButtonLabel: "Go", Subject: "S", Body: "Hello."},
			[]Problem{{Field: FieldBody, Rule: RuleRequiredPlaceholderMissing, Placeholder: "link"}}},
		{"the button does not satisfy the link", linkRequired, Text{ButtonLabel: "Go", Subject: "S", Body: "Hello.\n{{button}}"},
			[]Problem{{Field: FieldBody, Rule: RuleRequiredPlaceholderMissing, Placeholder: "link"}}},
		{"the link only in a link's title does not satisfy it", linkRequired,
			Text{ButtonLabel: "Go", Subject: "S", Body: `[Reset](https://acme.example "{{link}}")`},
			[]Problem{{Field: FieldBody, Rule: RuleRequiredPlaceholderMissing, Placeholder: "link"}}},
		{"an escaped link does not satisfy it", linkRequired, Text{ButtonLabel: "Go", Subject: "S", Body: `\{{link}}`},
			[]Problem{{Field: FieldBody, Rule: RuleRequiredPlaceholderMissing, Placeholder: "link"}}},
		{"the link in the subject", everything, Text{ButtonLabel: "Go", Subject: "Open {{link}}", Body: "{{link}}"},
			[]Problem{{Field: FieldSubject, Rule: RulePlaceholderNotInSubject, Placeholder: "link"}}},
		{"the button in the subject", everything, Text{ButtonLabel: "Go", Subject: "{{ button }}", Body: "{{link}}"},
			[]Problem{{Field: FieldSubject, Rule: RulePlaceholderNotInSubject, Placeholder: "button"}}},
		{"the button inside a sentence", everything, Text{ButtonLabel: "Go", Subject: "S", Body: "Select {{button}} now.\n\n{{link}}"},
			[]Problem{{Field: FieldBody, Rule: RuleButtonNotAlone, Placeholder: "button"}}},
		{"the button in a list item", everything, Text{ButtonLabel: "Go", Subject: "S", Body: "- {{button}}\n\n{{link}}"},
			[]Problem{{Field: FieldBody, Rule: RuleButtonNotAlone, Placeholder: "button"}}},
		{"the link as part of a longer destination", everything,
			Text{ButtonLabel: "Go", Subject: "S", Body: "[Reset](https://evil.example/?next={{link}})\n\n{{link}}"},
			[]Problem{{Field: FieldBody, Rule: RulePlaceholderInLinkDestination, Placeholder: "link"}}},
		{"another placeholder as a destination", everything, Text{ButtonLabel: "Go", Subject: "S", Body: "[Hi]({{name}})\n\n{{link}}"},
			[]Problem{{Field: FieldBody, Rule: RulePlaceholderInLinkDestination, Placeholder: "name"}}},
		{"a body holding nothing but the button", linkRequired, Text{ButtonLabel: "Go", Subject: "S", Body: "\n  {{button}}\n\n"},
			[]Problem{
				{Field: FieldBody, Rule: RuleRequiredPlaceholderMissing, Placeholder: "link"},
				{Field: FieldBody, Rule: RuleNothingToRead},
			}},
		{"an empty body", notice, Text{Subject: "S", Body: " \n "},
			[]Problem{{Field: FieldBody, Rule: RuleNothingToRead}}},

		// The limits of decision 7, counted in characters as a browser's maxlength counts them: an
		// "é" is one, and an emoji outside the basic plane two.
		{"an empty subject", notice, Text{Subject: "", Body: "Hello."},
			[]Problem{{Field: FieldSubject, Rule: RuleEmpty}}},
		{"a blank subject", notice, Text{Subject: " \t ", Body: "Hello."},
			[]Problem{{Field: FieldSubject, Rule: RuleEmpty}}},
		{"a subject of 201 characters", notice, Text{Subject: strings.Repeat("é", 201), Body: "Hello."},
			[]Problem{{Field: FieldSubject, Rule: RuleTooLong}}},
		{"a subject of 101 emoji, 202 in a browser's count", notice, Text{Subject: strings.Repeat("🔑", 101), Body: "Hello."},
			[]Problem{{Field: FieldSubject, Rule: RuleTooLong}}},
		{"a subject on two lines", notice, Text{Subject: "Your account\nwas deleted", Body: "Hello."},
			[]Problem{{Field: FieldSubject, Rule: RuleNotOneLine}}},
		{"a subject ending in a carriage return", notice, Text{Subject: "Your account\r", Body: "Hello."},
			[]Problem{{Field: FieldSubject, Rule: RuleNotOneLine}}},
		{"an empty button label", everything, Text{Subject: "S", ButtonLabel: "", Body: "{{link}}"},
			[]Problem{{Field: FieldButtonLabel, Rule: RuleEmpty}}},
		{"a blank button label", everything, Text{Subject: "S", ButtonLabel: "  ", Body: "{{link}}"},
			[]Problem{{Field: FieldButtonLabel, Rule: RuleEmpty}}},
		{"a button label of 61 characters", everything, Text{Subject: "S", ButtonLabel: strings.Repeat("ü", 61), Body: "{{link}}"},
			[]Problem{{Field: FieldButtonLabel, Rule: RuleTooLong}}},
		{"a button label for an email with no button", notice, Text{Subject: "S", ButtonLabel: "Open", Body: "Hello."},
			[]Problem{{Field: FieldButtonLabel, Rule: RuleNoButton}}},
		{"a body of 20,001 characters", notice, Text{Subject: "S", Body: strings.Repeat("a", 20_001)},
			[]Problem{{Field: FieldBody, Rule: RuleTooLong}}},
		{"every field past its limit at once", everything,
			Text{Subject: strings.Repeat("s", 201), ButtonLabel: strings.Repeat("b", 61), Body: strings.Repeat("a", 20_001)},
			[]Problem{
				{Field: FieldSubject, Rule: RuleTooLong},
				{Field: FieldButtonLabel, Rule: RuleTooLong},
				{Field: FieldBody, Rule: RuleTooLong},
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, Problems(tc.want), tc.email.Check(tc.text))

			_, err := tc.email.Render("en", tc.text, testValues, testLook)
			var refused Problems
			require.ErrorAs(t, err, &refused, "a text a save would refuse is not rendered")
			assert.Equal(t, Problems(tc.want), refused)
		})
	}
}

// The rule about the button is the same whatever the brand draws: a welcome email whose body is
// only {{button}} is refused, as the save would refuse it.
func TestCheck_AWelcomeBodyOfOnlyTheButtonIsRefused(t *testing.T) {
	welcome := &Email{ID: "welcome", Placeholders: []Placeholder{{Name: AppName}, {Name: Link}, {Name: Button}}}
	assert.Equal(t, Problems{{Field: FieldBody, Rule: RuleNothingToRead}}, welcome.Check(Text{ButtonLabel: "Go", Subject: "Welcome!", Body: "{{button}}"}))
	assert.Empty(t, welcome.Check(Text{ButtonLabel: "Go", Subject: "Welcome!", Body: "Welcome.\n{{button}}"}))
}

// A body must hold something to read besides the button (#818 decision 17), judged on what it
// draws and not on the characters typed: an empty list item, a link with no label whose address is
// dropped, or a character reference to whitespace draws nothing a reader reads, and the sender
// would refuse the message for want of text in a brand with no footer.
func TestCheck_ABodyThatDrawsNothingToReadIsRefused(t *testing.T) {
	for _, body := range []string{
		"- ",
		"1. ",
		"- \n- \n\n1. ",
		"[]()",
		"[ ](relative)",
		"[](javascript:alert(1))",
		"&NewLine;",
		"&#32;&#9;&#10;",
		"{{button}}\n\n- ",
		"- \n\n{{button}}\n\n[ ]()",
	} {
		t.Run(body, func(t *testing.T) {
			assert.Equal(t, Problems{{Field: FieldBody, Rule: RuleNothingToRead}},
				everything.Check(Text{ButtonLabel: "Go", Subject: "Welcome!", Body: body}))
		})
	}
}

// What a body draws for a reader counts, whatever the values: a placeholder other than the button,
// whose value is never empty, a link with no label, which the plain-text part writes as its
// address, a character written by a reference or an escape, and syntax shown as typed.
func TestCheck_ABodyThatDrawsSomethingToReadIsAccepted(t *testing.T) {
	for _, body := range []string{
		"{{name}}",
		"{{button}}\n\n{{app_name}}",
		"- {{expiry}}",
		"{{code}}",
		"{{link}}",
		"[](https://acme.example/help)",
		"[]({{link}})",
		"&amp;",
		"\\-",
		"![]()",
		"# ",
	} {
		t.Run(body, func(t *testing.T) {
			text := Text{ButtonLabel: "Go", Subject: "Welcome!", Body: body}
			require.Empty(t, everything.Check(text))
			rendered, err := everything.Render("en", text, testValues, testLook)
			require.NoError(t, err)
			plain, err := emaildelivery.PlainText("<main>" + string(rendered.Body) + "</main>")
			require.NoError(t, err, "the sender finds text in %q", rendered.Body)
			assert.NotEmpty(t, strings.TrimSpace(plain))
		})
	}
}

// A text at each limit, counted in characters, is accepted: 200 for the subject, 60 for the button
// label and 20,000 for the body.
func TestCheck_ATextAtEachLimitIsAccepted(t *testing.T) {
	assert.Empty(t, everything.Check(Text{
		Subject:     strings.Repeat("é", 200),
		ButtonLabel: strings.Repeat("ü", 60),
		Body:        strings.Repeat("a", 19_992) + "{{link}}",
	}))
	assert.Empty(t, notice.Check(Text{Subject: strings.Repeat("🔑", 100), Body: "Hello."}))
}

// Rendering refuses a look whose values are not what the frame gives, since they are written into
// style attributes unescaped by any CSS filter.
func TestRender_RefusesALookThatIsNotAFrames(t *testing.T) {
	for name, look := range map[string]Look{
		"a color that is not #rrggbb": func() Look { l := testLook; l.Link = "red; background: url(x)"; return l }(),
		"a radius that is not pixels": func() Look { l := testLook; l.ControlRadius = "8px; color: red"; return l }(),
		"a font list with a quote":    func() Look { l := testLook; l.FontFamily = `"Evil"; x: y`; return l }(),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := everything.Render("en", Text{ButtonLabel: "Go", Subject: "S", Body: "{{link}}"}, testValues, look)
			require.Error(t, err)
		})
	}
}
