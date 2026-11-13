package customcss_test

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/customcss"
)

// pngData is a data: image a url() may hold.
const pngData = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

type checkCase struct {
	name string
	css  string
	// want is nil for CSS that passes.
	want *customcss.Refusal
}

func refused(rule customcss.Rule, line int) *customcss.Refusal {
	return &customcss.Refusal{Rule: rule, Line: line}
}

func runCases(t *testing.T, cases []checkCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := customcss.Check(tc.css)
			css := tc.css
			if len(css) > 120 {
				css = css[:120] + "…"
			}
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("Check(%q) = %+v, want a pass", css, *got)
			case tc.want != nil && got == nil:
				t.Fatalf("Check(%q) passed, want %+v", css, *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("Check(%q) = %+v, want %+v", css, *got, *tc.want)
			}
		})
	}
}

func TestCheck_Passes(t *testing.T) {
	runCases(t, []checkCase{
		{"blank", "", nil},
		{"whitespace only", " \n\t\n", nil},
		{"ordinary rules", ".auth-card { border: 2px solid var(--color-brand); border-radius: 0; }\n" +
			"body[data-page=\"sign-in\"] .auth-title { font-size: 2rem; }\n" +
			"@media (max-width: 40rem) { .auth-card { padding: 1rem; } }\n", nil},
		{"a data: image in an unquoted url()", ".auth-page { background-image: url(" + pngData + "); }", nil},
		{"a data: image in a double-quoted url()", `.auth-page { background-image: url("` + pngData + `"); }`, nil},
		{"a data: image in a single-quoted url()", `.auth-page { background-image: url( '` + pngData + `' ); }`, nil},
		{"a data: image in upper case", ".auth-page { background: URL(DATA:IMAGE/PNG;base64,AAAA); }", nil},
		{"an svg data: image", `.auth-logo { content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E"); }`, nil},
		{"a data: image in a custom property", ":root { --picture: url(" + pngData + "); }\n.auth-page { background-image: var(--picture); }", nil},
		{"a custom property holding a plain string", ":root { --label: \"/some/path\"; }\n.auth-title::after { content: var(--label); }", nil},
		{"var() in a color and a length", ".button { color: var(--color-brand, #123456); margin: var(--gap, 4px) calc(var(--gap) * 2); }", nil},
		{"the word image-set with no parenthesis", ".x { transition-property: image-set; --name: image src; }", nil},
		{"image-set followed by a comment then a parenthesis", ".x { --a: image-set/**/(1x); }", nil},
		{"@import in a comment", "/* @import url(https://example.com/a.css); */\n.x { color: red; }", nil},
		{"@import in a string", `.x::before { content: "@import 'a.css';"; }`, nil},
		{"url( in a comment", "/* background: url(https://example.com/a.png) */", nil},
		{"url( in a string", `.x::before { content: "url(https://example.com/a.png)"; }`, nil},
		{"image-set( in a comment and a string", "/* image-set(\"/a\" 1x) */ .x::before { content: \"src(/a) image(/b)\"; }", nil},
		{"other at-rules", "@font-feature-values Font One { @styleset { nice: 12; } }\n@supports (display: grid) { .x { display: grid; } }\n@layer base;", nil},
		{"an escaped newline inside a string", ".x::before { content: \"one\\\ntwo\"; }", nil},
		{"CDO and CDC", "<!-- .x { color: red; } -->", nil},
		{"a local() font source", "@font-face { font-family: Mine; src: local(\"Arial\"); }", nil},
		{"a function named like a refused one with a longer name", ".x { --a: images(1); --b: srcset(2); --c: image-sets(3); }", nil},
		{"a lone hyphen prefix is no vendor prefix", ".x { --a: -image(1); }", nil},
		{"CSS at the cap", sized(customcss.MaxBytes), nil},
	})
}

func TestCheck_Size(t *testing.T) {
	runCases(t, []checkCase{
		{"one byte past the cap", sized(customcss.MaxBytes + 1), refused(customcss.RuleTooLarge, 0)},
		{"a multi-byte character past the cap", sized(customcss.MaxBytes-1) + "é", refused(customcss.RuleTooLarge, 0)},
	})
}

func TestCheck_Import(t *testing.T) {
	runCases(t, []checkCase{
		{"@import of a URL", "@import url(\"https://example.com/a.css\");", refused(customcss.RuleImport, 1)},
		{"@import of a string", ".x { color: red; }\n@import 'a.css';", refused(customcss.RuleImport, 2)},
		{"@import of a data: URL", "@import url(data:text/css,.x{});", refused(customcss.RuleImport, 1)},
		{"@import in upper case", "\n\n@IMPORT 'a.css';", refused(customcss.RuleImport, 3)},
		{"@import in mixed case", "@ImPoRt 'a.css';", refused(customcss.RuleImport, 1)},
		{"@import through an escape", "/* fine */\n@\\69mport 'a.css';", refused(customcss.RuleImport, 2)},
		{"@import through an escape with its whitespace", "@\\000069 mport 'a.css';", refused(customcss.RuleImport, 1)},
		{"@import through an escaped letter", "@im\\port 'a.css';", refused(customcss.RuleImport, 1)},
		{"@import after a comment on its line", "/* a */ @import 'a.css';", refused(customcss.RuleImport, 1)},
		{"@import after a string holding @import", ".x::before { content: \"@import\"; }\n@import 'a.css';", refused(customcss.RuleImport, 2)},
	})
}

func TestCheck_URL(t *testing.T) {
	runCases(t, []checkCase{
		{"an unquoted url() of another origin", ".x { background: url(https://example.com/a.png); }", refused(customcss.RuleURL, 1)},
		{"a quoted url() of another origin", ".x {\n  background: url(\"https://example.com/a.png\");\n}", refused(customcss.RuleURL, 2)},
		{"a single-quoted url() with whitespace", ".x { background: url(  'https://example.com/a.png'  ); }", refused(customcss.RuleURL, 1)},
		{"a path", ".x { background: url(/brand-assets/1); }", refused(customcss.RuleURL, 1)},
		{"a relative URL", ".x { background: url(a.png); }", refused(customcss.RuleURL, 1)},
		{"a fragment", ".x { filter: url(#blur); }", refused(customcss.RuleURL, 1)},
		{"an empty url()", ".x { background: url(); }", refused(customcss.RuleURL, 1)},
		{"an empty quoted url()", ".x { background: url(\"\"); }", refused(customcss.RuleURL, 1)},
		{"a protocol-relative URL", ".x { background: url(//example.com/a.png); }", refused(customcss.RuleURL, 1)},
		{"a data: value that is not an image", ".x { background: url(data:text/html,hello); }", refused(customcss.RuleURL, 1)},
		{"a data: value with no type", ".x { background: url(\"data:,hello\"); }", refused(customcss.RuleURL, 1)},
		{"a data: image with whitespace before its scheme", ".x { background: url(\" data:image/png,AAAA\"); }", refused(customcss.RuleURL, 1)},
		{"a url() in upper case", ".x { background: URL(https://example.com/a.png); }", refused(customcss.RuleURL, 1)},
		{"a url() in mixed case", ".x { background: uRl(\"/a.png\"); }", refused(customcss.RuleURL, 1)},
		{"a url() through an escape", "\n.x { background: \\75rl(https://example.com/a.png); }", refused(customcss.RuleURL, 2)},
		{"a url() through an escape, quoted", ".x { background: \\75 rl('/a.png'); }", refused(customcss.RuleURL, 1)},
		{"a url() through an escaped letter", ".x { background: u\\rl(/a.png); }", refused(customcss.RuleURL, 1)},
		{"a url() whose value is escaped", ".x { background: url(\\68ttps://example.com/a.png); }", refused(customcss.RuleURL, 1)},
		{"a url() whose value spells data through an escape", ".x { background: url(\\64 ata:image/png,AAAA); }", nil},
		{"a url() in a custom property", ":root {\n  --picture: url(https://example.com/a.png);\n}", refused(customcss.RuleURL, 2)},
		{"a quoted url() in a custom property", ":root { --picture: url('/a.png'); }", refused(customcss.RuleURL, 1)},
		{"a url() in @font-face", "@font-face {\n  font-family: Mine;\n  src: url(/font.woff2) format(\"woff2\");\n}", refused(customcss.RuleURL, 3)},
		{"a url() after a comment holding one", "/* url(" + pngData + ") */ .x { background: url(/a.png); }", refused(customcss.RuleURL, 1)},
		{"a second url() after a data: image", ".x { background: url(" + pngData + "),\n  url(/a.png); }", refused(customcss.RuleURL, 2)},
		{"a quoted url() with more than its string", ".x { background: url(\"" + pngData + "\" var(--x)); }", refused(customcss.RuleURL, 1)},
		{"a quoted url() never closed", ".x { background: url(\"" + pngData + "\"", refused(customcss.RuleURL, 1)},
	})
}

func TestCheck_RefusedFunctions(t *testing.T) {
	cases := []checkCase{}
	for _, fn := range []string{"src", "image", "image-set", "-webkit-image-set"} {
		for _, arg := range []struct{ name, text string }{
			{"a path", `"/some/path"`},
			{"a data: image", `"` + pngData + `"`},
			{"a data: image in url()", "url(" + pngData + ")"},
			{"a var()", "var(--picture)"},
		} {
			cases = append(cases, checkCase{
				fn + "() holding " + arg.name,
				".x {\n  background-image: " + fn + "(" + arg.text + ");\n}",
				refused(customcss.RuleFunction, 2),
			})
		}
	}
	cases = append(cases, []checkCase{
		{"image-set() in upper case", ".x { background: IMAGE-SET(\"/a\" 1x); }", refused(customcss.RuleFunction, 1)},
		{"image-set() in mixed case", ".x { background: Image-Set(\"/a\" 1x); }", refused(customcss.RuleFunction, 1)},
		{"src() in upper case", ".x { background: SRC(\"/a\"); }", refused(customcss.RuleFunction, 1)},
		{"image() in mixed case", ".x { background: iMaGe(\"/a\"); }", refused(customcss.RuleFunction, 1)},
		{"-webkit-image-set() in upper case", ".x { background: -WEBKIT-IMAGE-SET(\"/a\" 1x); }", refused(customcss.RuleFunction, 1)},
		{"image-set() through an escape", ".x { background: \\69mage-set(\"/a\" 1x); }", refused(customcss.RuleFunction, 1)},
		{"image-set() through an escaped hyphen", ".x { background: image\\-set(\"/a\" 1x); }", refused(customcss.RuleFunction, 1)},
		{"src() through an escape", ".x { background: \\73 rc(\"/a\"); }", refused(customcss.RuleFunction, 1)},
		{"-webkit-image-set() through an escape", ".x { background: -webkit-\\69mage-set(\"/a\" 1x); }", refused(customcss.RuleFunction, 1)},
		{"image-set() under another vendor prefix", ".x { background: -moz-image-set(\"/a\" 1x); }", refused(customcss.RuleFunction, 1)},
		{"image() under a vendor prefix", ".x { background: -webkit-image(\"/a\"); }", refused(customcss.RuleFunction, 1)},
		{"src() under a vendor prefix", ".x { background: -o-src(\"/a\"); }", refused(customcss.RuleFunction, 1)},
		{"image-set() in a custom property's value", ":root {\n  --set: image-set(\"/a\" 1x);\n}", refused(customcss.RuleFunction, 2)},
		{"the probe's example", ":root { --picture: \"/some/path\"; }\n.auth-page {\n  background-image: image-set(var(--picture) 1x);\n}", refused(customcss.RuleFunction, 3)},
		{"the probe's example through -webkit-image-set()", ":root { --picture: \"/some/path\"; }\n.auth-page { background-image: -webkit-image-set(var(--picture) 1x); }", refused(customcss.RuleFunction, 2)},
		{"a variable naming another variable", ":root {\n  --path: \"/some/path\";\n  --picture: var(--path);\n}\n.auth-page { background-image: image-set(var(--picture) 1x); }", refused(customcss.RuleFunction, 5)},
		{"a var() whose fallback is the string", ".auth-page { background-image:\n  image-set(var(--unset, \"/some/path\") 1x); }", refused(customcss.RuleFunction, 2)},
		{"image-set() after a comment and a string holding it", "/* image-set( */ .x::before { content: \"image-set(\"; }\n.x { background: image-set(\"/a\" 1x); }", refused(customcss.RuleFunction, 2)},
	}...)
	runCases(t, cases)
}

func TestCheck_Malformed(t *testing.T) {
	runCases(t, []checkCase{
		{"url(var(--x))", ":root { --picture: url(" + pngData + "); }\n.x { background: url(var(--picture)); }", refused(customcss.RuleMalformed, 2)},
		{"url( var(--x) ) with whitespace", ".x { background: url( var(--picture) ); }", refused(customcss.RuleMalformed, 1)},
		{"an unterminated comment", ".x { color: red; }\n/* never closed\n.y { color: blue; }", refused(customcss.RuleMalformed, 2)},
		{"an unterminated double-quoted string", ".x::before {\n  content: \"never closed", refused(customcss.RuleMalformed, 2)},
		{"an unterminated single-quoted string", ".x::before { content: 'never closed", refused(customcss.RuleMalformed, 1)},
		{"a string broken by a newline", ".x::before { content: \"one\ntwo\"; }", refused(customcss.RuleMalformed, 1)},
		{"an unterminated unquoted url()", "\n.x { background: url(" + pngData, refused(customcss.RuleMalformed, 2)},
		{"an unquoted url() holding whitespace", ".x { background: url(data:image/png a); }", refused(customcss.RuleMalformed, 1)},
		{"an unquoted url() holding a quote", ".x { background: url(data:image/png'a); }", refused(customcss.RuleMalformed, 1)},
		{"an unquoted url() holding a parenthesis", ".x { background: url(data:image/png(a); }", refused(customcss.RuleMalformed, 1)},
		{"an unquoted url() holding a control character", ".x { background: url(data:image/png\x01a); }", refused(customcss.RuleMalformed, 1)},
		{"an unquoted url() whose whitespace ends at the end", ".x { background: url(" + pngData + "  ", refused(customcss.RuleMalformed, 1)},
		{"an escape at the end", ".x { color: red; }\n.y\\", refused(customcss.RuleMalformed, 2)},
		{"an escape at the end of a string", ".x::before { content: \"a\\", refused(customcss.RuleMalformed, 1)},
		{"a backslash before a newline outside a string", ".x { color: red; }\n.y \\\n{ color: blue; }", refused(customcss.RuleMalformed, 2)},
		{"an unterminated comment holding @import", "/* @import 'a.css';", refused(customcss.RuleMalformed, 1)},
	})
}

func TestCheck_Lines(t *testing.T) {
	runCases(t, []checkCase{
		{"CRLF counts as one line break", ".x { color: red; }\r\n.y { color: blue; }\r\n@import 'a.css';", refused(customcss.RuleImport, 3)},
		{"CR counts as a line break", ".x { color: red; }\r@import 'a.css';", refused(customcss.RuleImport, 2)},
		{"a form feed counts as a line break", ".x { color: red; }\f@import 'a.css';", refused(customcss.RuleImport, 2)},
		{"line breaks inside a comment count", "/* one\ntwo\nthree */ .x { background: url(/a.png); }", refused(customcss.RuleURL, 3)},
		{"an escaped line break inside a string counts", ".x::before { content: \"one\\\ntwo\"; }\n@import 'a.css';", refused(customcss.RuleImport, 3)},
		{"the first refusal in the text wins", ".x { background: url(/a.png); }\n@import 'a.css';\n.y::before { content: \"never closed", refused(customcss.RuleURL, 1)},
		{"a malformed token before a refusal wins", "\n/* never closed\n@import 'a.css';", refused(customcss.RuleMalformed, 2)},
	})
}

// sized answers CSS that passes, of exactly n bytes: a rule, then a comment filling the rest.
func sized(n int) string {
	const head = ".x { color: red; }\n/*"
	const tail = "*/"
	return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
}
