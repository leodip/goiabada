package guard

// The cap AssertScriptSyntax enforces, each construct newer than ES2020 and each script no browser
// parses over a script it must refuse, the ES2020 a page may use over scripts it must admit, the
// acorn release held to its pin, and the reporting half driven through Run.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pastTheCap = "syntax newer than ES2020, the cap: "
	unparsed   = "does not parse: "
)

// scriptDetails runs the check once over every script given, keyed by name, and returns each one's
// findings.
func scriptDetails(t *testing.T, sources map[string]string) map[string][]string {
	t.Helper()
	scripts := make([]scriptFile, 0, len(sources))
	for name, src := range sources {
		scripts = append(scripts, scriptFile{Path: name, Source: src})
	}
	found, err := findScriptSyntaxProblems(scripts)
	require.NoError(t, err)
	details := map[string][]string{}
	for _, f := range found {
		details[f.path] = append(details[f.path], f.detail)
	}
	return details
}

func TestScriptSyntax_TheCapTable(t *testing.T) {
	refused := []struct {
		name string
		src  string
		want string
	}{
		{"a syntax error", "function (", unparsed},
		{"logical and-assignment", "a &&= b;", pastTheCap},
		{"logical or-assignment", "a ||= b;", pastTheCap},
		{"nullish assignment", "a ??= b;", pastTheCap},
		{"a numeric separator", "const n = 1_000;", pastTheCap},
		{"a class field", "class A { x = 1; }", pastTheCap},
		{"a private field", "class A { #x = 1; }", pastTheCap},
		{"a private method", "class A { #m() {} }", pastTheCap},
		{"a private member read", "class A { #x = 1; m() { return this.#x; } }", pastTheCap},
		{"a static block", "class A { static { init(); } }", pastTheCap},
		{"the d flag", "const r = /a/d;", pastTheCap},
		{"the v flag", "const r = /[a]/v;", pastTheCap},
		{"an inline modifier", "const r = /(?i:a)b/;", pastTheCap},
		{"a hashbang", "#!/usr/bin/env node\nx();", pastTheCap},
		{"top-level await, a module's alone", "await load();", unparsed},
		{"an import", `import { a } from "./a.js";`, unparsed},
		{"an export", "export const a = 1;", unparsed},
		{"import.meta", "console.log(import.meta.url);", unparsed},
		{"for await outside an async function", "for await (const x of y) {}", unparsed},
		{"an assignment to a literal", "const x = 1; 1 = x;", unparsed},
		{"a compound assignment to a call", "f() += 1;", unparsed},
		{"an assignment to an optional chain", "a?.b = 1;", unparsed},
		{"an assignment through an optional chain", "a?.b.c = 1;", unparsed},
		{"an increment of a literal", "1++;", unparsed},
		{"a literal in a destructuring pattern", "[1] = x;", unparsed},
		{"a nested literal in a destructuring pattern", "({ a: [b, 2] } = x);", unparsed},
		{"a rest element with a default", "let a; [...a = []] = x;", unparsed},
		{"a rest element before the last", "let a, b; [...a, b] = x;", unparsed},
		{"a rest property with a default", "let a; ({ ...a = 1 } = x);", unparsed},
		{"a rest property holding a pattern", "let a; ({ ...{ a } } = x);", unparsed},
		{"an unclosed group", "const r = /(/;", unparsed},
		{"a stray group end", "const r = /a)/;", unparsed},
		{"an unclosed character class", "const r = /[a/;", unparsed},
		{"an unknown group syntax", "const r = /(?x)/;", unparsed},
		{"a quantifier with nothing to repeat", "const r = /a|*b/;", unparsed},
		{"a repeated flag", "const r = /a/gg;", unparsed},
		{"an unknown flag", "const r = /a/q;", unparsed},
		{"a class range out of order", "const r = /[z-a]/;", unparsed},
		{"a class range ending before an escaped start", `const r = /[\x7a-a]/;`, unparsed},
		{"a class range with a set at one end under u", `const r = /[\d-z]/u;`, unparsed},
		{"a group name used twice", "const r = /(?<x>a)(?<x>b)/;", unparsed},
		{"a group name used twice, once escaped", `const r = /(?<a>x)(?<a>y)/;`, unparsed},
	}
	admitted := map[string]string{
		"optional chaining and nullish coalescing": "const a = b?.c ?? d;",
		"BigInt":                                            "const n = 10n;",
		"await in an async function":                        "async function f() { await g(); for await (const x of y) {} }",
		"await in an async arrow":                           "const f = async () => { await g(); };",
		"await in an async method":                          "class A { async m() { await g(); } }",
		"classes with methods":                              "class A extends B { constructor() { super(); } get x() { return 1; } static s() {} }",
		"spread and destructuring":                          "const { a, ...rest } = o; const b = [...rest];",
		"template literals":                                 "const s = `a ${b} c`;",
		"a regular expression":                              "const r = /a(?:b)c/gimsuy;",
		"regular expressions a browser compiles":            `const r = [/[(]/, /\(/, /(?<y>\d{4})-(?=\d)(?!x)(?<=a)(?<!b)/u, /a+?b*?c??/, /[\]]/];`,
		"destructuring, compound and grouped assignments":   "let a, b; [a, b] = [b, a]; ({ a } = o); a += 1; (b) = 2; o.p++; o[k]--;",
		"a modifier-like class and a Unicode group name":    `const r = [/[(?i:)]/, /(?<π>a)\k<π>/u, /[a-z0-9_-]/, /[\d-z]/];`,
		"destructuring with defaults, rest and nesting":     "let a, b, c; [a = 1, , ...b] = x; ({ a, b: { c = 2 }, ...b } = x);",
		"a rest element holding a pattern":                  "let a, b; [...[a, b]] = x;",
		"class ranges between escapes a browser decodes":    `const r = [/[z-\x7e]/, /[\b-\t]/, /[\0-\x1f]/, /[\cA-\cZ]/, /[A-\u{5a}]/u, /[😀-🙏]/u, /[\p{L}-]/u];`,
		"group names with escapes and combining marks":      "const r = [/(?<\\u0061b>x)\\k<ab>/, /(?<éx>a)/, /(?<\\u{62}>a)/];",
		"a number with a decimal":                           "const n = 1.5e3;",
		"an await identifier is a name in a script":         "const await = 1;",
		"strict mode and a function declared in a block":    `"use strict"; if (a) { function f() {} }`,
		"a getter, a setter and a computed name in a class": "class A { get [k]() { return 1; } set v(x) {} }",
	}

	sources := map[string]string{}
	for _, tc := range refused {
		sources[tc.name] = tc.src
	}
	for name, src := range admitted {
		sources[name] = src
	}
	details := scriptDetails(t, sources)

	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			require.Len(t, details[tc.name], 1, "%v", details[tc.name])
			assert.True(t, strings.HasPrefix(details[tc.name][0], tc.want), "%s", details[tc.name][0])
		})
	}
	for name := range admitted {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, details[name])
		})
	}
}

// The acorn the check embeds is the release versions.yaml pins, byte for byte.
func TestScriptSyntax_AcornIsThePinnedRelease(t *testing.T) {
	const versionsYAML = "../../authserver/versions.yaml"
	content, err := os.ReadFile(versionsYAML)
	require.NoError(t, err)
	pin := regexp.MustCompile(`(?m)^  acorn-sha256: "([0-9a-f]{64})"$`).FindStringSubmatch(string(content))
	require.NotNil(t, pin, "%s pins no vendored.acorn-sha256", versionsYAML)

	acorn, err := scriptCheck.ReadFile("scriptcheck/acorn.js")
	require.NoError(t, err)
	sum := sha256.Sum256(acorn)
	assert.Equal(t, pin[1], hex.EncodeToString(sum[:]),
		"scriptcheck/acorn.js is not the release versions.yaml pins; run ./version-manager.sh update")
}

func TestScriptSyntax_TheGuardFailsOnATreeThatBreaksTheCap(t *testing.T) {
	fsys := fstest.MapFS{
		"static/a.js": {Data: []byte("a ??= 1;")},
		"static/b.js": {Data: []byte("const b = 1;")},
	}

	report := Run(func(r Reporter) { assertScriptSyntax(r, fsys, "static") })

	require.True(t, report.Failed(), "a script past the cap passed the guard")
	assert.Contains(t, report.Text(), "static/a.js: "+pastTheCap)
	assert.NotContains(t, report.Text(), "static/b.js")
}

func TestScriptSyntax_TheGuardPassesACleanTree(t *testing.T) {
	fsys := fstest.MapFS{
		"static/a.js":            {Data: []byte("function f(x) { return x?.y ?? 0; }")},
		"static/vendor/lib.js":   {Data: []byte("var lib = {};")},
		"static/main.css":        {Data: []byte("a ??= b")},
		"static/pages/a-page.js": {Data: []byte("document.querySelectorAll('x').forEach(function (e) { f(e); });")},
	}

	report := Run(func(r Reporter) { assertScriptSyntax(r, fsys, "static") })

	assert.False(t, report.Failed(), "a clean tree failed the guard: %s", report.Text())
}

func TestScriptSyntax_AWalkThatReachesNothingIsFatal(t *testing.T) {
	fsys := fstest.MapFS{"static/main.css": {Data: []byte("body{}")}}

	report := Run(func(r Reporter) { assertScriptSyntax(r, fsys, "static") })

	require.True(t, report.Stopped, "an empty walk must be fatal rather than a pass")
	assert.Contains(t, report.Fatal, "walked no .js files under static")

	missing := Run(func(r Reporter) { assertScriptSyntax(r, fsys, "scripts") })
	require.True(t, missing.Stopped)
	assert.Contains(t, missing.Fatal, "walking scripts under scripts")
}

// Without Node the guard stops rather than passing what it never read.
func TestScriptSyntax_NodeNotOnThePathIsFatal(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	fsys := fstest.MapFS{"static/a.js": {Data: []byte("a ??= 1;")}}

	report := Run(func(r Reporter) { assertScriptSyntax(r, fsys, "static") })

	require.True(t, report.Stopped, "a guard that cannot run passed")
	assert.Contains(t, report.Fatal, "node is not on PATH")
}
