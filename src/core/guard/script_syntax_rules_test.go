package guard

// The cap AssertScriptSyntax enforces, each construct newer than ES2020 over a script it must refuse,
// the ES2020 a page may use over scripts it must admit, and the reporting half driven through Run.

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scriptDetails(src string) []string {
	found := findScriptSyntaxProblems("static/t.js", []byte(src))
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.detail)
	}
	return out
}

func TestScriptSyntax_TheCapTable(t *testing.T) {
	refused := []struct {
		name string
		src  string
		want string
	}{
		{"a syntax error", "function (", "does not parse: "},
		{"logical and-assignment", "a &&= b;", "the logical assignment &&= is ES2021"},
		{"logical or-assignment", "a ||= b;", "the logical assignment ||= is ES2021"},
		{"nullish assignment", "a ??= b;", "the logical assignment ??= is ES2021"},
		{"a numeric separator", "const n = 1_000;", "the numeric separator in 1_000 is ES2021"},
		{"a class field", "class A { x = 1; }", "class field x is ES2022"},
		{"a private field", "class A { #x = 1; }", "class field #x is ES2022"},
		{"a private method", "class A { #m() {} }", "private class member #m is ES2022"},
		{"a private member read", "class A { m() { return this.#x; } }", "private member #x is ES2022"},
		{"a static block", "class A { static { init(); } }", "a class static block is ES2022"},
		{"top-level await", "await load();", "await outside an async function is top-level await, ES2022, and a module's alone"},
		{"the d flag", "const r = /a/d;", "the regular expression flag d, in /a/d, is ES2022"},
		{"the v flag", "const r = /[a]/v;", "the regular expression flag v, in /[a]/v, is ES2024"},
		{"an inline modifier", "const r = /(?i:a)b/;", "an inline modifier group, in /(?i:a)b/, is ES2025"},
		{"a hashbang", "#!/usr/bin/env node\nx();", "line 1: a hashbang is ES2023"},
		{"an import", `import { a } from "./a.js";`, "import is module syntax, which a classic script cannot use"},
		{"an export", "export const a = 1;", "export is module syntax, which a classic script cannot use"},
		{"import.meta", "console.log(import.meta.url);", "import.meta is module syntax, which a classic script cannot use"},
		{"for await outside an async function", "for await (const x of y) {}", "for await outside an async function is a syntax error in a script"},
		{"an assignment to a literal", "const x = 1; 1 = x;", "= assigns to 1, which is not a variable, a property or a destructuring pattern"},
		{"a compound assignment to a call", "f() += 1;", "+= assigns to (f()), which is not a variable, a property or a destructuring pattern"},
		{"an assignment to an optional chain", "a?.b = 1;", "which is not a variable, a property or a destructuring pattern"},
		{"an increment of a literal", "1++;", "changes 1, which is not a variable or a property"},
		{"an unclosed group", "const r = /(/;", "the regular expression /(/ is refused by a browser: a group is not closed"},
		{"a stray group end", "const r = /a)/;", "the regular expression /a)/ is refused by a browser: a group is closed that was never opened"},
		{"an unclosed character class", "const r = /[a/;", "does not parse: unexpected EOF or newline in regular expression"},
		{"an unknown group syntax", "const r = /(?x)/;", "the regular expression /(?x)/ is refused by a browser: a group starts with an unknown (? syntax"},
		{"a quantifier with nothing to repeat", "const r = /a|*b/;", "the regular expression /a|*b/ is refused by a browser: a quantifier has nothing to repeat"},
		{"a repeated flag", "const r = /a/gg;", "the regular expression /a/gg has the flag g twice"},
		{"a class range out of order", "const r = /[z-a]/;", "the regular expression /[z-a]/ is refused by a browser: a character class range is out of order"},
		{"a group name used twice", "const r = /(?<x>a)(?<x>b)/;", "the regular expression /(?<x>a)(?<x>b)/ is refused by a browser: the group name x is used twice"},
		{"a literal in a destructuring pattern", "[1] = x;", "which is not a variable, a property or a destructuring pattern"},
		{"a nested literal in a destructuring pattern", "({ a: [b, 2] } = x);", "which is not a variable, a property or a destructuring pattern"},
		{"an assignment through an optional chain", "a?.b.c = 1;", "which is not a variable, a property or a destructuring pattern"},
		{"an unknown flag", "const r = /a/q;", "the regular expression /a/q has the unknown flag q"},
		{"a class range ending before an escaped start", "const r = /[\\x7a-a]/;", "the regular expression /[\\x7a-a]/ is refused by a browser: a character class range is out of order"},
		{"a class range with a set at one end under u", "const r = /[\\d-z]/u;", "a character class range has a set such as \\d at one end"},
		{"a group name used twice, once escaped", "const r = /(?<a>x)(?<\\u0061>y)/;", "the group name a is used twice"},
		{"a rest element with a default", "let a; [...a = []] = x;", "which is not a variable, a property or a destructuring pattern"},
		{"a rest element before the last", "let a, b; [...a, b] = x;", "which is not a variable, a property or a destructuring pattern"},
		{"a rest property with a default", "let a; ({ ...a = 1 } = x);", "which is not a variable, a property or a destructuring pattern"},
		{"a rest property holding a pattern", "let a; ({ ...{ a } } = x);", "which is not a variable, a property or a destructuring pattern"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			details := scriptDetails(tc.src)
			require.Len(t, details, 1, "%v", details)
			assert.Contains(t, details[0], tc.want)
		})
	}

	admitted := map[string]string{
		"optional chaining and nullish coalescing": "const a = b?.c ?? d;",
		"BigInt":                                               "const n = 10n;",
		"await in an async function":                           "async function f() { await g(); for await (const x of y) {} }",
		"await in an async arrow":                              "const f = async () => { await g(); };",
		"await in an async method":                             "class A { async m() { await g(); } }",
		"classes with methods":                                 "class A extends B { constructor() { super(); } get x() { return 1; } static s() {} }",
		"spread and destructuring":                             "const { a, ...rest } = o; const b = [...rest];",
		"template literals":                                    "const s = `a ${b} c`;",
		"a regular expression":                                 "const r = /a(?:b)c/gimsuy;",
		"regular expressions a browser compiles":               "const r = [/[(]/, /\\(/, /(?<y>\\d{4})-(?=\\d)(?!x)(?<=a)(?<!b)/u, /a+?b*?c??/, /[\\]]/];",
		"destructuring, compound and grouped assignments":      "let a, b; [a, b] = [b, a]; ({ a } = o); a += 1; (b) = 2; o.p++; o[k]--;",
		"a modifier-like class and a Unicode group name":       "const r = [/[(?i:)]/, /(?<π>a)\\k<π>/u, /[a-z0-9_-]/, /[\\d-z]/];",
		"destructuring with defaults, rest and nesting":        "let a, b, c; [a = 1, , ...b] = x; ({ a, b: { c = 2 }, ...b } = x);",
		"for await in an async function":                       "async function f() { for await (const x of y) {} }",
		"class ranges between escapes a browser decodes":       "const r = [/[z-\\x7e]/, /[\\b-\\t]/, /[\\0-\\x1f]/, /[\\cA-\\cZ]/, /[\\u0041-\\u{5a}]/u, /[\\uD83D\\uDE00-\\uD83D\\uDE4F]/u, /[\\p{L}-]/u];",
		"group names with escapes and combining marks":         "const r = [/(?<\\u0061b>x)\\k<ab>/, /(?<e\u0301x>a)/, /(?<\\u{62}>a)/];",
		"a rest element holding a pattern":                     "let a, b; [...[a, b]] = x;",
		"a number with a decimal":                              "const n = 1.5e3;",
		"an await identifier is a name in a script, unawaited": "const delay = 1;",
	}
	for name, src := range admitted {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, scriptDetails(src))
		})
	}
}

func TestScriptSyntax_TheGuardFailsOnATreeThatBreaksTheCap(t *testing.T) {
	fsys := fstest.MapFS{
		"static/a.js": {Data: []byte("a ??= 1;")},
		"static/b.js": {Data: []byte("const b = 1;")},
	}

	report := Run(func(r Reporter) { assertScriptSyntax(r, fsys, "static") })

	require.True(t, report.Failed(), "a script past the cap passed the guard")
	assert.Contains(t, report.Text(), "static/a.js: the logical assignment ??= is ES2021")
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
