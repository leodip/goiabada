// Package customcss is the check a brand's custom CSS passes before it is saved (#816 decision 4).
// The CSS is read as tokens, by a tokenizer that follows CSS Syntax Level 3 section 4, because a
// browser reads `@\69mport` as `@import` and `\75rl(` as `url(`, so matching its text is not enough.
// With the check's rules a brand's CSS can make a browser request nothing at all: `@import` is
// refused, a URL passes only when it is a `data:` image, and `url()` is the only way to write one.
package customcss

import "strings"

// MaxBytes is the most bytes of UTF-8 a brand's custom CSS may hold: 64 KB.
const MaxBytes = 65536

// Rule is the rule of decision 4 a refused CSS breaks.
type Rule string

const (
	// RuleTooLarge refuses CSS of more than MaxBytes bytes.
	RuleTooLarge Rule = "too_large"
	// RuleImport refuses an `@import`, whatever it names.
	RuleImport Rule = "import"
	// RuleURL refuses a `url()` that is not a `data:` image, written quoted or unquoted.
	RuleURL Rule = "url"
	// RuleFunction refuses `src()`, `image()` and `image-set()`, under any vendor prefix too,
	// whatever they hold: each takes a plain string as a URL, which a `var()` can bring in.
	RuleFunction Rule = "function"
	// RuleMalformed refuses CSS that does not tokenize cleanly: a tokenizer parse error, such as
	// an unterminated comment, string or URL, an escape at the end, or `url(var(--x))`.
	RuleMalformed Rule = "malformed"
)

// Refusal is why Check refused a CSS text: the rule it breaks, and the line it is about, counted
// from 1, where a line ends at a line feed, a carriage return, both together or a form feed. A
// refusal of the size is about no line, and its Line is 0.
type Refusal struct {
	Rule Rule
	Line int
}

// refusedFunctions are the functions that take a plain string as a URL, refused whatever they hold.
var refusedFunctions = []string{"src", "image", "image-set"}

// Check answers nil when css passes decision 4's rules, and otherwise the refusal of the first
// thing in the text that breaks one. Blank CSS passes. Check reads css as it will be stored: it
// rewrites nothing.
func Check(css string) *Refusal {
	if len(css) > MaxBytes {
		return &Refusal{Rule: RuleTooLarge}
	}
	toks := tokenize(css)
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		switch {
		case tok.malformed:
			return &Refusal{Rule: RuleMalformed, Line: tok.line}
		case tok.kind == tokenAtKeyword && asciiLower(tok.value) == "import":
			return &Refusal{Rule: RuleImport, Line: tok.line}
		case tok.kind == tokenURL:
			if !isDataImage(tok.value) {
				return &Refusal{Rule: RuleURL, Line: tok.line}
			}
		case tok.kind == tokenFunction && asciiLower(tok.value) == "url":
			end, refusal := checkQuotedURL(toks, i)
			if refusal != nil {
				return refusal
			}
			i = end
		case tok.kind == tokenFunction && isRefusedFunction(tok.value):
			return &Refusal{Rule: RuleFunction, Line: tok.line}
		}
	}
	return nil
}

// checkQuotedURL checks the url( function token at toks[open], which the tokenizer answers for
// url( followed by a quote, and answers the index of the `)` that closes it. It passes when the
// function holds nothing but one string that is a data: image, with whitespace around it; a string
// that does not tokenize cleanly is refused as malformed, and anything else as a URL.
func checkQuotedURL(toks []token, open int) (int, *Refusal) {
	refusal := &Refusal{Rule: RuleURL, Line: toks[open].line}
	i := skipWhitespace(toks, open+1)
	if i >= len(toks) || toks[i].kind != tokenString {
		return 0, refusal
	}
	if toks[i].malformed {
		return 0, &Refusal{Rule: RuleMalformed, Line: toks[i].line}
	}
	if !isDataImage(toks[i].value) {
		return 0, refusal
	}
	i = skipWhitespace(toks, i+1)
	if i >= len(toks) || toks[i].kind != tokenCloseParen {
		return 0, refusal
	}
	return i, nil
}

func skipWhitespace(toks []token, i int) int {
	for i < len(toks) && toks[i].kind == tokenWhitespace {
		i++
	}
	return i
}

// isDataImage is whether a URL is a data: image, data:image/ in any case, as written: a URL with
// anything before its scheme is not one.
func isDataImage(url string) bool {
	return strings.HasPrefix(asciiLower(url), "data:image/")
}

// isRefusedFunction is whether a function's name is one of refusedFunctions, in any case, alone or
// under a vendor prefix: a hyphen, a name and a hyphen before it, as in -webkit-image-set.
func isRefusedFunction(name string) bool {
	name = asciiLower(name)
	for _, fn := range refusedFunctions {
		if name == fn {
			return true
		}
		if strings.HasPrefix(name, "-") && strings.HasSuffix(name, "-"+fn) && len(name) > len(fn)+2 {
			return true
		}
	}
	return false
}

// asciiLower lowers the ASCII letters of s alone, as CSS compares names ASCII case-insensitively:
// a non-ASCII letter that folds to an ASCII one is a different name to a browser.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
