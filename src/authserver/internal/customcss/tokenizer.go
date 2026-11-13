package customcss

import (
	"strings"
	"unicode/utf8"
)

// The tokenizer of CSS Syntax Level 3 section 4 (https://www.w3.org/TR/css-syntax-3/#tokenization),
// after the input is preprocessed as section 3.3 says. Each "consume" function below is the
// algorithm of section 4.3 of the same name. It answers only what the check reads: a token's kind
// among the few the check tells apart, its value for the kinds that have one the check reads, the
// line it starts on, and whether the tokenizer met a parse error in it.

type tokenKind int

const (
	tokenOther tokenKind = iota
	tokenWhitespace
	tokenString // a <string-token>, or a <bad-string-token> when malformed
	tokenURL    // a <url-token>, or a <bad-url-token> when malformed
	tokenFunction
	tokenAtKeyword
	tokenCloseParen
	tokenComment // only an unterminated comment, always malformed: a closed one makes no token
)

type token struct {
	kind  tokenKind
	value string
	line  int
	// malformed is whether the tokenizer met a parse error in the token.
	malformed bool
}

// eof is the code point peek answers past the end of the input.
const eof rune = -1

type tokenizer struct {
	src []rune
	pos int
	// bad records a parse error in the token being consumed.
	bad bool
	// lineAt's cursor: line is the line src[linePos] is on.
	linePos, line int
}

// tokenize answers the tokens of css, ending at its end with no <EOF-token>.
func tokenize(css string) []token {
	t := &tokenizer{src: preprocess(css), line: 1}
	var toks []token
	for {
		if start, closed := t.consumeComments(); !closed {
			toks = append(toks, token{kind: tokenComment, line: t.lineAt(start), malformed: true})
		}
		if t.pos >= len(t.src) {
			return toks
		}
		start := t.pos
		t.bad = false
		kind, value := t.consumeToken()
		if t.pos == start {
			// Every token consumes a code point; one that did not would loop here for ever on a
			// request's input, so it ends the input as malformed instead.
			return append(toks, token{line: t.lineAt(start), malformed: true})
		}
		toks = append(toks, token{kind: kind, value: value, line: t.lineAt(start), malformed: t.bad})
	}
}

// preprocess filters the input code points as section 3.3 says: a carriage return and line feed
// together, a carriage return alone and a form feed become one line feed, and U+0000, a surrogate
// and bytes that are not UTF-8 become U+FFFD.
func preprocess(css string) []rune {
	out := make([]rune, 0, len(css))
	for i := 0; i < len(css); {
		r, size := utf8.DecodeRuneInString(css[i:])
		i += size
		switch r {
		case '\r':
			if i < len(css) && css[i] == '\n' {
				i++
			}
			r = '\n'
		case '\f':
			r = '\n'
		case 0:
			r = utf8.RuneError
		}
		out = append(out, r)
	}
	return out
}

// lineAt answers the line, from 1, the code point at pos is on. Its calls come with positions that
// never go back.
func (t *tokenizer) lineAt(pos int) int {
	for ; t.linePos < pos; t.linePos++ {
		if t.src[t.linePos] == '\n' {
			t.line++
		}
	}
	return t.line
}

// peek answers the code point n after the current position, or eof.
func (t *tokenizer) peek(n int) rune {
	if t.pos+n < len(t.src) {
		return t.src[t.pos+n]
	}
	return eof
}

// consumeComments consumes every comment at the current position, and answers where the last one
// began and false when it is not closed, which consumes the rest of the input.
func (t *tokenizer) consumeComments() (int, bool) {
	for t.peek(0) == '/' && t.peek(1) == '*' {
		start := t.pos
		t.pos += 2
		for {
			if t.pos >= len(t.src) {
				return start, false
			}
			if t.peek(0) == '*' && t.peek(1) == '/' {
				t.pos += 2
				break
			}
			t.pos++
		}
	}
	return 0, true
}

// consumeToken is "consume a token", after its comments are consumed, with input left.
func (t *tokenizer) consumeToken() (tokenKind, string) {
	c := t.peek(0)
	switch {
	case isWhitespace(c):
		for isWhitespace(t.peek(0)) {
			t.pos++
		}
		return tokenWhitespace, ""
	case c == '"' || c == '\'':
		t.pos++
		return t.consumeString(c)
	case c == '#':
		t.pos++
		if isIdentCodePoint(t.peek(0)) || isValidEscape(t.peek(0), t.peek(1)) {
			t.consumeIdentSequence()
		}
		return tokenOther, ""
	case c == ')':
		t.pos++
		return tokenCloseParen, ""
	case c == '+' || c == '.':
		if startsNumber(c, t.peek(1), t.peek(2)) {
			return t.consumeNumeric()
		}
		t.pos++
		return tokenOther, ""
	case c == '-':
		if startsNumber(c, t.peek(1), t.peek(2)) {
			return t.consumeNumeric()
		}
		if t.peek(1) == '-' && t.peek(2) == '>' {
			t.pos += 3
			return tokenOther, "" // <CDC-token>
		}
		if startsIdentSequence(c, t.peek(1), t.peek(2)) {
			return t.consumeIdentLike()
		}
		t.pos++
		return tokenOther, ""
	case c == '<':
		if t.peek(1) == '!' && t.peek(2) == '-' && t.peek(3) == '-' {
			t.pos += 4
			return tokenOther, "" // <CDO-token>
		}
		t.pos++
		return tokenOther, ""
	case c == '@':
		t.pos++
		if startsIdentSequence(t.peek(0), t.peek(1), t.peek(2)) {
			return tokenAtKeyword, t.consumeIdentSequence()
		}
		return tokenOther, ""
	case c == '\\':
		if isValidEscape(c, t.peek(1)) {
			return t.consumeIdentLike()
		}
		t.bad = true
		t.pos++
		return tokenOther, ""
	case isDigit(c):
		return t.consumeNumeric()
	case isIdentStart(c):
		return t.consumeIdentLike()
	}
	// (, [, ], {, }, :, ; and , are tokens of their own, and anything else a <delim-token>: the
	// check tells none of them apart.
	t.pos++
	return tokenOther, ""
}

// consumeNumeric is "consume a numeric token": a <number-token>, a <percentage-token> or a
// <dimension-token>, whose unit is an ident sequence, so `1e3url(` is a dimension and a `(`.
func (t *tokenizer) consumeNumeric() (tokenKind, string) {
	t.consumeNumber()
	if startsIdentSequence(t.peek(0), t.peek(1), t.peek(2)) {
		t.consumeIdentSequence()
	} else if t.peek(0) == '%' {
		t.pos++
	}
	return tokenOther, ""
}

// consumeNumber is "consume a number", which the check needs only to move past.
func (t *tokenizer) consumeNumber() {
	if c := t.peek(0); c == '+' || c == '-' {
		t.pos++
	}
	t.consumeDigits()
	if t.peek(0) == '.' && isDigit(t.peek(1)) {
		t.pos += 2
		t.consumeDigits()
	}
	if c := t.peek(0); c == 'e' || c == 'E' {
		switch {
		case isDigit(t.peek(1)):
			t.pos += 2
			t.consumeDigits()
		case (t.peek(1) == '+' || t.peek(1) == '-') && isDigit(t.peek(2)):
			t.pos += 3
			t.consumeDigits()
		}
	}
}

func (t *tokenizer) consumeDigits() {
	for isDigit(t.peek(0)) {
		t.pos++
	}
}

// consumeIdentLike is "consume an ident-like token": an <ident-token>, a <function-token> or a
// <url-token>, its name read with its escapes, so `\75rl(` is url(. A url( followed by a quote,
// whitespace before it or not, is a <function-token> named url, with the string to follow.
func (t *tokenizer) consumeIdentLike() (tokenKind, string) {
	name := t.consumeIdentSequence()
	if t.peek(0) != '(' {
		return tokenOther, name
	}
	t.pos++
	if asciiLower(name) != "url" {
		return tokenFunction, name
	}
	for isWhitespace(t.peek(0)) && isWhitespace(t.peek(1)) {
		t.pos++
	}
	if isQuote(t.peek(0)) || (isWhitespace(t.peek(0)) && isQuote(t.peek(1))) {
		return tokenFunction, name
	}
	return t.consumeURL()
}

// consumeString is "consume a string token", ended by the quote it began with. A newline in it is
// a <bad-string-token>, and the input ending in it a parse error too.
func (t *tokenizer) consumeString(ending rune) (tokenKind, string) {
	var b strings.Builder
	for {
		c := t.peek(0)
		switch c {
		case ending:
			t.pos++
			return tokenString, b.String()
		case eof:
			t.bad = true
			return tokenString, b.String()
		case '\n':
			t.bad = true
			return tokenString, b.String()
		case '\\':
			t.pos++
			switch t.peek(0) {
			case eof:
			case '\n':
				t.pos++
			default:
				b.WriteRune(t.consumeEscapedCodePoint())
			}
		default:
			b.WriteRune(c)
			t.pos++
		}
	}
}

// consumeURL is "consume a url token", after url( and its whitespace. Whitespace inside the URL, a
// quote, a parenthesis, a code point that is not printable or an escape that is not valid makes it
// a <bad-url-token>, and the input ending before its ) is a parse error too.
func (t *tokenizer) consumeURL() (tokenKind, string) {
	var b strings.Builder
	for isWhitespace(t.peek(0)) {
		t.pos++
	}
	for {
		c := t.peek(0)
		switch {
		case c == ')':
			t.pos++
			return tokenURL, b.String()
		case c == eof:
			t.bad = true
			return tokenURL, b.String()
		case isWhitespace(c):
			for isWhitespace(t.peek(0)) {
				t.pos++
			}
			switch t.peek(0) {
			case ')':
				t.pos++
				return tokenURL, b.String()
			case eof:
				t.bad = true
				return tokenURL, b.String()
			}
			t.bad = true
			t.consumeBadURLRemnants()
			return tokenURL, b.String()
		case isQuote(c) || c == '(' || isNonPrintable(c):
			t.bad = true
			t.consumeBadURLRemnants()
			return tokenURL, b.String()
		case c == '\\':
			if !isValidEscape(c, t.peek(1)) {
				t.bad = true
				t.consumeBadURLRemnants()
				return tokenURL, b.String()
			}
			t.pos++
			b.WriteRune(t.consumeEscapedCodePoint())
		default:
			b.WriteRune(c)
			t.pos++
		}
	}
}

// consumeBadURLRemnants is "consume the remnants of a bad url", up to its ) or the input's end.
func (t *tokenizer) consumeBadURLRemnants() {
	for {
		c := t.peek(0)
		switch {
		case c == ')':
			t.pos++
			return
		case c == eof:
			return
		case isValidEscape(c, t.peek(1)):
			t.pos++
			t.consumeEscapedCodePoint()
		default:
			t.pos++
		}
	}
}

// consumeEscapedCodePoint is "consume an escaped code point", after its backslash: one to six hex
// digits and one whitespace after them, or any other code point as itself. The input ending is a
// parse error.
func (t *tokenizer) consumeEscapedCodePoint() rune {
	c := t.peek(0)
	if c == eof {
		t.bad = true
		return utf8.RuneError
	}
	t.pos++
	if !isHexDigit(c) {
		return c
	}
	value := hexValue(c)
	for n := 1; n < 6 && isHexDigit(t.peek(0)); n++ {
		value = value*16 + hexValue(t.peek(0))
		t.pos++
	}
	if isWhitespace(t.peek(0)) {
		t.pos++
	}
	if value == 0 || (value >= 0xD800 && value <= 0xDFFF) || value > utf8.MaxRune {
		return utf8.RuneError
	}
	return value
}

// consumeIdentSequence is "consume an ident sequence", its escapes read.
func (t *tokenizer) consumeIdentSequence() string {
	var b strings.Builder
	for {
		c := t.peek(0)
		switch {
		case isIdentCodePoint(c):
			b.WriteRune(c)
			t.pos++
		case isValidEscape(c, t.peek(1)):
			t.pos++
			b.WriteRune(t.consumeEscapedCodePoint())
		default:
			return b.String()
		}
	}
}

// isValidEscape is "check if two code points are a valid escape".
func isValidEscape(first, second rune) bool {
	return first == '\\' && second != '\n'
}

// startsIdentSequence is "check if three code points would start an ident sequence".
func startsIdentSequence(first, second, third rune) bool {
	switch {
	case first == '-':
		return isIdentStart(second) || second == '-' || isValidEscape(second, third)
	case isIdentStart(first):
		return true
	case first == '\\':
		return isValidEscape(first, second)
	}
	return false
}

// startsNumber is "check if three code points would start a number".
func startsNumber(first, second, third rune) bool {
	switch first {
	case '+', '-':
		return isDigit(second) || (second == '.' && isDigit(third))
	case '.':
		return isDigit(second)
	}
	return isDigit(first)
}

func isWhitespace(c rune) bool { return c == '\n' || c == '\t' || c == ' ' }

func isQuote(c rune) bool { return c == '"' || c == '\'' }

func isDigit(c rune) bool { return '0' <= c && c <= '9' }

func isHexDigit(c rune) bool {
	return isDigit(c) || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func hexValue(c rune) rune {
	switch {
	case isDigit(c):
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// isIdentStart is an "ident-start code point": a letter, a non-ASCII code point or _.
func isIdentStart(c rune) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c >= 0x80 || c == '_'
}

// isIdentCodePoint is an "ident code point": an ident-start code point, a digit or -.
func isIdentCodePoint(c rune) bool {
	return isIdentStart(c) || isDigit(c) || c == '-'
}

// isNonPrintable is a "non-printable code point".
func isNonPrintable(c rune) bool {
	return (c >= 0 && c <= 0x08) || c == 0x0B || (c >= 0x0E && c <= 0x1F) || c == 0x7F
}
