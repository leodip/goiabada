package main

import (
	"fmt"
	"strings"
)

// Every value the generators interpolate goes through one of the three helpers below, safe or not,
// because the operator's answers reach YAML, Compose and a shell unescaped otherwise: a `: ` or a
// leading `*` made Compose refuse the file, ` #` cut the admin password down to what preceded it, a
// `$` was interpolated by Compose, and a backtick in the env file ran a command under `source`.
// Deciding per value whether quoting is needed is where YAML's traps are (`yes`, `~`, `0123`), so
// nothing decides: every value is quoted (#430).

// yamlQuote writes s as a YAML double-quoted scalar, the one style that can carry any string (YAML
// 1.2.2, section 7.3.1), escaping the two characters the style reserves, `\` and `"`, and every
// character outside YAML's printable set (section 5.1), plus the line breaks YAML 1.1 parsers still
// fold (NEL, LS, PS) and the byte order mark. Everything else is written as it is.
//
// s must be valid UTF-8: a YAML stream is Unicode, so an invalid byte has no spelling. The wizard
// refuses such a value where it is read (checkWritable), and yamlQuote would otherwise write it as
// U+FFFD.
func yamlQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02X`, r)
		case (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 || r == 0xfeff || r == 0xfffe || r == 0xffff:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// composeQuote writes s as a YAML double-quoted scalar Compose reads back as s. Compose
// interpolates any `$` that starts a valid variable, substitutes an unset one with an empty
// string, and reads `$$` as a literal `$` (compose-spec, Interpolation), so every `$` is doubled
// before the YAML quoting, and a value is never read as a variable reference. A healthcheck that
// means the container's own variable writes `${NAME}` through here and gets the `$${NAME}` Compose
// hands to the container's shell.
func composeQuote(s string) string {
	return yamlQuote(strings.ReplaceAll(s, "$", "$$"))
}

// envQuote writes s as a double-quoted value that a POSIX shell's `.` and systemd's
// EnvironmentFile= both read back as s. Inside double quotes a shell keeps every character literal
// except `$`, backquote and `\`, and `\` escapes exactly those three, `"` and a newline (POSIX XCU
// 2.2.3); systemd.exec(5) recognises "the same escape sequences as in POSIX shell double-quoted
// text", a `\` before any of `"\`$` preserving that character. Escaping those four makes the one
// form mean the same to both, a newline included, since a newline preceded by nothing is kept by
// both. s must be valid UTF-8 and hold no NUL, which a process environment cannot carry; the
// wizard refuses both where it reads them (checkWritable).
func envQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		if r == '\\' || r == '"' || r == '$' || r == '`' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}
