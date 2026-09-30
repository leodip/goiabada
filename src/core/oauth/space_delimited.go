package oauth

import "strings"

// isSpaceDelimiter is RE2's \s: space, tab, newline, form feed, carriage return.
//
// RFC 6749 section 3.3 delimits a scope with %x20 alone, and OIDC Core 1.0 section 3.1.2.1 says the
// same of response_type, prompt, ui_locales and acr_values. The wider set is what the `\s+` regexes
// this rule replaced matched (#116), kept because a client that puts a tab between two scopes works
// today. It is deliberately not unicode.IsSpace, which strings.Fields uses: that also splits on
// vertical tab, U+0085 and U+00A0, and #244 part 4 dropped those for every parameter that is
// delimited by space, since no client can be relying on a no-break space to mean a separator.
func isSpaceDelimiter(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\f' || r == '\r'
}

// SplitSpaceDelimited splits the value of a space-delimited request parameter (scope, response_type,
// prompt, acr_values, ui_locales) into its values: on runs of isSpaceDelimiter, each value trimmed
// with strings.TrimSpace, empty values dropped. Duplicates are kept.
//
// The trim is what the scope splitter has always done: FieldsFunc leaves a value with no delimiter
// in it, and TrimSpace then takes vertical tab, U+0085 and U+00A0 off its edges, so a value padded
// with one of them is still recognised. Only a separator inside a value changed with #244.
//
// One function for the five, so each reads a parameter the way the others do: where response_type,
// prompt and ui_locales split with strings.Fields and scope with its own function, a value with a
// no-break space was two tokens to some readers and one to others, and prompt's two readers, the
// handler's silence test and the validator's parse, could disagree (#244).
func SplitSpaceDelimited(value string) []string {
	values := []string{}
	for _, field := range strings.FieldsFunc(value, isSpaceDelimiter) {
		if field = strings.TrimSpace(field); field != "" {
			values = append(values, field)
		}
	}
	return values
}
