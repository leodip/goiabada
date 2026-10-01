package oauth

import "strings"

// IsWellFormedSpaceDelimited reports whether value is a list of values each separated from the next
// by exactly one space (U+0020), with no space before the first or after the last. An empty value
// is well formed and holds no values: RFC 6749 section 3.1 treats a parameter sent without a value
// as omitted, and each reader decides what an omitted one means.
//
// This is RFC 6749 section 3.3's grammar for scope, scope-token *( SP scope-token ), and section
// 3.1.1's for response_type, response-name *( SP response-name ); OIDC Core 1.0 section 3.1.2.1
// calls prompt, ui_locales and acr_values space delimited in the same sense. Only the separators
// are judged here. What a value may hold is each parameter's own vocabulary, every one of them
// narrower than the grammar's characters: a scope a resource or OIDC defines, one of three response
// types, one of four prompt values, an ACR level, a BCP 47 tag. So a tab, a newline or a no-break
// space between two words is not a separator but part of one value, which that vocabulary then
// refuses or ignores as unrecognised.
//
// The separators used to be any of space, tab, newline, form feed and carriage return, in runs, with
// the same characters and vertical tab, U+0085 and U+00A0 trimmed off each value's edges, a leniency
// the grammar does not allow (#244).
func IsWellFormedSpaceDelimited(value string) bool {
	return !strings.HasPrefix(value, " ") && !strings.HasSuffix(value, " ") && !strings.Contains(value, "  ")
}

// SplitSpaceDelimited splits the value of a space-delimited request parameter (scope, response_type,
// prompt, acr_values, ui_locales) into its values on the space (U+0020) alone. Duplicates are kept.
//
// It splits whatever it is handed and judges nothing: a run of spaces, or one at either end, yields
// no empty value. Whether the value was well formed is IsWellFormedSpaceDelimited's question, which
// every reader of a request parameter asks before acting on the split, and which a stored value,
// written with single spaces, has already answered. Splitting a malformed value anyway is what lets
// the authorization endpoint see that a malformed prompt still asks for none, and so must not be
// shown a login page before it is refused.
//
// One function for the five, so each reads a parameter the way the others do: where response_type,
// prompt and ui_locales split with strings.Fields and scope with its own function, a value with a
// no-break space was two tokens to some readers and one to others, and prompt's two readers, the
// handler's silence test and the validator's parse, could disagree (#244).
func SplitSpaceDelimited(value string) []string {
	values := []string{}
	for _, field := range strings.Split(value, " ") {
		if field != "" {
			values = append(values, field)
		}
	}
	return values
}
