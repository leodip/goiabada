package customerrors

import (
	"strings"
	"unicode/utf8"
)

// maxErrorDescriptionBytes bounds what ConformErrorDescription returns.
//
// 512 is measured rather than picked. The longest description this server produces with nothing
// interpolated into it is 214 characters:
//
//	grep -ohE '"[A-Z][^"]{40,}"' src/core/validators/*_validator.go | awk '{print length($0)-2}' | sort -rn | head -1
//
// so the bound is more than double the longest legitimate text and truncates nothing the server says
// on its own account. What it does bound is the part a caller chose: a description interpolates
// request text, and an unbounded one ends up both on the wire and, since #213's deferral, inside a
// cookie whose store caps a session at 50 chunks.
const maxErrorDescriptionBytes = 512

// conformingErrorDescriptionRune answers whether r is admitted by RFC 6749 Appendix A.8's NQSCHAR.
func conformingErrorDescriptionRune(r rune) bool {
	return (r >= 0x20 && r <= 0x21) || (r >= 0x23 && r <= 0x5B) || (r >= 0x5D && r <= 0x7E)
}

// ConformErrorDescription returns description with every character RFC 6749 forbids in an
// error_description replaced by '?', and the result bounded to 512 bytes.
//
// RFC 6749 Appendix A.8 gives one production, and it governs sections 4.1.2.1, 4.2.2.1, 5.2 and 7.2
// alike, so the same rule binds the authorization endpoint's error redirect, the implicit flow's
// fragment and the token endpoint's JSON body:
//
//	error-description = 1*NQSCHAR
//	NQSCHAR = %x20-21 / %x23-5B / %x5D-7E
//
// That admits printable ASCII except the double quote (0x22) and the backslash (0x5C), and excludes
// every control character, DEL, and every byte above 0x7E, which is all of non-ASCII.
//
// The caller decides none of this. Descriptions interpolate request text, a rejected scope or a
// rejected prompt value, so without the filter an emoji in a scope puts 0xF0 into a protocol
// parameter (#213).
//
// Three properties the callers depend on:
//
// Replacement, not removal. A forbidden rune becomes exactly one '?', which is itself permitted.
// Dropping would turn 'a"b' into 'ab' and tell an integrator their scope was a string they never
// sent, which is worse than telling them a character could not be shown. One '?' per rune and not
// per byte, so a four-byte emoji becomes one character; a byte that is not valid UTF-8 has no rune
// to count and becomes one '?' on its own.
//
// The bound runs second, and the order is load-bearing: by then every character is one byte, so
// truncation cannot split a rune. A truncated result is exactly maxErrorDescriptionBytes bytes
// including the trailing "...", which is what says the text was cut rather than what the server
// meant to say.
//
// Idempotent, and conforming input under the bound is returned byte-identical. Both matter beyond
// tidiness: #213 filters at the parking site as well as at the emitter, and the description a client
// receives on the deferred path must be byte-identical to the one it receives on the immediate path.
func ConformErrorDescription(description string) string {
	conformed := replaceForbiddenRunes(description)

	if len(conformed) <= maxErrorDescriptionBytes {
		return conformed
	}
	return conformed[:maxErrorDescriptionBytes-len("...")] + "..."
}

// replaceForbiddenRunes is the first half of ConformErrorDescription: the character set, with no
// bound applied. It walks by rune rather than by byte so one forbidden rune costs one '?'.
func replaceForbiddenRunes(description string) string {
	// The overwhelmingly common case is a description that is already conforming, and it must come
	// back byte-identical, so scan first and build nothing when there is nothing to replace.
	needsReplacing := false
	for _, r := range description {
		if !conformingErrorDescriptionRune(r) {
			needsReplacing = true
			break
		}
	}
	if !needsReplacing {
		return description
	}

	var sb strings.Builder
	sb.Grow(len(description))
	for i := 0; i < len(description); {
		r, width := utf8.DecodeRuneInString(description[i:])
		if conformingErrorDescriptionRune(r) {
			sb.WriteRune(r)
		} else {
			// An invalid UTF-8 byte decodes as RuneError with width 1, and RuneError is itself
			// forbidden, so it lands here and advances one byte. A real U+FFFD in the input is
			// forbidden too and answers the same way, which is why the two need not be told apart.
			sb.WriteByte('?')
		}
		i += width
	}
	return sb.String()
}
