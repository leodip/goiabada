package customerrors

import (
	"strings"
	"testing"
)

// longestStaticDescription is the longest description this server produces with nothing
// interpolated into it, measured from the tree at 214 characters:
//
//	grep -ohE '"[A-Z][^"]{40,}"' src/core/validators/*_validator.go | awk '{print length($0)-2}' | sort -rn | head -1
//
// It is here rather than as a literal count so the passthrough row asserts against the real text.
const longestStaticDescription = "Id token scopes (such as '%v') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces."

// allPermittedCharacters returns every character RFC 6749 Appendix A.8 admits, once each, in order.
func allPermittedCharacters() string {
	var sb strings.Builder
	for c := 0x20; c <= 0x21; c++ {
		sb.WriteByte(byte(c))
	}
	for c := 0x23; c <= 0x5B; c++ {
		sb.WriteByte(byte(c))
	}
	for c := 0x5D; c <= 0x7E; c++ {
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

func TestConformErrorDescription(t *testing.T) {
	permitted := allPermittedCharacters()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			// KEEP THIS ROW. It reads as the least interesting one here and it is the claim every
			// unmoved assertion elsewhere in the tree rests on: the filter changes nothing this
			// server says on its own account, so no existing test had to move when it was added.
			name:     "conforming passthrough, the longest static description in the tree",
			input:    longestStaticDescription,
			expected: longestStaticDescription,
		},
		{
			name:     "every permitted character survives",
			input:    permitted,
			expected: permitted,
		},
		{
			// One '?', not four. The emoji is four bytes, and replacing per byte would tell the
			// integrator their scope held four characters it never held.
			name:     "emoji becomes one question mark per rune",
			input:    "Invalid scope format: '💣'.",
			expected: "Invalid scope format: '?'.",
		},
		{
			name:     "cyrillic becomes one question mark per rune",
			input:    "Invalid scope format: 'абв'.",
			expected: "Invalid scope format: '???'.",
		},
		{
			name:     "the double quote is forbidden even though it is printable ASCII",
			input:    "Invalid scope format: 'a\"b'.",
			expected: "Invalid scope format: 'a?b'.",
		},
		{
			name:     "the backslash is forbidden even though it is printable ASCII",
			input:    "Invalid scope format: 'a\\b'.",
			expected: "Invalid scope format: 'a?b'.",
		},
		{
			name:     "NUL is replaced",
			input:    "Invalid scope format: 'a\x00b'.",
			expected: "Invalid scope format: 'a?b'.",
		},
		{
			name:     "DEL is replaced",
			input:    "Invalid scope format: 'a\x7fb'.",
			expected: "Invalid scope format: 'a?b'.",
		},
		{
			// A lone 0x80 is not valid UTF-8, so there is no rune to count. It must become exactly
			// one '?' and must not panic or consume the bytes around it.
			name:     "an invalid UTF-8 byte becomes one question mark",
			input:    "a\x80b",
			expected: "a?b",
		},
		{
			name:     "over the bound is truncated to 512 bytes ending in an ellipsis",
			input:    strings.Repeat("a", 600),
			expected: strings.Repeat("a", 509) + "...",
		},
		{
			// KEEP THIS ROW. Exactly at the bound, so nothing is cut and no ellipsis is added. It is
			// the off-by-one guard on the row above, and it fails if the comparison is < rather
			// than <=.
			name:     "exactly at the bound is unchanged",
			input:    strings.Repeat("a", 512),
			expected: strings.Repeat("a", 512),
		},
		{
			name:     "empty stays empty",
			input:    "",
			expected: "",
		},
	}

	if len(longestStaticDescription) != 214 {
		t.Fatalf("longestStaticDescription is %d bytes, not the 214 the bound was chosen against; "+
			"recount with the grep in its comment", len(longestStaticDescription))
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConformErrorDescription(tt.input)
			if got != tt.expected {
				t.Errorf("ConformErrorDescription(%q):\n  got  %q\n  want %q", tt.input, got, tt.expected)
			}

			// Every result must satisfy the RFC's own predicate, asserted independently of the
			// expected string above so a wrong expectation cannot make a violating result pass.
			for i := 0; i < len(got); i++ {
				c := got[i]
				ok := (c >= 0x20 && c <= 0x21) || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E)
				if !ok {
					t.Errorf("ConformErrorDescription(%q) returned byte 0x%02x at %d, outside NQSCHAR",
						tt.input, c, i)
				}
			}

			if len(got) > 512 {
				t.Errorf("ConformErrorDescription(%q) returned %d bytes, over the 512 byte bound",
					tt.input, len(got))
			}

			// Idempotence, over every row rather than as a row of its own so it cannot fall behind
			// the table. #213 filters at the parking site and again at the emitter, and the two
			// paths must deliver the same bytes to the client.
			if twice := ConformErrorDescription(got); twice != got {
				t.Errorf("ConformErrorDescription is not idempotent on %q:\n  once  %q\n  twice %q",
					tt.input, got, twice)
			}
		})
	}
}
