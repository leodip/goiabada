package ratelimit

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// TestAccountKey_BoundsTheIdentifier pins the length bound on the account key.
// The key is retained by the limiter's store for two windows and comes straight off an
// unauthenticated form with no body cap, so what matters is that an arbitrarily long
// submission cannot become an arbitrarily long map entry, and that bounding it does not
// put two identifiers in one bucket: nothing caps an account identifier's length on the
// way in, so a threshold that folded would fold real accounts (#276).
func TestAccountKey_BoundsTheIdentifier(t *testing.T) {
	// The longest address there is: a 64-octet local-part and a 255-octet domain, the
	// maxima RFC 5321 sections 4.5.3.1.1 and 4.5.3.1.2 state.
	longestLocal := strings.Repeat("a", 64)
	longestDomain := strings.Repeat("b", 251) + ".com"
	longestAddress := longestLocal + "@" + longestDomain

	if len(longestAddress) != maxAccountIdentifierLen {
		t.Fatalf("setup: the longest address is %d octets, want %d",
			len(longestAddress), maxAccountIdentifierLen)
	}

	tests := []struct {
		name       string
		identifier string
		want       string
	}{
		{"an ordinary address is itself", "victim@example.com", "victim@example.com"},
		{"case and whitespace still normalize", "  VICTIM@Example.COM\t", "victim@example.com"},
		{"the longest possible address keeps its own bucket", longestAddress, longestAddress},
		{
			"whitespace is trimmed before the length is judged",
			"   " + longestAddress + "   ",
			longestAddress,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AccountKey(tc.identifier); got != tc.want {
				t.Errorf("AccountKey(%q) = %q, want %q", tc.identifier, got, tc.want)
			}
		})
	}

	// The identifier the store must never retain whole: net/http's form limit is the only
	// ceiling on it, and the limiter holds a key for two windows.
	huge := strings.Repeat("x", 10<<20) + "@example.com"

	t.Run("a form value at net/http's limit is digested rather than retained", func(t *testing.T) {
		got := AccountKey(huge)
		if len(got) != len(oversizedAccountKeyPrefix)+2*sha256.Size {
			// Truncated: an input of ten mebibytes has no place in a failure line.
			t.Errorf("AccountKey(%.20q...) is %d octets: %.80q", huge, len(got), got)
		}
		if !strings.HasPrefix(got, oversizedAccountKeyPrefix) {
			t.Errorf("key %.80q does not carry the digest prefix %q, so an audit reader "+
				"cannot tell it from an address", got, oversizedAccountKeyPrefix)
		}
	})

	t.Run("one octet past the bound is digested", func(t *testing.T) {
		if got := AccountKey(longestAddress + "x"); !strings.HasPrefix(got, oversizedAccountKeyPrefix) {
			t.Errorf("AccountKey(longestAddress+\"x\") = %.80q, want a digest", got)
		}
	})

	// The property the digest exists for, and the one a shared bucket cost. Nothing bounds
	// an account identifier's length on the way in: ValidateEmailAddress checks the shape
	// without a length, self-registration and the setup program use it, and users.email is
	// TEXT on sqlite. So an identifier past the bound can name a real account, and folding
	// would spend that account's budget on strangers' submissions (#276).
	t.Run("two distinct oversized identifiers keep distinct buckets", func(t *testing.T) {
		a := AccountKey(strings.Repeat("a", maxAccountIdentifierLen) + "@example.com")
		b := AccountKey(strings.Repeat("b", maxAccountIdentifierLen) + "@example.com")
		if a == b {
			t.Errorf("two distinct oversized identifiers both keyed as %.80q; want a bucket each", a)
		}
	})

	t.Run("an oversized identifier normalizes before it is digested", func(t *testing.T) {
		// Otherwise a long account has 2^n buckets from case alone, which is the whole
		// reason this function exists (#219).
		long := strings.Repeat("a", maxAccountIdentifierLen) + "@Example.COM"
		if got, want := AccountKey("  "+strings.ToUpper(long)+"\t"), AccountKey(long); got != want {
			t.Errorf("two spellings of one oversized identifier keyed as %.80q and %.80q; want one bucket",
				got, want)
		}
	})

	// The two branches have to be disjoint, or bounding the key reintroduces the shared
	// bucket it was meant to remove. A digest key is the eight-octet prefix and sixty-four
	// hex characters, seventy-two in all and far inside the bound, so it can be submitted
	// as an ordinary identifier; and it is not a secret, since reportTrip writes it to the
	// warning line and the audit event. Without the prefix test in AccountKey,
	// submitting one back lands in the bucket of the long identifier it names, with no
	// SHA-256 collision involved and without the sender ever knowing that identifier (#276).
	t.Run("a submission spelled as a digest key cannot reach a digested bucket", func(t *testing.T) {
		long := strings.Repeat("a", maxAccountIdentifierLen) + "@example.com"
		digested := AccountKey(long)
		if len(digested) > maxAccountIdentifierLen {
			t.Fatalf("setup: the digest key is %d octets, past the bound, so it could not be "+
				"submitted as an exact key in the first place", len(digested))
		}
		if got := AccountKey(digested); got == digested {
			t.Errorf("submitting %q back keyed as itself, so it shares the bucket of the "+
				"oversized identifier it names", digested)
		}
	})

	t.Run("the exact branch never emits a key carrying the digest prefix", func(t *testing.T) {
		// The last spelling also pins the order: normalizing before the prefix is tested
		// is what stops "<SHA256>" reaching the exact branch.
		for _, spelling := range []string{
			oversizedAccountKeyPrefix,
			oversizedAccountKeyPrefix + "victim@example.com",
			"  " + strings.ToUpper(oversizedAccountKeyPrefix) + "abc\t",
		} {
			got := AccountKey(spelling)
			if len(got) != len(oversizedAccountKeyPrefix)+2*sha256.Size {
				t.Errorf("AccountKey(%q) = %q, want a digest: an exact key carrying "+
					"the prefix shares a namespace with the digested ones", spelling, got)
			}
		}
	})
}
