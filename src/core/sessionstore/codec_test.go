package sessionstore

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hex an environment variable carries, at the lengths the startup validators demand: 64
// bytes as 128 characters and 32 bytes as 64. The values are arbitrary. Only their shape
// matters here, because the length rule is the validators' and deliberately not this file's.
var (
	hexSessionAuthKey = strings.Repeat("ab", 64)
	hexSessionEncKey  = strings.Repeat("cd", 32)
)

func decodedSessionAuthKey() []byte { return bytes.Repeat([]byte{0xab}, 64) }
func decodedSessionEncKey() []byte  { return bytes.Repeat([]byte{0xcd}, 32) }

func TestDecodeKeyPair(t *testing.T) {
	cases := []struct {
		name    string
		auth    string
		enc     string
		want    KeyPair
		wantErr string
	}{
		{
			name: "the configured pair decodes to its bytes",
			auth: hexSessionAuthKey,
			enc:  hexSessionEncKey,
			want: KeyPair{
				AuthenticationKey: decodedSessionAuthKey(),
				EncryptionKey:     decodedSessionEncKey(),
			},
		},
		{
			name:    "an authentication key that is not hex is refused",
			auth:    strings.Repeat("zz", 64),
			enc:     hexSessionEncKey,
			wantErr: "unable to decode the session authentication key",
		},
		{
			name:    "an encryption key that is not hex is refused",
			auth:    hexSessionAuthKey,
			enc:     strings.Repeat("zz", 32),
			wantErr: "unable to decode the session encryption key",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pair, err := DecodeKeyPair(c.auth, c.enc)

			if c.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, c.want, pair)
		})
	}
}

func TestDecodePreviousKeyPair(t *testing.T) {
	cases := []struct {
		name    string
		auth    string
		enc     string
		want    *KeyPair
		wantErr string
	}{
		{
			// The case this helper exists for. A deployment that is not rotating gets nil,
			// never a KeyPair holding two empty keys: the second would satisfy "no error"
			// and "not rotating" while handing the store a permanently valid opening key
			// derived from nothing but the two info constants in codec.go.
			name: "neither variable set gives no pair at all",
			want: nil,
		},
		{
			// Config trims what it reads, so this is a caller that did not come through
			// config. A variable holding blanks is a variable nobody set.
			name: "a variable holding only whitespace counts as unset",
			auth: "   ",
			enc:  "\t",
			want: nil,
		},
		{
			name: "both variables set gives the decoded pair",
			auth: hexSessionAuthKey,
			enc:  hexSessionEncKey,
			want: &KeyPair{
				AuthenticationKey: decodedSessionAuthKey(),
				EncryptionKey:     decodedSessionEncKey(),
			},
		},
		{
			name:    "the authentication key alone is refused",
			auth:    hexSessionAuthKey,
			wantErr: "both the authentication key and the encryption key",
		},
		{
			name:    "the encryption key alone is refused",
			enc:     hexSessionEncKey,
			wantErr: "both the authentication key and the encryption key",
		},
		{
			name:    "an authentication key that is not hex is refused",
			auth:    strings.Repeat("zz", 64),
			enc:     hexSessionEncKey,
			wantErr: "unable to decode the session authentication key",
		},
		{
			name:    "an encryption key that is not hex is refused",
			auth:    hexSessionAuthKey,
			enc:     strings.Repeat("zz", 32),
			wantErr: "unable to decode the session encryption key",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pair, err := DecodePreviousKeyPair(c.auth, c.enc)

			if c.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), c.wantErr)
				assert.Nil(t, pair, "a refused pair is not handed back half built")
				return
			}

			require.NoError(t, err)
			if c.want == nil {
				assert.Nil(t, pair, "an absent previous pair is nil, not a zero-value KeyPair")
				return
			}
			require.NotNil(t, pair)
			assert.Equal(t, *c.want, *pair)
		})
	}
}

// TestNewServerSideStore_RefusesAKeyPairWithAnEmptyKey is the store-side half of what
// DecodePreviousKeyPair's comment describes. HKDF derives a valid key from an empty secret
// and an empty salt, the AEAD accepts it, and values seal and open under it, so a pair with
// no bytes in it is refused at construction rather than left to work.
//
// Through the constructor because that is the only door to the sealer, which is private and
// stays that way: a test that reached in would be testing the copy of the derivation it made
// to get there.
func TestNewServerSideStore_RefusesAKeyPairWithAnEmptyKey(t *testing.T) {
	cases := []struct {
		name     string
		current  KeyPair
		previous *KeyPair
	}{
		{
			name:    "the current pair has no bytes at all",
			current: KeyPair{},
		},
		{
			name:    "the current authentication key is empty",
			current: KeyPair{EncryptionKey: []byte(storeTestEncKey)},
		},
		{
			name:    "the current encryption key is empty",
			current: KeyPair{AuthenticationKey: []byte(storeTestAuthKey)},
		},
		{
			// The branch a binary would take if it built the previous pair from two empty
			// configuration values instead of leaving it nil.
			name:     "the previous pair has no bytes at all",
			current:  storeTestPair(),
			previous: &KeyPair{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store, err := NewServerSideStore(newFakeBackend(), "SessionIdentifier", false,
				c.current, c.previous)

			require.Error(t, err)
			assert.Nil(t, store, "a store that could not build its keys is not returned")
			assert.Contains(t, err.Error(), "non-empty")
		})
	}
}
