package sessionstore

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hex a configuration value carries, at the lengths ParseKeys demands: 64 bytes as 128
// characters and 32 bytes as 64. The values are arbitrary. The previous pair's bytes differ
// from the current pair's, so a result that swapped the two generations fails.
var (
	hexSessionAuthKey         = strings.Repeat("ab", 64)
	hexSessionEncKey          = strings.Repeat("cd", 32)
	hexPreviousSessionAuthKey = strings.Repeat("12", 64)
	hexPreviousSessionEncKey  = strings.Repeat("34", 32)
)

func decodedSessionAuthKey() []byte         { return bytes.Repeat([]byte{0xab}, 64) }
func decodedSessionEncKey() []byte          { return bytes.Repeat([]byte{0xcd}, 32) }
func decodedPreviousSessionAuthKey() []byte { return bytes.Repeat([]byte{0x12}, 64) }
func decodedPreviousSessionEncKey() []byte  { return bytes.Repeat([]byte{0x34}, 32) }

// The names are test values rather than either application's, so a name that reached a
// message by any route but the argument fails the whole-message comparison.
const (
	testAuthName         = "TEST_AUTH"
	testEncName          = "TEST_ENC"
	testPreviousAuthName = "TEST_PREV_AUTH"
	testPreviousEncName  = "TEST_PREV_ENC"
)

// configuredKeys is a valid current pair and no previous pair, under the test names. Each
// row of TestParseKeys varies one thing from it.
func configuredKeys(edit func(*ConfiguredKeys)) ConfiguredKeys {
	keys := ConfiguredKeys{
		Authentication:         ConfiguredKey{Name: testAuthName, Value: hexSessionAuthKey},
		Encryption:             ConfiguredKey{Name: testEncName, Value: hexSessionEncKey},
		PreviousAuthentication: ConfiguredKey{Name: testPreviousAuthName},
		PreviousEncryption:     ConfiguredKey{Name: testPreviousEncName},
	}
	if edit != nil {
		edit(&keys)
	}
	return keys
}

func withPrevious(keys *ConfiguredKeys) {
	keys.PreviousAuthentication.Value = hexPreviousSessionAuthKey
	keys.PreviousEncryption.Value = hexPreviousSessionEncKey
}

func TestParseKeys(t *testing.T) {
	current := KeyPair{AuthenticationKey: decodedSessionAuthKey(), EncryptionKey: decodedSessionEncKey()}
	previous := &KeyPair{AuthenticationKey: decodedPreviousSessionAuthKey(), EncryptionKey: decodedPreviousSessionEncKey()}

	const (
		invalidByteZ = "encoding/hex: invalid byte: U+007A 'z'"
		oddLength    = "encoding/hex: odd length hex string"
		pairTail     = ": both halves of the previous pair are needed to open a session sealed under it"
	)

	cases := []struct {
		name         string
		keys         ConfiguredKeys
		wantCurrent  KeyPair
		wantPrevious *KeyPair
		wantErr      string
	}{
		{
			// The case the nil-versus-zero distinction exists for. A deployment that is not
			// rotating gets nil, never a KeyPair holding two empty keys: the second would
			// satisfy "no error" and "not rotating" while handing the store a permanently
			// valid opening key derived from nothing but the two info constants in codec.go.
			name:         "the current pair alone gives no previous pair at all",
			keys:         configuredKeys(nil),
			wantCurrent:  current,
			wantPrevious: nil,
		},
		{
			name:         "both pairs decode, each to its own bytes",
			keys:         configuredKeys(withPrevious),
			wantCurrent:  current,
			wantPrevious: previous,
		},
		{
			name: "whitespace around all four values is trimmed",
			keys: configuredKeys(func(k *ConfiguredKeys) {
				k.Authentication.Value = " " + hexSessionAuthKey + "\n"
				k.Encryption.Value = "\t" + hexSessionEncKey + " "
				k.PreviousAuthentication.Value = "  " + hexPreviousSessionAuthKey
				k.PreviousEncryption.Value = hexPreviousSessionEncKey + "\r\n"
			}),
			wantCurrent:  current,
			wantPrevious: previous,
		},
		{
			// A value holding blanks is a value nobody set.
			name: "both previous values holding only whitespace give no previous pair",
			keys: configuredKeys(func(k *ConfiguredKeys) {
				k.PreviousAuthentication.Value = "   "
				k.PreviousEncryption.Value = "\t"
			}),
			wantCurrent:  current,
			wantPrevious: nil,
		},
		{
			name:    "a missing authentication key is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Authentication.Value = "" }),
			wantErr: "TEST_AUTH is required",
		},
		{
			name:    "an authentication key holding only whitespace is refused as missing",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Authentication.Value = " \t " }),
			wantErr: "TEST_AUTH is required",
		},
		{
			name:    "a missing encryption key is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Encryption.Value = "" }),
			wantErr: "TEST_ENC is required",
		},
		{
			name: "both current keys missing names the authentication key first",
			keys: configuredKeys(func(k *ConfiguredKeys) {
				k.Authentication.Value = ""
				k.Encryption.Value = ""
			}),
			wantErr: "TEST_AUTH is required",
		},
		{
			name:    "an authentication key with a non-hex byte is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Authentication.Value = strings.Repeat("zz", 64) }),
			wantErr: "TEST_AUTH must be hex-encoded (error: " + invalidByteZ + "). Generate with: openssl rand -hex 64",
		},
		{
			name:    "an authentication key with an odd count of hex characters is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Authentication.Value = hexSessionAuthKey[:127] }),
			wantErr: "TEST_AUTH must be hex-encoded (error: " + oddLength + "). Generate with: openssl rand -hex 64",
		},
		{
			name:    "a 32 byte authentication key is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Authentication.Value = strings.Repeat("ab", 32) }),
			wantErr: "TEST_AUTH must be 64 bytes (128 hex chars), got 32 bytes. Generate with: openssl rand -hex 64",
		},
		{
			name:    "a 65 byte authentication key is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Authentication.Value = strings.Repeat("ab", 65) }),
			wantErr: "TEST_AUTH must be 64 bytes (128 hex chars), got 65 bytes. Generate with: openssl rand -hex 64",
		},
		{
			name:    "an encryption key with a non-hex byte is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Encryption.Value = strings.Repeat("zz", 32) }),
			wantErr: "TEST_ENC must be hex-encoded (error: " + invalidByteZ + "). Generate with: openssl rand -hex 32",
		},
		{
			name:    "a 16 byte encryption key is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Encryption.Value = strings.Repeat("cd", 16) }),
			wantErr: "TEST_ENC must be 32 bytes (64 hex chars), got 16 bytes. Generate with: openssl rand -hex 32",
		},
		{
			name:    "a 33 byte encryption key is refused",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.Encryption.Value = strings.Repeat("cd", 33) }),
			wantErr: "TEST_ENC must be 32 bytes (64 hex chars), got 33 bytes. Generate with: openssl rand -hex 32",
		},
		{
			name:    "the previous encryption key alone is refused, naming the previous authentication key",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.PreviousEncryption.Value = hexPreviousSessionEncKey }),
			wantErr: "TEST_PREV_AUTH is required when TEST_PREV_ENC is set" + pairTail,
		},
		{
			name:    "the previous authentication key alone is refused, naming the previous encryption key",
			keys:    configuredKeys(func(k *ConfiguredKeys) { k.PreviousAuthentication.Value = hexPreviousSessionAuthKey }),
			wantErr: "TEST_PREV_ENC is required when TEST_PREV_AUTH is set" + pairTail,
		},
		{
			// No `Generate with` hint on any of the four previous-key refusals: the previous
			// pair is copied from the old current one, never generated.
			name: "a previous authentication key with a non-hex byte is refused",
			keys: configuredKeys(func(k *ConfiguredKeys) {
				withPrevious(k)
				k.PreviousAuthentication.Value = strings.Repeat("zz", 64)
			}),
			wantErr: "TEST_PREV_AUTH must be hex-encoded (error: " + invalidByteZ + ")",
		},
		{
			name: "a 32 byte previous authentication key is refused",
			keys: configuredKeys(func(k *ConfiguredKeys) {
				withPrevious(k)
				k.PreviousAuthentication.Value = strings.Repeat("12", 32)
			}),
			wantErr: "TEST_PREV_AUTH must be 64 bytes (128 hex chars), got 32 bytes",
		},
		{
			name: "a previous encryption key with a non-hex byte is refused",
			keys: configuredKeys(func(k *ConfiguredKeys) {
				withPrevious(k)
				k.PreviousEncryption.Value = strings.Repeat("zz", 32)
			}),
			wantErr: "TEST_PREV_ENC must be hex-encoded (error: " + invalidByteZ + ")",
		},
		{
			name: "a 33 byte previous encryption key is refused",
			keys: configuredKeys(func(k *ConfiguredKeys) {
				withPrevious(k)
				k.PreviousEncryption.Value = strings.Repeat("34", 33)
			}),
			wantErr: "TEST_PREV_ENC must be 32 bytes (64 hex chars), got 33 bytes",
		},
		{
			name: "a valid previous pair beside a malformed current key refuses on the current key",
			keys: configuredKeys(func(k *ConfiguredKeys) {
				withPrevious(k)
				k.Encryption.Value = strings.Repeat("cd", 16)
			}),
			wantErr: "TEST_ENC must be 32 bytes (64 hex chars), got 16 bytes. Generate with: openssl rand -hex 32",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotCurrent, gotPrevious, err := ParseKeys(c.keys)

			if c.wantErr != "" {
				require.Error(t, err)
				assert.Equal(t, c.wantErr, err.Error())
				// Every refusal of the previous pair, and only those, is a *PreviousKeysError, which
				// is what tells each application's startup record a rotation mistake from a
				// credential the deployment lacks. The rows refusing a TEST_PREV_ variable are those.
				var previousErr *PreviousKeysError
				assert.Equal(t, strings.HasPrefix(c.wantErr, "TEST_PREV_"), errors.As(err, &previousErr),
					"whether the refusal is a *PreviousKeysError")
				assert.Equal(t, KeyPair{}, gotCurrent, "a refusal hands back no current pair")
				assert.Nil(t, gotPrevious, "a refusal hands back no previous pair")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, c.wantCurrent, gotCurrent)
			if c.wantPrevious == nil {
				assert.Nil(t, gotPrevious, "an absent previous pair is nil, not a zero-value KeyPair")
				return
			}
			require.NotNil(t, gotPrevious)
			assert.Equal(t, *c.wantPrevious, *gotPrevious)
		})
	}
}

// TestNewServerSideStore_RefusesAKeyPairWithAnEmptyKey is the store-side half of what
// ParseKeys' comment describes. HKDF derives a valid key from an empty secret and an empty
// salt, the AEAD accepts it, and values seal and open under it, so a pair with no bytes in it
// is refused at construction rather than left to work.
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
			store, err := NewServerSideStore(newFakeBackend(), "SessionIdentifier", false, BrowserSessionCookie,
				c.current, c.previous)

			require.Error(t, err)
			assert.Nil(t, store, "a store that could not build its keys is not returned")
			assert.Contains(t, err.Error(), "non-empty")
		})
	}
}
