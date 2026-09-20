package emaildelivery

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSMTPEncryption_String owns the total String decision 16 of #385 settled for this type. The
// in-range rows are stored values: settings.smtp_encryption is a plain string column, so these are
// what a deployment's configuration actually holds and what SMTPEncryptionFromString has to read
// back.
func TestSMTPEncryption_String(t *testing.T) {
	testCases := []struct {
		name       string
		encryption SMTPEncryption
		want       string
	}{
		{"none is the zero value", SMTPEncryptionNone, "none"},
		{"ssltls", SMTPEncryptionSSLTLS, "ssltls"},
		{"starttls, the top of the range", SMTPEncryptionSTARTTLS, "starttls"},
		{"one past the range", SMTPEncryption(3), ""},
		{"far past the range", SMTPEncryption(99), ""},
		{"negative", SMTPEncryption(-1), ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.encryption.String())
		})
	}
}

// TestSMTPEncryptionFromString covers the parse in both directions, including the empty string,
// which this one parse treats as "none" for deployments configured before the column existed. The
// guard on String does not touch that: "" is never what an in-range value renders as, so the two
// cannot be confused for each other.
func TestSMTPEncryptionFromString(t *testing.T) {
	all := []SMTPEncryption{SMTPEncryptionNone, SMTPEncryptionSSLTLS, SMTPEncryptionSTARTTLS}
	for _, encryption := range all {
		t.Run(encryption.String(), func(t *testing.T) {
			parsed, err := SMTPEncryptionFromString(encryption.String())
			assert.NoError(t, err)
			assert.Equal(t, encryption, parsed)
		})
	}

	t.Run("the empty string is none, for backward compatibility", func(t *testing.T) {
		parsed, err := SMTPEncryptionFromString("")
		assert.NoError(t, err)
		assert.Equal(t, SMTPEncryptionNone, parsed)
	})

	t.Run("an unrecognized encryption is refused", func(t *testing.T) {
		for _, raw := range []string{"tls", "SSLTLS", "0", " none"} {
			parsed, err := SMTPEncryptionFromString(raw)
			assert.Error(t, err, "%q must not parse", raw)
			assert.Equal(t, SMTPEncryptionNone, parsed, "the refused value returns the zero encryption")
		}
	})
}
