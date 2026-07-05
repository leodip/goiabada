package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

const testClientSecret = "a-representative-60-char-client-secret-0123456789abcdefgh"

// encryptJWE builds a compact JWE the way a client would, so the decrypt path
// can be exercised end-to-end.
func encryptJWE(t *testing.T, plaintext string, keyAlg jose.KeyAlgorithm, contentEnc jose.ContentEncryption, key interface{}) string {
	t.Helper()
	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{Algorithm: keyAlg, Key: key},
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewEncrypter(%s/%s): %v", keyAlg, contentEnc, err)
	}
	obj, err := encrypter.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return compact
}

func TestDeriveIDTokenHintKey(t *testing.T) {
	k1 := DeriveIDTokenHintKey(testClientSecret)
	if len(k1) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(k1))
	}
	// Deterministic for a given secret, different for a different secret.
	k2 := DeriveIDTokenHintKey(testClientSecret)
	if string(k1) != string(k2) {
		t.Error("derivation is not deterministic")
	}
	if string(DeriveIDTokenHintKey("other-secret")) == string(k1) {
		t.Error("different secrets produced the same key")
	}
}

func TestDecryptIDTokenHintJWE_RoundTrip(t *testing.T) {
	// The plaintext is the inner signed ID Token (a compact JWS). Its content is
	// opaque to the encryption layer; we only assert it round-trips exactly.
	inner := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature-bytes"
	key := DeriveIDTokenHintKey(testClientSecret)

	jwe := encryptJWE(t, inner, jose.DIRECT, jose.A256GCM, key)

	got, err := DecryptIDTokenHintJWE(jwe, testClientSecret)
	if err != nil {
		t.Fatalf("DecryptIDTokenHintJWE: %v", err)
	}
	if got != inner {
		t.Errorf("round-trip mismatch:\n got  %q\n want %q", got, inner)
	}
}

func TestDecryptIDTokenHintJWE_WrongSecret(t *testing.T) {
	jwe := encryptJWE(t, "inner-token", jose.DIRECT, jose.A256GCM, DeriveIDTokenHintKey(testClientSecret))

	if _, err := DecryptIDTokenHintJWE(jwe, "a-completely-different-client-secret-value"); err == nil {
		t.Error("expected decryption with the wrong secret to fail, got nil error")
	}
}

func TestDecryptIDTokenHintJWE_Tampered(t *testing.T) {
	jwe := encryptJWE(t, "inner-token", jose.DIRECT, jose.A256GCM, DeriveIDTokenHintKey(testClientSecret))

	// Flip a character in the ciphertext segment (4th of 5 compact segments).
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 JWE segments, got %d", len(parts))
	}
	ct := []byte(parts[3])
	if ct[0] == 'A' {
		ct[0] = 'B'
	} else {
		ct[0] = 'A'
	}
	parts[3] = string(ct)
	tampered := strings.Join(parts, ".")

	if _, err := DecryptIDTokenHintJWE(tampered, testClientSecret); err == nil {
		t.Error("expected tampered ciphertext to fail authentication, got nil error")
	}
}

// TestDecryptIDTokenHintJWE_AlgorithmAllowlist proves that only dir + A256GCM is
// accepted, blocking algorithm-substitution / downgrade attempts.
func TestDecryptIDTokenHintJWE_AlgorithmAllowlist(t *testing.T) {
	key := DeriveIDTokenHintKey(testClientSecret)

	t.Run("different key alg (A256KW) rejected", func(t *testing.T) {
		jwe := encryptJWE(t, "inner", jose.A256KW, jose.A256GCM, key)
		if _, err := DecryptIDTokenHintJWE(jwe, testClientSecret); err == nil {
			t.Error("expected A256KW to be rejected, got nil error")
		}
	})

	t.Run("different content enc (A128GCM) rejected", func(t *testing.T) {
		// A128GCM needs a 16-byte key.
		jwe := encryptJWE(t, "inner", jose.DIRECT, jose.A128GCM, key[:16])
		if _, err := DecryptIDTokenHintJWE(jwe, testClientSecret); err == nil {
			t.Error("expected A128GCM to be rejected, got nil error")
		}
	})

	t.Run("asymmetric key alg (RSA-OAEP) rejected", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		jwe := encryptJWE(t, "inner", jose.RSA_OAEP, jose.A256GCM, &rsaKey.PublicKey)
		if _, err := DecryptIDTokenHintJWE(jwe, testClientSecret); err == nil {
			t.Error("expected RSA-OAEP to be rejected, got nil error")
		}
	})
}

func TestDecryptIDTokenHintJWE_InvalidInput(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		secret string
	}{
		{"empty jwe", "", testClientSecret},
		{"empty secret", "a.b.c.d.e", ""},
		{"not a jwe (plain string)", "not-a-jwe", testClientSecret},
		{"jws not jwe (3 segments)", "header.payload.signature", testClientSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecryptIDTokenHintJWE(tc.input, tc.secret); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}
