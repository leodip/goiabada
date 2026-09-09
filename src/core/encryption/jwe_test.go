package encryption

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

const testClientSecret = "a-representative-60-char-client-secret-0123456789abcdefgh"

// testInner is the plaintext of a real hint: the inner signed ID Token, a compact
// JWS. Its content is opaque to the encryption layer.
const testInner = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature-bytes"

// jweOpts is the low-level fixture builder's dial box. Every field defaults to the
// documented scheme, so a refused case differs from the accepted baseline in
// exactly one thing and cannot pass for some other reason (#277).
type jweOpts struct {
	header       string // raw protected header JSON, used byte for byte
	encryptedKey []byte // empty by default, as "dir" requires
	iv           []byte // 12 random bytes by default
	tagLen       int    // 16 by default
	compress     bool   // DEFLATE the plaintext, for the zip cases
	pad          bool   // standard base64url with '=' padding on every segment
}

// buildJWE assembles a compact JWE segment by segment, so a case can write any
// header and any segment length. It deliberately does not call
// EncryptIDTokenHintJWE: the encryptor can only produce well-formed input, and
// almost every case here is malformed on purpose.
func buildJWE(t *testing.T, plaintext string, key []byte, o jweOpts) string {
	t.Helper()
	if o.header == "" {
		o.header = idTokenHintJWEHeader
	}
	if o.iv == nil {
		o.iv = make([]byte, 12)
		if _, err := rand.Read(o.iv); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
	}
	if o.tagLen == 0 {
		o.tagLen = 16
	}

	pt := []byte(plaintext)
	if o.compress {
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			t.Fatalf("flate.NewWriter: %v", err)
		}
		if _, err := w.Write(pt); err != nil {
			t.Fatalf("flate write: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("flate close: %v", err)
		}
		pt = buf.Bytes()
	}

	enc := func(b []byte) string {
		if o.pad {
			return base64.URLEncoding.EncodeToString(b)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}

	protected := enc([]byte(o.header))
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(o.iv))
	if err != nil {
		t.Fatalf("cipher.NewGCMWithNonceSize(%d): %v", len(o.iv), err)
	}
	sealed := gcm.Seal(nil, o.iv, pt, []byte(protected))
	ciphertext, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	tag = tag[:o.tagLen]

	return strings.Join([]string{
		protected,
		enc(o.encryptedKey),
		enc(o.iv),
		enc(ciphertext),
		enc(tag),
	}, ".")
}

// replaceSegment returns compactJWE with segment i replaced.
func replaceSegment(t *testing.T, compactJWE string, i int, segment string) string {
	t.Helper()
	parts := strings.Split(compactJWE, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 JWE segments, got %d", len(parts))
	}
	parts[i] = segment
	return strings.Join(parts, ".")
}

// flipFirstByte returns compactJWE with the first character of segment i changed,
// which alters that segment's decoded bytes without changing its length or making
// it non-canonical, so the case reaches the AEAD rather than an earlier gate.
func flipFirstByte(t *testing.T, compactJWE string, i int) string {
	t.Helper()
	parts := strings.Split(compactJWE, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 JWE segments, got %d", len(parts))
	}
	seg := []byte(parts[i])
	if len(seg) == 0 {
		t.Fatalf("segment %d is empty, nothing to flip", i)
	}
	if seg[0] == 'A' {
		seg[0] = 'B'
	} else {
		seg[0] = 'A'
	}
	return replaceSegment(t, compactJWE, i, string(seg))
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

// TestEncryptIDTokenHintJWE_Shape pins the wire format the docs at
// integration/endpoints.mdx promise an RP, byte for byte: change any of it and
// every client following that page breaks.
func TestEncryptIDTokenHintJWE_Shape(t *testing.T) {
	jwe, err := EncryptIDTokenHintJWE(testInner, testClientSecret)
	if err != nil {
		t.Fatalf("EncryptIDTokenHintJWE: %v", err)
	}
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("segments = %d, want 5", len(parts))
	}

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("segment 0 is not raw base64url: %v", err)
	}
	if string(header) != `{"alg":"dir","enc":"A256GCM","cty":"JWT"}` {
		t.Errorf("protected header = %s, want the documented header", header)
	}
	if parts[1] != "" {
		t.Errorf("encrypted key segment = %q, want empty (RFC 7518 section 4.5)", parts[1])
	}

	for i, want := range map[int]int{2: 12, 4: 16} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatalf("segment %d is not raw base64url: %v", i, err)
		}
		if len(raw) != want {
			t.Errorf("segment %d is %d bytes, want %d", i, len(raw), want)
		}
	}

	// A second call must not repeat the IV.
	other, err := EncryptIDTokenHintJWE(testInner, testClientSecret)
	if err != nil {
		t.Fatalf("EncryptIDTokenHintJWE (second): %v", err)
	}
	if strings.Split(other, ".")[2] == parts[2] {
		t.Error("two encryptions reused the same iv")
	}
}

func TestEncryptIDTokenHintJWE_InvalidInput(t *testing.T) {
	if _, err := EncryptIDTokenHintJWE("", testClientSecret); err == nil {
		t.Error("expected an empty plaintext to be refused, got nil error")
	} else if !strings.Contains(err.Error(), "plaintext is empty") {
		t.Errorf("empty plaintext: err = %v, want it to name the empty plaintext", err)
	}
	if _, err := EncryptIDTokenHintJWE(testInner, ""); err == nil {
		t.Error("expected an empty client secret to be refused, got nil error")
	} else if !strings.Contains(err.Error(), "client secret is empty") {
		t.Errorf("empty secret: err = %v, want it to name the empty secret", err)
	}
}

func TestDecryptIDTokenHintJWE_RoundTrip(t *testing.T) {
	jwe, err := EncryptIDTokenHintJWE(testInner, testClientSecret)
	if err != nil {
		t.Fatalf("EncryptIDTokenHintJWE: %v", err)
	}

	got, err := DecryptIDTokenHintJWE(jwe, testClientSecret)
	if err != nil {
		t.Fatalf("DecryptIDTokenHintJWE: %v", err)
	}
	if got != testInner {
		t.Errorf("round-trip mismatch:\n got  %q\n want %q", got, testInner)
	}
}

// TestDecryptIDTokenHintJWE_Accepted is the other half of the refusal table: the
// inputs the parser must keep taking. Unknown header parameters are ignored per
// RFC 7515 section 4, and "cty" is never required (decision 4), so a hint that
// works today goes on working.
func TestDecryptIDTokenHintJWE_Accepted(t *testing.T) {
	key := DeriveIDTokenHintKey(testClientSecret)

	cases := []struct {
		name      string
		plaintext string // defaults to testInner
		opts      jweOpts
	}{
		// The baseline is also the interop proof: a stdlib encryptor's output, built
		// segment by segment, is what the parser reads.
		{name: "baseline: dir/A256GCM/cty"},
		// keep this: pins decision 4's "cty is never required" half. The docs table
		// lists cty, but requiring it would refuse a hint that works today.
		{name: "header without cty", opts: jweOpts{header: `{"alg":"dir","enc":"A256GCM"}`}},
		{name: "header with typ JWT", opts: jweOpts{header: `{"alg":"dir","enc":"A256GCM","typ":"JWT"}`}},
		{name: "header with an unknown non-critical param", opts: jweOpts{header: `{"alg":"dir","enc":"A256GCM","foo":"bar"}`}},
		{name: "header with an unknown number param", opts: jweOpts{header: `{"alg":"dir","enc":"A256GCM","foo":1}`}},
		{name: "header enc before alg", opts: jweOpts{header: `{"enc":"A256GCM","alg":"dir"}`}},
		{name: "header alg JSON-escaped as d\\u0069r", opts: jweOpts{header: `{"alg":"d\u0069r","enc":"A256GCM"}`}},
		{name: "header with trailing whitespace inside the object", opts: jweOpts{header: `{"alg":"dir","enc":"A256GCM"} `}},
		// Member names compare code point for code point (RFC 7515 section 5.3), so
		// these two are unknown parameters and are ignored rather than acted on. Parity
		// with go-jose.
		{name: "header name uppercase ZIP with DEF", opts: jweOpts{header: `{"alg":"dir","enc":"A256GCM","ZIP":"DEF"}`}},
		{name: "header name uppercase CRIT with a list", opts: jweOpts{header: `{"alg":"dir","enc":"A256GCM","CRIT":["exp"]}`}},
		// Names nested inside an unknown parameter are not header parameter names, so
		// the duplicate-name walk must not count them; without the depth skip this row
		// is refused as a repeated "alg".
		{name: "header with alg and enc nested inside unknown params", opts: jweOpts{header: `{"alg":"dir","enc":"A256GCM","x":{"alg":"A256KW"},"y":["alg","enc"]}`}},
		// The plaintext is opaque to the JWE layer; the caller validates the inner token.
		{name: "plaintext that is not a JWS", plaintext: "hello world"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.plaintext
			if want == "" {
				want = testInner
			}
			got, err := DecryptIDTokenHintJWE(buildJWE(t, want, key, tc.opts), testClientSecret)
			if err != nil {
				t.Fatalf("expected acceptance, got error: %v", err)
			}
			if got != want {
				t.Errorf("plaintext = %q, want %q", got, want)
			}
		})
	}
}

func TestDecryptIDTokenHintJWE_WrongSecret(t *testing.T) {
	jwe := buildJWE(t, testInner, DeriveIDTokenHintKey(testClientSecret), jweOpts{})

	_, err := DecryptIDTokenHintJWE(jwe, "a-completely-different-client-secret-value")
	if err == nil {
		t.Fatal("expected decryption with the wrong secret to fail, got nil error")
	}
	if !strings.Contains(err.Error(), "decryption failed") {
		t.Errorf("err = %v, want the shared decryption-failed message", err)
	}
}

// TestDecryptIDTokenHintJWE_Tampered proves every segment is authenticated,
// including the protected header: the AAD is the header segment exactly as
// received, so changing a header a reader would otherwise accept still fails.
func TestDecryptIDTokenHintJWE_Tampered(t *testing.T) {
	key := DeriveIDTokenHintKey(testClientSecret)
	jwe := buildJWE(t, testInner, key, jweOpts{})

	// The substituted header passes every gate above the cipher (alg dir, enc
	// A256GCM, no zip, no crit, cty ignored), so only the AAD binding can refuse it.
	swappedHeader := replaceSegment(t, jwe, 0,
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"dir","enc":"A256GCM","cty":"JWS"}`)))

	cases := []struct {
		name  string
		input string
	}{
		{"protected header substituted", swappedHeader},
		{"initialization vector", flipFirstByte(t, jwe, 2)},
		{"ciphertext", flipFirstByte(t, jwe, 3)},
		{"authentication tag", flipFirstByte(t, jwe, 4)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecryptIDTokenHintJWE(tc.input, testClientSecret)
			if err == nil {
				t.Fatal("expected tampering to fail authentication, got nil error")
			}
			if !strings.Contains(err.Error(), "decryption failed") {
				t.Errorf("err = %v, want the shared decryption-failed message", err)
			}
		})
	}
}

// TestDecryptIDTokenHintJWE_AlgorithmAllowlist proves that only dir + A256GCM is
// accepted, blocking algorithm-substitution / downgrade attempts. The header
// names the foreign algorithm; nothing in the parser dispatches on it.
func TestDecryptIDTokenHintJWE_AlgorithmAllowlist(t *testing.T) {
	key := DeriveIDTokenHintKey(testClientSecret)

	t.Run("different key alg (A256KW) rejected", func(t *testing.T) {
		jwe := buildJWE(t, testInner, key, jweOpts{header: `{"alg":"A256KW","enc":"A256GCM"}`})
		assertRefused(t, jwe, testClientSecret, `alg is "A256KW", want "dir"`)
	})

	t.Run("different content enc (A128GCM) rejected", func(t *testing.T) {
		jwe := buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A128GCM"}`})
		assertRefused(t, jwe, testClientSecret, `enc is "A128GCM", want "A256GCM"`)
	})

	t.Run("asymmetric key alg (RSA-OAEP) rejected", func(t *testing.T) {
		jwe := buildJWE(t, testInner, key, jweOpts{header: `{"alg":"RSA-OAEP","enc":"A256GCM"}`})
		assertRefused(t, jwe, testClientSecret, `alg is "RSA-OAEP", want "dir"`)
	})
}

func assertRefused(t *testing.T, compactJWE, secret, wantErr string) {
	t.Helper()
	got, err := DecryptIDTokenHintJWE(compactJWE, secret)
	if err == nil {
		t.Fatalf("expected refusal, got plaintext %q", got)
	}
	// Naming the gate is what stops a case passing on some other failure, most often
	// the shared decryption-failed message.
	if !strings.Contains(err.Error(), wantErr) {
		t.Errorf("err = %v\n want it to contain %q", err, wantErr)
	}
}

// TestDecryptIDTokenHintJWE_InvalidInput is the refusal table: one row per input
// the parser must reject, each asserting the message of the gate that is meant to
// reject it.
func TestDecryptIDTokenHintJWE_InvalidInput(t *testing.T) {
	key := DeriveIDTokenHintKey(testClientSecret)
	baseline := buildJWE(t, testInner, key, jweOpts{})

	cases := []struct {
		name    string
		input   string
		secret  string
		wantErr string
	}{
		// --- the two guards at the top ---
		{"empty jwe", "", testClientSecret, "id_token_hint is empty"},
		{"empty secret", "a.b.c.d.e", "", "client secret is empty"},

		// --- segment count (RFC 7516 section 5.2 step 1) ---
		{"not a jwe (plain string)", "not-a-jwe", testClientSecret, "expected 5 segments, got 1"},
		{"jws not jwe (3 segments)", "header.payload.signature", testClientSecret, "expected 5 segments, got 3"},
		{"four segments", strings.Join(strings.Split(baseline, ".")[:4], "."), testClientSecret, "expected 5 segments, got 4"},
		{"six segments", baseline + ".x", testClientSecret, "expected 5 segments, got 6"},

		// --- canonical base64url (RFC 7515 section 2, decision 5) ---
		{"= padding on every segment", buildJWE(t, testInner, key, jweOpts{pad: true}), testClientSecret,
			"segment 0 (protected header) is not valid base64url"},
		{"leading space before the compact form", " " + baseline, testClientSecret,
			"segment 0 (protected header) is not valid base64url"},
		// keep this: reverses the library. Go's decoder skips \r and \n anywhere, so
		// go-jose accepts all three of these today (decision 5).
		{"newline inside the ciphertext segment",
			replaceSegment(t, baseline, 3, strings.Split(baseline, ".")[3][:4]+"\n"+strings.Split(baseline, ".")[3][4:]),
			testClientSecret, "segment 3 (ciphertext) is not canonical base64url"},
		{"trailing newline after the compact form", baseline + "\n", testClientSecret,
			"segment 4 (authentication tag) is not canonical base64url"},
		{"trailing CRLF after the compact form", baseline + "\r\n", testClientSecret,
			"segment 4 (authentication tag) is not canonical base64url"},

		// --- the protected header is UTF-8 and a JSON object (RFC 7516 5.2 step 3) ---
		{"header is a JSON array", buildJWE(t, testInner, key, jweOpts{header: `["alg","dir"]`}), testClientSecret,
			"header is not a JSON object"},
		{"header is a JSON string", buildJWE(t, testInner, key, jweOpts{header: `"alg"`}), testClientSecret,
			"header is not a JSON object"},
		{"header with trailing garbage after the object",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A256GCM"}{}`}), testClientSecret,
			"header has trailing data after the JSON object"},
		{"header with an unknown out-of-range number 1e400",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A256GCM","foo":1e400}`}), testClientSecret,
			"header is not a JSON object"},
		// keep this: reverses the library. encoding/json substitutes U+FFFD rather than
		// failing, so go-jose accepts both of these today.
		{"header with invalid UTF-8 in an unknown value",
			buildJWE(t, testInner, key, jweOpts{header: "{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"foo\":\"\xff\"}"}), testClientSecret,
			"header is not valid UTF-8"},
		{"header with invalid UTF-8 in an unknown name",
			buildJWE(t, testInner, key, jweOpts{header: "{\"alg\":\"dir\",\"enc\":\"A256GCM\",\"\xff\":1}"}), testClientSecret,
			"header is not valid UTF-8"},

		// --- duplicate header parameter names (RFC 7515 section 4, decision 6) ---
		{"header duplicate alg, dir first",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","alg":"A256KW","enc":"A256GCM"}`}), testClientSecret,
			`header repeats the member name "alg"`},
		// keep this: reverses encoding/json's silent last-wins, which would accept this
		// row (decision 6). Parity with go-jose, which refuses both orders.
		{"header duplicate alg, dir last",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"A256KW","alg":"dir","enc":"A256GCM"}`}), testClientSecret,
			`header repeats the member name "alg"`},
		{"header duplicate alg, dir in both copies",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","alg":"dir","enc":"A256GCM"}`}), testClientSecret,
			`header repeats the member name "alg"`},
		{"header duplicate name other than alg or enc",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A256GCM","cty":"JWT","cty":"JWT"}`}), testClientSecret,
			`header repeats the member name "cty"`},

		// --- alg and enc, compared exactly (RFC 7515 section 5.3) ---
		{"header missing alg", buildJWE(t, testInner, key, jweOpts{header: `{"enc":"A256GCM"}`}), testClientSecret,
			`alg is "", want "dir"`},
		{"header missing enc", buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir"}`}), testClientSecret,
			`enc is "", want "A256GCM"`},
		{"header alg uppercase DIR", buildJWE(t, testInner, key, jweOpts{header: `{"alg":"DIR","enc":"A256GCM"}`}), testClientSecret,
			`alg is "DIR", want "dir"`},
		{"header name uppercase ALG reads as a missing alg",
			buildJWE(t, testInner, key, jweOpts{header: `{"ALG":"dir","enc":"A256GCM"}`}), testClientSecret,
			`alg is "", want "dir"`},
		{"header name uppercase ENC reads as a missing enc",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","ENC":"A256GCM"}`}), testClientSecret,
			`enc is "", want "A256GCM"`},
		{"header alg is not a string", buildJWE(t, testInner, key, jweOpts{header: `{"alg":1,"enc":"A256GCM"}`}), testClientSecret,
			`alg is "", want "dir"`},

		// --- zip (RFC 7516 section 4.1.3, decision 3) ---
		// keep this: reverses the library. go-jose inflates this row and returns the
		// plaintext; this parser never inflates, so there is no decompression surface.
		{"header zip DEF with deflated content",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A256GCM","zip":"DEF"}`, compress: true}), testClientSecret,
			"header has a zip parameter"},
		{"header zip DEF with plain content",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A256GCM","zip":"DEF"}`}), testClientSecret,
			"header has a zip parameter"},

		// --- crit (RFC 7515 section 4.1.11, decision 4) ---
		{"header crit naming an extension",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A256GCM","crit":["exp"]}`}), testClientSecret,
			"header has a crit parameter"},
		// The empty list a producer MUST NOT use; RFC 7515 leaves refusing it optional,
		// and decision 4 takes the option. Parity with go-jose.
		{"header crit empty list",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A256GCM","crit":[]}`}), testClientSecret,
			"header has a crit parameter"},
		{"header crit not a list",
			buildJWE(t, testInner, key, jweOpts{header: `{"alg":"dir","enc":"A256GCM","crit":"x"}`}), testClientSecret,
			"header has a crit parameter"},

		// --- segment sizes (RFC 7516 5.2 step 10, RFC 7518 5.3, decision 2) ---
		// keep this: reverses the library. go-jose ignores a non-empty encrypted key
		// under dir and decrypts anyway.
		{"non-empty encrypted key with dir",
			buildJWE(t, testInner, key, jweOpts{encryptedKey: make([]byte, 32)}), testClientSecret,
			"encrypted key is 32 bytes, want empty"},
		{"iv of 8 bytes", buildJWE(t, testInner, key, jweOpts{iv: make([]byte, 8)}), testClientSecret,
			"iv is 8 bytes, want 12"},
		{"iv of 16 bytes", buildJWE(t, testInner, key, jweOpts{iv: make([]byte, 16)}), testClientSecret,
			"iv is 16 bytes, want 12"},
		{"empty iv segment", replaceSegment(t, baseline, 2, ""), testClientSecret,
			"iv is 0 bytes, want 12"},
		{"tag truncated to 8 bytes", buildJWE(t, testInner, key, jweOpts{tagLen: 8}), testClientSecret,
			"authentication tag is 8 bytes, want 16"},
		{"tag truncated to 15 bytes", buildJWE(t, testInner, key, jweOpts{tagLen: 15}), testClientSecret,
			"authentication tag is 15 bytes, want 16"},
		{"empty tag segment", replaceSegment(t, baseline, 4, ""), testClientSecret,
			"authentication tag is 0 bytes, want 16"},
		// An empty ciphertext with a valid tag authenticates, so without this gate the
		// hint would decrypt to the empty string (decision 2).
		{"empty ciphertext segment", replaceSegment(t, buildJWE(t, "", key, jweOpts{}), 3, ""), testClientSecret,
			"ciphertext is empty"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertRefused(t, tc.input, tc.secret, tc.wantErr)
		})
	}
}
