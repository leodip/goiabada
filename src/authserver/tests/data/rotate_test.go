package datatests

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil/fake"
)

// TestRotateEncryptionKeyIfNeeded exercises env-to-env key rotation (issue #83):
// idempotent, canary-based detection, and fail-closed on a mismatch. Uses an
// isolated file-based sqlite DB and explicit keys.
//
// It also owns the exhaustive table over commondb.aesProtectedColumns. That table used to be
// reencrypt_test.go's, over the 1.5.x startup conversion; #359 deleted the conversion (#262) and
// rotation is now the only caller of the re-keying machinery, so the coverage moved here rather
// than leaving four of the eight columns unreached. The list is "an enumeration nothing derives"
// by its own comment, so this test is what derives it: every column is seeded under keyA, and
// after the rotation every one must decrypt under keyB and NO LONGER under keyA. A column dropped
// from the enumeration survives as ciphertext readable only under the retired key, which is
// exactly what the second half of each pair catches.
func TestRotateEncryptionKeyIfNeeded(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rotate.db")
	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{DSN: dbPath}, false)
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	keyA := []byte("0123456789abcdef0123456789abcdef")
	keyB := []byte("fedcba9876543210fedcba9876543210")
	keyC := []byte("aaaabbbbccccddddaaaabbbbccccdddd")

	encA := func(s string) []byte {
		b, err := encryption.EncryptText(s, keyA)
		if err != nil {
			t.Fatalf("EncryptText: %v", err)
		}
		return b
	}

	// No data yet: no canary, so nothing to rotate.
	if rotated, err := db.RotateEncryptionKeyIfNeeded(keyB, keyA); err != nil || rotated {
		t.Errorf("rotate on empty db = (%v, %v), want (false, nil)", rotated, err)
	}

	// One seeded value per entry of aesProtectedColumns, plus the RSA private key PEM that
	// reencryptPrivateKeys handles separately and that doubles as the rotation canary.
	const (
		pem        = "-----BEGIN RSA PRIVATE KEY-----\nfakepem\n-----END RSA PRIVATE KEY-----\n"
		smtpPass   = "smtp-password"
		clientSec  = "client-secret"
		emailCode  = "email-verif-code"
		phoneCode  = "phone-verif-code"
		otpSeed    = "JBSWY3DPEHPK3PXP"
		forgotCode = "forgot-password-code"
		preRegCode = "prereg-verif-code"
		// The pending TOTP enrolment (#247).
		otpEnrolment = "otpauth://totp/Goiabada:u@example.com?secret=JBSWY3DPEHPK3PXP"
	)

	// A recognizable legacy data key, seeded so the assertion below has something to fail on.
	// It is neither keyA nor keyB: rotation must not read it and must not write it.
	legacyKey := []byte("legacy-key-legacy-key-legacy-key")

	if err := db.CreateKeyPair(nil, &models.KeyPair{
		State: "current", KeyIdentifier: fake.UUID(), Type: "RSA", Algorithm: "RS256",
		PrivateKeyPEM: encA(pem), // canary, encrypted under keyA
	}); err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	settings := &models.Settings{
		AESEncryptionKeyLegacy: legacyKey,
		SMTPPasswordEncrypted:  encA(smtpPass),
	}
	if err := db.CreateSettings(nil, settings); err != nil {
		t.Fatalf("CreateSettings: %v", err)
	}
	client := &models.Client{
		ClientIdentifier:      "c-" + fake.UUID(),
		ClientSecretEncrypted: encA(clientSec),
	}
	if err := db.CreateClient(nil, client); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	user := &models.User{
		Subject:                              fake.UUID(),
		Username:                             fake.UUID(),
		Email:                                fake.UUID() + "@example.com",
		PasswordHash:                         "x",
		EmailVerificationCodeEncrypted:       encA(emailCode),
		PhoneNumberVerificationCodeEncrypted: encA(phoneCode),
		OTPSecretEncrypted:                   encA(otpSeed),
		ForgotPasswordCodeEncrypted:          encA(forgotCode),
		OtpEnrollmentSecretEncrypted:         encA(otpEnrolment),
	}
	if err := db.CreateUser(nil, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	preReg := &models.PreRegistration{
		Email:                     fake.UUID() + "@example.com",
		PasswordHash:              "x",
		VerificationCodeEncrypted: encA(preRegCode),
	}
	if err := db.CreatePreRegistration(nil, preReg); err != nil {
		t.Fatalf("CreatePreRegistration: %v", err)
	}

	// Same key, or no previous key: no-op.
	if rotated, err := db.RotateEncryptionKeyIfNeeded(keyA, keyA); err != nil || rotated {
		t.Errorf("same key = (%v, %v), want (false, nil)", rotated, err)
	}
	if rotated, err := db.RotateEncryptionKeyIfNeeded(keyA, nil); err != nil || rotated {
		t.Errorf("no previous = (%v, %v), want (false, nil)", rotated, err)
	}

	// Data is under keyA; asking to rotate between keyB (current) and keyC
	// (previous) matches neither -> fail-closed.
	if _, err := db.RotateEncryptionKeyIfNeeded(keyB, keyC); err == nil {
		t.Error("expected error when data decrypts under neither key")
	}

	// Rotate keyA -> keyB.
	rotated, err := db.RotateEncryptionKeyIfNeeded(keyB, keyA)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation to occur")
	}

	// rekeyed asserts both halves for one column: it reads under the new key, and it no longer
	// reads under the retired one. The second half is what catches a column missing from
	// commondb.aesProtectedColumns, since an untouched column still decrypts under keyA.
	rekeyed := func(name string, ct []byte, want string) {
		t.Helper()
		got, err := encryption.DecryptText(ct, keyB)
		if err != nil {
			t.Errorf("%s: does not decrypt under the new key: %v", name, err)
		} else if got != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
		if _, err := encryption.DecryptText(ct, keyA); err == nil {
			t.Errorf("%s still decrypts under the retired key: is the column missing "+
				"from commondb.aesProtectedColumns?", name)
		}
	}

	gotSettings, err := db.GetSettingsById(nil, settings.Id)
	if err != nil {
		t.Fatalf("GetSettingsById: %v", err)
	}
	rekeyed("settings.smtp_password_encrypted", gotSettings.SMTPPasswordEncrypted, smtpPass)
	// Rotation leaves the legacy data-key column alone. Blanking it was the 1.5.x startup
	// conversion's own bookkeeping and rotation only ever reached it by sharing reencryptAll;
	// #359 removed that statement (#262), and this is what fails if someone puts it back.
	if !bytes.Equal(gotSettings.AESEncryptionKeyLegacy, legacyKey) {
		t.Errorf("rotation rewrote settings.aes_encryption_key: got len=%d, want the seeded value",
			len(gotSettings.AESEncryptionKeyLegacy))
	}

	gotClient, err := db.GetClientById(nil, client.Id)
	if err != nil {
		t.Fatalf("GetClientById: %v", err)
	}
	rekeyed("clients.client_secret_encrypted", gotClient.ClientSecretEncrypted, clientSec)

	gotUser, err := db.GetUserById(nil, user.Id)
	if err != nil {
		t.Fatalf("GetUserById: %v", err)
	}
	rekeyed("users.email_verification_code_encrypted", gotUser.EmailVerificationCodeEncrypted, emailCode)
	rekeyed("users.phone_number_verification_code_encrypted", gotUser.PhoneNumberVerificationCodeEncrypted, phoneCode)
	rekeyed("users.otp_secret_encrypted", gotUser.OTPSecretEncrypted, otpSeed)
	rekeyed("users.forgot_password_code_encrypted", gotUser.ForgotPasswordCodeEncrypted, forgotCode)
	rekeyed("users.otp_enrollment_secret_encrypted", gotUser.OtpEnrollmentSecretEncrypted, otpEnrolment)

	gotPreReg, err := db.GetPreRegistrationById(nil, preReg.Id)
	if err != nil {
		t.Fatalf("GetPreRegistrationById: %v", err)
	}
	rekeyed("pre_registrations.verification_code_encrypted", gotPreReg.VerificationCodeEncrypted, preRegCode)

	keys, err := db.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("GetAllSigningKeys: %v", err)
	}
	rekeyed("key_pairs.private_key_pem", keys[0].PrivateKeyPEM, pem)

	// Idempotent: data is already under keyB, so a repeat is a no-op.
	if rotated, err := db.RotateEncryptionKeyIfNeeded(keyB, keyA); err != nil || rotated {
		t.Errorf("second rotate = (%v, %v), want (false, nil)", rotated, err)
	}
}

// TestRotateEncryptionKeyIfNeeded_PlaintextPemFailsClosed is the one statement this tree can make
// about a database that never booted 1.6.x. #359 deleted the startup conversion that encrypted a
// plaintext RSA PEM (#262) and ships no pre-flight to refuse such a database (decision 8), so what
// is left to establish is that rotation does not quietly half-convert one: the canary is the first
// non-empty PrivateKeyPEM, a plaintext PEM decrypts under neither key, and RotateEncryptionKeyIfNeeded
// errors before re-keying anything.
//
// That is why commondb.reencryptPrivateKeys keeps its plaintext-PEM branch as unreachable code
// rather than deleting it: nothing can reach it, and this test is the reason that claim holds.
//
// It needs a database of its own because the canary is whichever key pair comes back first, so a
// plaintext one cannot be added beside the encrypted canary of the test above and still be read.
func TestRotateEncryptionKeyIfNeeded_PlaintextPemFailsClosed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rotate-plaintext-pem.db")
	db, err := sqlitedb.NewSQLiteDatabase(&sqlitedb.DatabaseConfig{DSN: dbPath}, false)
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	keyA := []byte("0123456789abcdef0123456789abcdef")
	keyB := []byte("fedcba9876543210fedcba9876543210")

	const (
		pemPlain  = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc123fakepemcontent\n-----END RSA PRIVATE KEY-----\n"
		clientSec = "client-secret"
	)

	if err := db.CreateKeyPair(nil, &models.KeyPair{
		State: "current", KeyIdentifier: fake.UUID(), Type: "RSA", Algorithm: "RS256",
		PrivateKeyPEM: []byte(pemPlain), // the pre-1.6.0 state: never encrypted
	}); err != nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	secretUnderA, err := encryption.EncryptText(clientSec, keyA)
	if err != nil {
		t.Fatalf("EncryptText: %v", err)
	}
	client := &models.Client{
		ClientIdentifier:      "c-" + fake.UUID(),
		ClientSecretEncrypted: secretUnderA,
	}
	if err := db.CreateClient(nil, client); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	rotated, err := db.RotateEncryptionKeyIfNeeded(keyB, keyA)
	if err == nil {
		t.Fatal("expected an error: a plaintext PEM decrypts under neither key")
	}
	if rotated {
		t.Error("rotation reported success on a database it refused to read")
	}

	// Nothing was re-keyed. The PEM is still the plaintext it was, and the client secret still
	// reads under keyA: the refusal happens before reencryptToKey opens its transaction.
	keys, err := db.GetAllSigningKeys(nil)
	if err != nil {
		t.Fatalf("GetAllSigningKeys: %v", err)
	}
	if !bytes.Equal(keys[0].PrivateKeyPEM, []byte(pemPlain)) {
		t.Error("the plaintext PEM was rewritten by a rotation that reported failure")
	}
	gotClient, err := db.GetClientById(nil, client.Id)
	if err != nil {
		t.Fatalf("GetClientById: %v", err)
	}
	if dec, err := encryption.DecryptText(gotClient.ClientSecretEncrypted, keyA); err != nil || dec != clientSec {
		t.Errorf("client secret after the refused rotation = (%q, %v), want (%q, nil)", dec, err, clientSec)
	}
}
