package datatests

import (
	"bytes"
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The keys every case below re-keys between. Distinct and 32 bytes each, so a value under one
// opens under that one alone.
var (
	rekeyKeyA = []byte("0123456789abcdef0123456789abcdef")
	rekeyKeyB = []byte("fedcba9876543210fedcba9876543210")
	rekeyKeyC = []byte("aaaabbbbccccddddaaaabbbbccccdddd")
)

// rekeyEncrypt is the ciphertext under key that the seeded rows carry.
func rekeyEncrypt(t *testing.T, plaintext string, key []byte) []byte {
	t.Helper()
	ciphertext, err := encryption.EncryptText(plaintext, key)
	require.NoError(t, err)
	return ciphertext
}

// rekeyKeyPair is a key pair holding pem as its private key, the row shape ReencryptToKey re-keys
// apart from the string columns.
func rekeyKeyPair(pem []byte) *record.KeyPair {
	return &record.KeyPair{
		State: record.KeyStateCurrent.String(), KeyIdentifier: fake.UUID(), Type: "RSA", Algorithm: "RS256",
		PrivateKeyPEM: pem,
	}
}

// TestReencryptToKey exercises the re-key behind env-to-env key rotation (#83) on the tier's own
// engine, in a database of its own because it rewrites every encrypted row there is.
//
// It owns the exhaustive table over commondb.aesProtectedColumns. The list is "an enumeration
// nothing derives" by its own comment, so this test is what derives it: every column is seeded
// under keyA, and after the re-key every one must decrypt under keyB and NO LONGER under keyA. A
// column dropped from the enumeration survives as ciphertext readable only under the retired key,
// which is exactly what the second half of each pair catches.
//
// Whether to re-key at all is not asked here. That is the canary decision, which #438 decision 8
// moved to datafactory's startup task, where its unit table covers every branch.
func TestReencryptToKey(t *testing.T) {
	h := migratedIsolatedDB(t)
	db := h.DB
	ctx := context.Background()

	// One seeded value per entry of aesProtectedColumns, plus the RSA private key PEM that
	// reencryptPrivateKeys handles separately.
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
	// It is neither keyA nor keyB: the re-key must not read it and must not write it.
	legacyKey := []byte("legacy-key-legacy-key-legacy-key")

	require.NoError(t, db.CreateKeyPair(ctx, nil, rekeyKeyPair(rekeyEncrypt(t, pem, rekeyKeyA))))
	settings := initialSettings("Rotate")
	settings.AESEncryptionKeyLegacy = legacyKey
	settings.SMTPPasswordEncrypted = rekeyEncrypt(t, smtpPass, rekeyKeyA)
	require.NoError(t, db.CreateSettings(ctx, nil, settings))
	client := &record.Client{
		ClientIdentifier:      "c-" + fake.UUID(),
		ClientSecretEncrypted: rekeyEncrypt(t, clientSec, rekeyKeyA),
	}
	require.NoError(t, db.CreateClient(ctx, nil, client))
	user := &record.User{
		Subject:                              fake.UUID(),
		Username:                             fake.Username(),
		Email:                                fake.Email(),
		PasswordHash:                         "x",
		EmailVerificationCodeEncrypted:       rekeyEncrypt(t, emailCode, rekeyKeyA),
		PhoneNumberVerificationCodeEncrypted: rekeyEncrypt(t, phoneCode, rekeyKeyA),
		OTPSecretEncrypted:                   rekeyEncrypt(t, otpSeed, rekeyKeyA),
		ForgotPasswordCodeEncrypted:          rekeyEncrypt(t, forgotCode, rekeyKeyA),
		OtpEnrollmentSecretEncrypted:         rekeyEncrypt(t, otpEnrolment, rekeyKeyA),
	}
	require.NoError(t, db.CreateUser(ctx, nil, user))
	preReg := &record.PreRegistration{
		Email:                     fake.Email(),
		VerificationCodeEncrypted: rekeyEncrypt(t, preRegCode, rekeyKeyA),
		VerificationCodeHash:      codeHashOf(t, fake.UUID()),
	}
	require.NoError(t, db.CreatePreRegistration(ctx, nil, preReg))

	require.NoError(t, db.ReencryptToKey(ctx, rekeyKeyA, rekeyKeyB))

	// rekeyed asserts both halves for one column: it reads under the new key, and it no longer
	// reads under the retired one. The second half is what catches a column missing from
	// commondb.aesProtectedColumns, since an untouched column still decrypts under keyA.
	rekeyed := func(name string, ct []byte, want string) {
		t.Helper()
		got, decryptTextErr := encryption.DecryptText(ct, rekeyKeyB)
		if assert.NoErrorf(t, decryptTextErr, "%s: does not decrypt under the new key", name) {
			assert.Equalf(t, want, got, "%s: the re-key changed the plaintext", name)
		}
		_, decryptTextErr = encryption.DecryptText(ct, rekeyKeyA)
		assert.Errorf(t, decryptTextErr,
			"%s still decrypts under the retired key: is the column missing from commondb.aesProtectedColumns?", name)
	}

	gotSettings, err := db.GetSettingsById(ctx, nil, settings.Id)
	require.NoError(t, err)
	rekeyed("settings.smtp_password_encrypted", gotSettings.SMTPPasswordEncrypted, smtpPass)
	// The re-key leaves the legacy data-key column alone. Blanking it was the 1.5.x startup
	// conversion's own bookkeeping and rotation only ever reached it by sharing reencryptAll;
	// #359 removed that statement (#262), and this is what fails if someone puts it back.
	assert.True(t, bytes.Equal(gotSettings.AESEncryptionKeyLegacy, legacyKey),
		"the re-key rewrote settings.aes_encryption_key: got len=%d, want the seeded value",
		len(gotSettings.AESEncryptionKeyLegacy))

	gotClient, err := db.GetClientById(ctx, nil, client.Id)
	require.NoError(t, err)
	rekeyed("clients.client_secret_encrypted", gotClient.ClientSecretEncrypted, clientSec)

	gotUser, err := db.GetUserById(ctx, nil, user.Id)
	require.NoError(t, err)
	rekeyed("users.email_verification_code_encrypted", gotUser.EmailVerificationCodeEncrypted, emailCode)
	rekeyed("users.phone_number_verification_code_encrypted", gotUser.PhoneNumberVerificationCodeEncrypted, phoneCode)
	rekeyed("users.otp_secret_encrypted", gotUser.OTPSecretEncrypted, otpSeed)
	rekeyed("users.forgot_password_code_encrypted", gotUser.ForgotPasswordCodeEncrypted, forgotCode)
	rekeyed("users.otp_enrollment_secret_encrypted", gotUser.OtpEnrollmentSecretEncrypted, otpEnrolment)

	gotPreReg, err := db.GetPreRegistrationById(ctx, nil, preReg.Id)
	require.NoError(t, err)
	rekeyed("pre_registrations.verification_code_encrypted", gotPreReg.VerificationCodeEncrypted, preRegCode)

	keys, err := db.GetAllSigningKeys(ctx, nil)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	rekeyed("key_pairs.private_key_pem", keys[0].PrivateKeyPEM, pem)
}

// TestReencryptToKey_RefusesShortKeys pins the length check on both keys. A short new key would
// encrypt every secret under a key the configuration could never supply again, and a short old
// key reads nothing, so each is refused before the transaction opens and nothing is rewritten.
func TestReencryptToKey_RefusesShortKeys(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	const clientSec = "client-secret"
	client := &record.Client{
		ClientIdentifier:      "c-" + fake.UUID(),
		ClientSecretEncrypted: rekeyEncrypt(t, clientSec, rekeyKeyA),
	}
	require.NoError(t, h.DB.CreateClient(ctx, nil, client))

	cases := []struct {
		name           string
		oldKey, newKey []byte
	}{
		{"a short old key", rekeyKeyA[:16], rekeyKeyB},
		{"a short new key", rekeyKeyA, rekeyKeyB[:16]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := h.DB.ReencryptToKey(ctx, tc.oldKey, tc.newKey)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "re-encryption requires 32-byte old and new keys")

			got, err := h.DB.GetClientById(ctx, nil, client.Id)
			require.NoError(t, err)
			plaintext, err := encryption.DecryptText(got.ClientSecretEncrypted, rekeyKeyA)
			require.NoError(t, err, "a refused re-key must leave the secret under the old key")
			assert.Equal(t, clientSec, plaintext)
		})
	}
}

// TestReencryptToKey_AFailureLeavesEverythingUnderTheOldKey pins the one-transaction property. The
// client secret is under keyA and is re-keyed first; the private key is under keyC, so the re-key
// fails at its last step, after every string column has been rewritten inside the transaction.
// What a failure must leave is the database as it was: the client secret still under keyA, not
// under keyB beside a private key nobody re-keyed. Half a re-key is a database no single key opens.
func TestReencryptToKey_AFailureLeavesEverythingUnderTheOldKey(t *testing.T) {
	h := migratedIsolatedDB(t)
	ctx := context.Background()

	const (
		clientSec = "client-secret"
		pem       = "-----BEGIN RSA PRIVATE KEY-----\nfakepem\n-----END RSA PRIVATE KEY-----\n"
	)
	client := &record.Client{
		ClientIdentifier:      "c-" + fake.UUID(),
		ClientSecretEncrypted: rekeyEncrypt(t, clientSec, rekeyKeyA),
	}
	require.NoError(t, h.DB.CreateClient(ctx, nil, client))
	unreadable := rekeyEncrypt(t, pem, rekeyKeyC)
	require.NoError(t, h.DB.CreateKeyPair(ctx, nil, rekeyKeyPair(unreadable)))

	err := h.DB.ReencryptToKey(ctx, rekeyKeyA, rekeyKeyB)

	require.Error(t, err, "a private key that does not open under the old key must fail the re-key")
	assert.Contains(t, err.Error(), "re-encrypting RSA private keys")

	got, err := h.DB.GetClientById(ctx, nil, client.Id)
	require.NoError(t, err)
	plaintext, err := encryption.DecryptText(got.ClientSecretEncrypted, rekeyKeyA)
	require.NoError(t, err,
		"the client secret was re-keyed by a transaction that failed: the re-key is not all-or-nothing")
	assert.Equal(t, clientSec, plaintext)

	keys, err := h.DB.GetAllSigningKeys(ctx, nil)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, unreadable, keys[0].PrivateKeyPEM, "the private key is the row the failure was on, and it is unchanged")
}
