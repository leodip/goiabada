package commondb

// aesProtectedColumns lists the (table, column) pairs holding AES-GCM ciphertext
// of string secrets that must be re-encrypted when the data-encryption key changes
// (issue #83). The re-encryption sweep, ReencryptStoredSecrets, takes every column
// through in this order, and the signing keys' private_key_pem after them.
var aesProtectedColumns = []struct{ table, column string }{
	{"settings", "smtp_password_encrypted"},
	{"settings", "turnstile_secret_key_encrypted"},
	{"clients", "client_secret_encrypted"},
	{"users", "email_verification_code_encrypted"},
	{"users", "otp_secret_encrypted"},
	{"users", "forgot_password_code_encrypted"},
	{"users", "otp_enrollment_secret_encrypted"},
	{"pre_registrations", "verification_code_encrypted"},
}

// storedValue is one row's id and the bytes one column holds for it.
type storedValue struct {
	id    int64
	value []byte
}
