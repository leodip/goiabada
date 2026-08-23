package models

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/encryption"
)

type User struct {
	Id                                   int64        `db:"id" fieldtag:"pk"`
	CreatedAt                            sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt                            sql.NullTime `db:"updated_at"`
	Enabled                              bool         `db:"enabled"`
	Subject                              uuid.UUID    `db:"subject"`
	Username                             string       `db:"username"`
	GivenName                            string       `db:"given_name"`
	MiddleName                           string       `db:"middle_name"`
	FamilyName                           string       `db:"family_name"`
	Nickname                             string       `db:"nickname"`
	Website                              string       `db:"website"`
	Gender                               string       `db:"gender"`
	Email                                string       `db:"email"`
	EmailVerified                        bool         `db:"email_verified"`
	EmailVerificationCodeEncrypted       []byte       `db:"email_verification_code_encrypted"`
	EmailVerificationCodeIssuedAt        sql.NullTime `db:"email_verification_code_issued_at"`
	ZoneInfoCountryName                  string       `db:"zone_info_country_name"`
	ZoneInfo                             string       `db:"zone_info"`
	Locale                               string       `db:"locale"`
	BirthDate                            sql.NullTime `db:"birth_date"`
	PhoneNumberCountryUniqueId           string       `db:"phone_number_country_uniqueid"`
	PhoneNumberCountryCallingCode        string       `db:"phone_number_country_callingcode"`
	PhoneNumber                          string       `db:"phone_number"`
	PhoneNumberVerified                  bool         `db:"phone_number_verified"`
	PhoneNumberVerificationCodeEncrypted []byte       `db:"phone_number_verification_code_encrypted"`
	PhoneNumberVerificationCodeIssuedAt  sql.NullTime `db:"phone_number_verification_code_issued_at"`
	AddressLine1                         string       `db:"address_line1"`
	AddressLine2                         string       `db:"address_line2"`
	AddressLocality                      string       `db:"address_locality"`
	AddressRegion                        string       `db:"address_region"`
	AddressPostalCode                    string       `db:"address_postal_code"`
	AddressCountry                       string       `db:"address_country"`
	PasswordHash                         string       `db:"password_hash"`
	OTPSecret                            string       `db:"otp_secret"`
	OTPSecretEncrypted                   []byte       `db:"otp_secret_encrypted"`
	OTPEnabled                           bool         `db:"otp_enabled"`
	ForgotPasswordCodeEncrypted          []byte       `db:"forgot_password_code_encrypted"`
	ForgotPasswordCodeIssuedAt           sql.NullTime `db:"forgot_password_code_issued_at"`
	// ForgotPasswordCodeHash is an unsalted SHA-256 of the outstanding reset code, and
	// the only way the reset link finds this row: the link carries the code and nothing
	// else, so no email address travels in it and no part of it needs percent-encoding
	// (#112). Empty means no code is outstanding, which is unreachable from any real
	// code because SHA-256 hex is always 64 characters. The encrypted column beside it
	// stays: it is what proves a submitted code matches, where this one only locates the
	// row.
	ForgotPasswordCodeHash string `db:"forgot_password_code_hash"`
	// AuthStateGeneration is the authoritative per-user authentication generation:
	// credentials authenticated under generation N cannot create or use
	// authentication state once the user advances to N+1. Tagged dont-update because
	// every credential handler loads the whole user and writes it back, so leaving it
	// in the ordinary update set would let a stale model regress it. It advances only
	// through IncrementUserAuthStateGeneration (#106).
	AuthStateGeneration int64 `db:"auth_state_generation" fieldtag:"dont-update"`
	// LastOTPStep is the most recently consumed TOTP time step, 0 meaning none has
	// been consumed: a step is Unix seconds divided by 30, so any real one is around
	// 6e7, and the column default is unambiguous. It is what makes a code one-time-use
	// (#111, RFC 6238 5.2). Tagged
	// dont-update for the same reason AuthStateGeneration is, and the hazard is even
	// more direct here: the OTP enrollment handler loads the whole user, claims a step
	// and then writes the user back, so leaving the column in the ordinary update set
	// would let it write the pre-claim value over its own claim. It moves only through
	// TryConsumeUserOTPStep and ResetUserOTPStep.
	LastOTPStep int64 `db:"last_otp_step" fieldtag:"dont-update"`
	// OtpConfigGeneration is the authoritative per-user counter of authenticator
	// changes: it advances by one every time OTP is enabled or disabled, and never
	// otherwise. A session whose own snapshot differs from it owes a level 2 re-prompt.
	// Being per user rather than per session is what makes "every session of this user"
	// one statement, which the boolean it replaced could never do (#242).
	//
	// Tagged dont-update for the same reason AuthStateGeneration and LastOTPStep are:
	// the OTP handlers load the whole user, change it and write it back, so leaving the
	// column in the ordinary update set would let a stale model regress the counter and
	// silently discharge every session's obligation. It advances only through
	// IncrementUserOtpConfigGeneration.
	OtpConfigGeneration int64           `db:"otp_config_generation" fieldtag:"dont-update"`
	Groups              []Group         `db:"-"`
	Permissions         []Permission    `db:"-"`
	Attributes          []UserAttribute `db:"-"`
}

// SetOTPSecret encrypts the TOTP seed at rest (AES-256-GCM, via the process
// data cipher) into OTPSecretEncrypted and clears the legacy plaintext OTPSecret
// field. See issue #82: TOTP secrets must not be stored in plaintext. The data
// cipher must be initialized at startup (encryption.InitDataCipher, issue #83).
func (u *User) SetOTPSecret(secret string) error {
	encrypted, err := encryption.EncryptData(secret)
	if err != nil {
		return err
	}
	u.OTPSecretEncrypted = encrypted
	u.OTPSecret = ""
	return nil
}

// GetOTPSecret returns the decrypted TOTP seed, or an empty string if the user
// has no encrypted secret. Existing rows are migrated to the encrypted form at
// startup (BackfillEncryptedOTPSecrets), so at runtime the plaintext column is
// always empty and is not consulted here.
func (u *User) GetOTPSecret() (string, error) {
	if len(u.OTPSecretEncrypted) == 0 {
		return "", nil
	}
	return encryption.DecryptData(u.OTPSecretEncrypted)
}

// ClearOTPSecret removes any stored TOTP seed, both the encrypted value and the
// legacy plaintext field.
func (u *User) ClearOTPSecret() {
	u.OTPSecretEncrypted = nil
	u.OTPSecret = ""
}

func (u *User) HasAddress() bool {
	if len(strings.TrimSpace(u.AddressLine1)) > 0 ||
		len(strings.TrimSpace(u.AddressLine2)) > 0 ||
		len(strings.TrimSpace(u.AddressLocality)) > 0 ||
		len(strings.TrimSpace(u.AddressRegion)) > 0 ||
		len(strings.TrimSpace(u.AddressPostalCode)) > 0 ||
		len(strings.TrimSpace(u.AddressCountry)) > 0 {
		return true
	}
	return false
}

func (u *User) GetAddressClaim() map[string]string {
	addressClaim := make(map[string]string)

	formatted := ""
	streetAddress := fmt.Sprintf("%v\r\n%v", u.AddressLine1, u.AddressLine2)
	if len(strings.TrimSpace(streetAddress)) > 0 {
		addressClaim["street_address"] = streetAddress
		formatted += streetAddress + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressLocality)) > 0 {
		addressClaim["locality"] = u.AddressLocality
		formatted += u.AddressLocality + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressRegion)) > 0 {
		addressClaim["region"] = u.AddressRegion
		formatted += u.AddressRegion + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressPostalCode)) > 0 {
		addressClaim["postal_code"] = u.AddressPostalCode
		formatted += u.AddressPostalCode + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressCountry)) > 0 {
		addressClaim["country"] = u.AddressCountry
		formatted += u.AddressCountry + "\r\n"
	}

	if len(strings.TrimSpace(u.AddressCountry)) > 0 {
		addressClaim["formatted"] = strings.TrimSpace(formatted)
	}

	return addressClaim
}

func (u *User) GetDateOfBirthFormatted() string {
	dateOfBirthFormatted := ""
	if u != nil && u.BirthDate.Valid {
		dateOfBirthFormatted = u.BirthDate.Time.Format("2006-01-02")
	}
	return dateOfBirthFormatted
}

func (u *User) GetFullName() string {
	fullName := ""

	if u != nil {
		if len(u.GivenName) > 0 {
			fullName += u.GivenName
		}

		if len(u.MiddleName) > 0 {
			fullName += " " + u.MiddleName
		}

		if len(u.FamilyName) > 0 {
			fullName += " " + u.FamilyName
		}
		fullName = strings.TrimSpace(fullName)
	}

	return fullName
}
