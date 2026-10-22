package record

import (
	"database/sql"
	"strings"
)

// OtpConsecutiveFailureLimit is the number of consecutive failed attempts against one
// enrolled authenticator that NIST SP 800-63B section 3.2.2 allows before the verifier
// SHALL disable it, which in Goiabada is the count a wrong or replayed code advances, a
// successful verification clears, and a fresh enrolment -- the rebind -- clears too
// (#489). The password is deliberately outside it: the account-wide password budget
// stays a rate, because a count a stranger can trip by knowing an email address would
// turn a one-hour denial into an indefinite one (#89, #489).
const OtpConsecutiveFailureLimit = 100

type User struct {
	Id                             int64        `db:"id" fieldtag:"pk"`
	CreatedAt                      sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt                      sql.NullTime `db:"updated_at"`
	Enabled                        bool         `db:"enabled"`
	Subject                        string       `db:"subject"`
	Username                       string       `db:"username"`
	GivenName                      string       `db:"given_name"`
	MiddleName                     string       `db:"middle_name"`
	FamilyName                     string       `db:"family_name"`
	Nickname                       string       `db:"nickname"`
	Website                        string       `db:"website"`
	Gender                         string       `db:"gender"`
	Email                          string       `db:"email"`
	EmailVerified                  bool         `db:"email_verified"`
	EmailVerificationCodeEncrypted []byte       `db:"email_verification_code_encrypted"`
	EmailVerificationCodeIssuedAt  sql.NullTime `db:"email_verification_code_issued_at"`
	ZoneInfoCountryName            string       `db:"zone_info_country_name"`
	ZoneInfo                       string       `db:"zone_info"`
	Locale                         string       `db:"locale"`
	BirthDate                      sql.NullTime `db:"birth_date"`
	PhoneNumberCountryUniqueId     string       `db:"phone_number_country_uniqueid"`
	PhoneNumberCountryCallingCode  string       `db:"phone_number_country_callingcode"`
	PhoneNumber                    string       `db:"phone_number"`
	PhoneNumberVerified            bool         `db:"phone_number_verified"`
	AddressLine1                   string       `db:"address_line1"`
	AddressLine2                   string       `db:"address_line2"`
	AddressLocality                string       `db:"address_locality"`
	AddressRegion                  string       `db:"address_region"`
	AddressPostalCode              string       `db:"address_postal_code"`
	AddressCountry                 string       `db:"address_country"`
	PasswordHash                   string       `db:"password_hash"`
	OTPSecretEncrypted             []byte       `db:"otp_secret_encrypted"`
	OTPEnabled                     bool         `db:"otp_enabled"`
	ForgotPasswordCodeEncrypted    []byte       `db:"forgot_password_code_encrypted"`
	ForgotPasswordCodeIssuedAt     sql.NullTime `db:"forgot_password_code_issued_at"`
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
	// authentication state once the user advances to N+1. Tagged dont-update so that
	// UpdateUser, which writes every other column from the model it is handed, can never
	// regress it from a stale model. No production code calls UpdateUser any more, and
	// TestNoWholeRowUserSave in internal/data holds it, but the data and integration tiers
	// seed fixtures through it (#471). It advances only through
	// IncrementUserAuthStateGeneration (#106).
	AuthStateGeneration int64 `db:"auth_state_generation" fieldtag:"dont-update"`
	// LastOTPStep is the most recently consumed TOTP time step, 0 meaning none has
	// been consumed: a step is Unix seconds divided by 30, so any real one is around
	// 6e7, and the column default is unambiguous. It is what makes a code one-time-use
	// (#111, RFC 6238 5.2). Tagged
	// dont-update for the same reason AuthStateGeneration is: a whole-row write from a
	// model read before a claim would write the pre-claim value over it. The OTP
	// enrolment used to do exactly that to its own claim, before #471 made it a narrow
	// compare-and-set. It moves only through TryConsumeUserOTPStep,
	// TryConsumeEnrolledUserOTPStep and ResetUserOTPStep.
	LastOTPStep int64 `db:"last_otp_step" fieldtag:"dont-update"`
	// OtpConfigGeneration is the authoritative per-user counter of authenticator
	// changes: it advances by one every time OTP is enabled or disabled, and never
	// otherwise. A session whose own snapshot differs from it owes a level 2 re-prompt.
	// Being per user rather than per session is what makes "every session of this user"
	// one statement, which the boolean it replaced could never do (#242).
	//
	// Tagged dont-update for the same reason AuthStateGeneration and LastOTPStep are: in
	// the ordinary update set, a whole-row write from a stale model would regress the
	// counter and silently discharge every session's obligation. It advances only through
	// IncrementUserOtpConfigGeneration.
	OtpConfigGeneration int64 `db:"otp_config_generation" fieldtag:"dont-update"`
	// OtpConsecutiveFailures is how many attempts against the enrolled authenticator have
	// failed without a successful verification between them, and at
	// OtpConsecutiveFailureLimit the authenticator is disabled until it is rebound
	// (NIST SP 800-63B section 3.2.2, #489). A successful verification clears it, that
	// section's "disregard any previous failed attempts", and so does the fresh enrolment
	// that rebinding is. Only a failed attempt against the enrolled authenticator advances
	// it: the OTP prompt sits behind the password, so a stranger cannot trip it, which is
	// what keeps the lockout-DoS of #89 from applying.
	//
	// Tagged dont-update for the same reason OtpConfigGeneration is: in the ordinary
	// update set, a whole-row write from a model read before a verification would write
	// the pre-attempt count back over the row's, silently unlocking a disabled
	// authenticator. It moves only through TryConsumeEnrolledUserOTPStep, which clears it
	// in the same statement that claims the step, IncrementUserOtpConsecutiveFailures, and
	// ClearUserOtpConsecutiveFailures, which a fresh enrolment calls.
	OtpConsecutiveFailures int64 `db:"otp_consecutive_failures" fieldtag:"dont-update"`
	// OtpEnrollmentSecretEncrypted is the AES-GCM ciphertext of a TOTP enrolment the server
	// has issued but the user has not yet confirmed, and OtpEnrollmentIssuedAt is when it was
	// issued. NULL in both means no enrolment is pending, which is the state of every user who
	// is not part way through one. They are the third pending-credential pair on this table,
	// in the same shape as email verification and forgot password, and they are cleared the
	// moment the authenticator is established.
	//
	// **The ciphertext is the whole otpauth:// URL, not the base32 seed the column is named
	// for.** The enrolment endpoint has to answer a repeat call with the same QR image, and
	// the image can only be rendered from the URL: otp.RenderQRCodeImage parses an otpauth://
	// URL and refuses a bare secret, and nothing rebuilds a URL from one. The seed comes off
	// the URL with otp.SecretFromKeyURL wherever it is needed, so there is one stored value
	// rather than two that could disagree (#247).
	//
	// Both are tagged dont-update for the reason AuthStateGeneration, LastOTPStep and
	// OtpConfigGeneration are, and the hazard is the pair's whole purpose. UpdateUser writes
	// every field not tagged pk or dont-update, from the model it is handed. In the ordinary
	// update set, two concurrent enrolment requests would each see no pending value, issue
	// different seeds and leave only the last one usable, which is exactly the reload bug these
	// columns exist to close; and any full-row write from a model loaded before issuance would
	// erase or resurrect the pending seed. No production code writes a user's whole row any
	// more: every save names its own columns, and TestNoWholeRowUserSave in internal/data
	// refuses a production call to UpdateUser, which stays for the data and integration tiers'
	// fixtures (#471). They move only through TryInstallPendingOTPEnrollment and
	// ClearPendingOTPEnrollment.
	OtpEnrollmentSecretEncrypted []byte       `db:"otp_enrollment_secret_encrypted" fieldtag:"dont-update"`
	OtpEnrollmentIssuedAt        sql.NullTime `db:"otp_enrollment_issued_at" fieldtag:"dont-update"`

	Groups      []Group         `db:"-"`
	Permissions []Permission    `db:"-"`
	Attributes  []UserAttribute `db:"-"`
}

// OtpAuthenticatorDisabled reports whether the user has an authenticator that the
// consecutive-failure count has disabled: OTPEnabled still reads true, and every code is
// refused until it is removed and a new one set up (#489). A count left at the limit after
// a removal disables nothing, since there is no authenticator, and the next one set up
// clears it.
func (u *User) OtpAuthenticatorDisabled() bool {
	return u.OTPEnabled && u.OtpConsecutiveFailures >= OtpConsecutiveFailureLimit
}

func (u *User) FullName() string {
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
