package commondb

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func SetUserInsertColsAndValues(insertBuilder *sqlbuilder.InsertBuilder, user *entitiesv2.User) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("users")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"enabled",
		"subject",
		"username",
		"given_name",
		"middle_name",
		"family_name",
		"nickname",
		"website",
		"gender",
		"email",
		"email_verified",
		"email_verification_code_encrypted",
		"email_verification_code_issued_at",
		"zone_info_country_name",
		"zone_info",
		"locale",
		"birth_date",
		"phone_number",
		"phone_number_verified",
		"phone_number_verification_code_encrypted",
		"phone_number_verification_code_issued_at",
		"address_line1",
		"address_line2",
		"address_locality",
		"address_region",
		"address_postal_code",
		"address_country",
		"password_hash",
		"otp_secret",
		"otp_enabled",
		"forgot_password_code_encrypted",
		"forgot_password_code_issued_at",
	)

	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		user.Enabled,
		user.Subject,
		user.Username,
		user.GivenName,
		user.MiddleName,
		user.FamilyName,
		user.Nickname,
		user.Website,
		user.Gender,
		user.Email,
		user.EmailVerified,
		user.EmailVerificationCodeEncrypted,
		user.EmailVerificationCodeIssuedAt,
		user.ZoneInfoCountryName,
		user.ZoneInfo,
		user.Locale,
		user.BirthDate,
		user.PhoneNumber,
		user.PhoneNumberVerified,
		user.PhoneNumberVerificationCodeEncrypted,
		user.PhoneNumberVerificationCodeIssuedAt,
		user.AddressLine1,
		user.AddressLine2,
		user.AddressLocality,
		user.AddressRegion,
		user.AddressPostalCode,
		user.AddressCountry,
		user.PasswordHash,
		user.OTPSecret,
		user.OTPEnabled,
		user.ForgotPasswordCodeEncrypted,
		user.ForgotPasswordCodeIssuedAt,
	)

	return insertBuilder
}

func ScanUser(rows *sql.Rows) (*entitiesv2.User, error) {
	var (
		id                                       int64
		created_at                               time.Time
		updated_at                               time.Time
		enabled                                  bool
		subject                                  uuid.UUID
		username                                 string
		given_name                               string
		middle_name                              string
		family_name                              string
		nickname                                 string
		website                                  string
		gender                                   string
		email                                    string
		email_verified                           bool
		email_verification_code_encrypted        []byte
		email_verification_code_issued_at        *time.Time
		zone_info_country_name                   string
		zone_info                                string
		locale                                   string
		birth_date                               *time.Time
		phone_number                             string
		phone_number_verified                    bool
		phone_number_verification_code_encrypted []byte
		phone_number_verification_code_issued_at *time.Time
		address_line1                            string
		address_line2                            string
		address_locality                         string
		address_region                           string
		address_postal_code                      string
		address_country                          string
		password_hash                            string
		otp_secret                               string
		otp_enabled                              bool
		forgot_password_code_encrypted           []byte
		forgot_password_code_issued_at           *time.Time
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&enabled,
		&subject,
		&username,
		&given_name,
		&middle_name,
		&family_name,
		&nickname,
		&website,
		&gender,
		&email,
		&email_verified,
		&email_verification_code_encrypted,
		&email_verification_code_issued_at,
		&zone_info_country_name,
		&zone_info,
		&locale,
		&birth_date,
		&phone_number,
		&phone_number_verified,
		&phone_number_verification_code_encrypted,
		&phone_number_verification_code_issued_at,
		&address_line1,
		&address_line2,
		&address_locality,
		&address_region,
		&address_postal_code,
		&address_country,
		&password_hash,
		&otp_secret,
		&otp_enabled,
		&forgot_password_code_encrypted,
		&forgot_password_code_issued_at,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan user")
	}

	user := &entitiesv2.User{
		Id:                                   id,
		CreatedAt:                            created_at,
		UpdatedAt:                            updated_at,
		Enabled:                              enabled,
		Subject:                              subject,
		Username:                             username,
		GivenName:                            given_name,
		MiddleName:                           middle_name,
		FamilyName:                           family_name,
		Nickname:                             nickname,
		Website:                              website,
		Gender:                               gender,
		Email:                                email,
		EmailVerified:                        email_verified,
		EmailVerificationCodeEncrypted:       email_verification_code_encrypted,
		EmailVerificationCodeIssuedAt:        email_verification_code_issued_at,
		ZoneInfoCountryName:                  zone_info_country_name,
		ZoneInfo:                             zone_info,
		Locale:                               locale,
		BirthDate:                            birth_date,
		PhoneNumber:                          phone_number,
		PhoneNumberVerified:                  phone_number_verified,
		PhoneNumberVerificationCodeEncrypted: phone_number_verification_code_encrypted,
		PhoneNumberVerificationCodeIssuedAt:  phone_number_verification_code_issued_at,
		AddressLine1:                         address_line1,
		AddressLine2:                         address_line2,
		AddressLocality:                      address_locality,
		AddressRegion:                        address_region,
		AddressPostalCode:                    address_postal_code,
		AddressCountry:                       address_country,
		PasswordHash:                         password_hash,
		OTPSecret:                            otp_secret,
		OTPEnabled:                           otp_enabled,
		ForgotPasswordCodeEncrypted:          forgot_password_code_encrypted,
		ForgotPasswordCodeIssuedAt:           forgot_password_code_issued_at,
	}

	return user, nil
}
