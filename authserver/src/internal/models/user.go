package models

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type User struct {
	Id                                   int64           `db:"id" fieldtag:"pk"`
	CreatedAt                            sql.NullTime    `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt                            sql.NullTime    `db:"updated_at"`
	Enabled                              bool            `db:"enabled"`
	Subject                              uuid.UUID       `db:"subject"`
	Username                             string          `db:"username"`
	GivenName                            string          `db:"given_name"`
	MiddleName                           string          `db:"middle_name"`
	FamilyName                           string          `db:"family_name"`
	Nickname                             string          `db:"nickname"`
	Website                              string          `db:"website"`
	Gender                               string          `db:"gender"`
	Email                                string          `db:"email"`
	EmailVerified                        bool            `db:"email_verified"`
	EmailVerificationCodeEncrypted       []byte          `db:"email_verification_code_encrypted"`
	EmailVerificationCodeIssuedAt        sql.NullTime    `db:"email_verification_code_issued_at"`
	ZoneInfoCountryName                  string          `db:"zone_info_country_name"`
	ZoneInfo                             string          `db:"zone_info"`
	Locale                               string          `db:"locale"`
	BirthDate                            sql.NullTime    `db:"birth_date"`
	PhoneNumber                          string          `db:"phone_number"`
	PhoneNumberVerified                  bool            `db:"phone_number_verified"`
	PhoneNumberVerificationCodeEncrypted []byte          `db:"phone_number_verification_code_encrypted"`
	PhoneNumberVerificationCodeIssuedAt  sql.NullTime    `db:"phone_number_verification_code_issued_at"`
	AddressLine1                         string          `db:"address_line1"`
	AddressLine2                         string          `db:"address_line2"`
	AddressLocality                      string          `db:"address_locality"`
	AddressRegion                        string          `db:"address_region"`
	AddressPostalCode                    string          `db:"address_postal_code"`
	AddressCountry                       string          `db:"address_country"`
	PasswordHash                         string          `db:"password_hash"`
	OTPSecret                            string          `db:"otp_secret"`
	OTPEnabled                           bool            `db:"otp_enabled"`
	ForgotPasswordCodeEncrypted          []byte          `db:"forgot_password_code_encrypted"`
	ForgotPasswordCodeIssuedAt           sql.NullTime    `db:"forgot_password_code_issued_at"`
	Groups                               []Group         `db:"-"`
	Permissions                          []Permission    `db:"-"`
	Attributes                           []UserAttribute `db:"-"`
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
