package userexport

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The secrets seeded on the user below, none of which the document may carry (#781: "Nothing
// secret is in it").
const (
	seededPasswordHash       = "$2a$10$seededpasswordhashseededpasswordhashseededpasswo"
	seededOTPSecret          = "seeded-otp-secret-ciphertext"
	seededEmailCode          = "seeded-email-verification-code-ciphertext"
	seededForgotPasswordCode = "seeded-forgot-password-code-ciphertext"
	seededForgotPasswordHash = "5eededf0e9a55a0bdc0dehashofthereset0000000000000000000000000000"
)

// exportedUser is a user with every profile field set, its secrets among them.
func exportedUser() *record.User {
	at := func(s string) sql.NullTime {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			panic(err)
		}
		return sql.NullTime{Time: t, Valid: true}
	}
	return &record.User{
		Id:                             42,
		CreatedAt:                      at("2025-01-02T03:04:05Z"),
		UpdatedAt:                      at("2026-10-01T12:00:00Z"),
		Enabled:                        true,
		Subject:                        "7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b",
		Username:                       "ana",
		GivenName:                      "Ana",
		MiddleName:                     "Maria",
		FamilyName:                     "Silva",
		Nickname:                       "Aninha",
		Website:                        "https://ana.example.com",
		Gender:                         "female",
		Email:                          "ana.silva@example.com",
		EmailVerified:                  true,
		EmailVerificationCodeEncrypted: []byte(seededEmailCode),
		EmailVerificationCodeIssuedAt:  at("2026-10-01T12:00:00Z"),
		ZoneInfoCountryName:            "Brazil",
		ZoneInfo:                       "America/Sao_Paulo",
		Locale:                         "pt-BR",
		PageLanguage:                   "pt",
		BirthDate:                      at("1990-05-17T00:00:00Z"),
		PhoneNumberCountryUniqueId:     "BRA_0",
		PhoneNumberCountryCallingCode:  "+55",
		PhoneNumber:                    "11 91234-5678",
		PhoneNumberVerified:            true,
		AddressLine1:                   "Rua das Flores 10",
		AddressLine2:                   "Apto 3",
		AddressLocality:                "São Paulo",
		AddressRegion:                  "SP",
		AddressPostalCode:              "01000-000",
		AddressCountry:                 "Brazil",
		PasswordHash:                   seededPasswordHash,
		OTPSecretEncrypted:             []byte(seededOTPSecret),
		OTPEnabled:                     true,
		ForgotPasswordCodeEncrypted:    []byte(seededForgotPasswordCode),
		ForgotPasswordCodeIssuedAt:     at("2026-10-02T12:00:00Z"),
		ForgotPasswordCodeHash:         seededForgotPasswordHash,
		AuthStateGeneration:            3,
		LastOTPStep:                    59000000,
	}
}

// The document for the user above, written out by hand from #781 decision 3: the
// wrapper, the identifiers (the digest is `printf '%s' ana.silva@example.com | sha256sum`), the
// user as GET /api/v1/admin/users/{id} answers it, and the parts the later slices fill, empty.
const exportedUserDocument = `{
	"formatVersion": 1,
	"exportedAt": "2026-11-05T09:30:00Z",
	"issuer": "https://auth.example.com",
	"identifiers": {
		"id": 42,
		"subject": "7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b",
		"email": "ana.silva@example.com",
		"emailDigest": "7bda2560ce1bf126ff5df73ed84b6c9f8dd6064e33fc273eb05b7761e31c2b86"
	},
	"user": {
		"id": 42,
		"createdAt": "2025-01-02T03:04:05Z",
		"updatedAt": "2026-10-01T12:00:00Z",
		"enabled": true,
		"subject": "7b0f2c4e-9d61-4a8e-b2c3-5f1e0a9d8c7b",
		"username": "ana",
		"givenName": "Ana",
		"middleName": "Maria",
		"familyName": "Silva",
		"nickname": "Aninha",
		"website": "https://ana.example.com",
		"gender": "female",
		"email": "ana.silva@example.com",
		"emailVerified": true,
		"zoneInfoCountryName": "Brazil",
		"zoneInfo": "America/Sao_Paulo",
		"locale": "pt-BR",
		"pageLanguage": "pt",
		"birthDate": "1990-05-17T00:00:00Z",
		"phoneNumberCountryUniqueId": "BRA_0",
		"phoneNumberCountryCallingCode": "+55",
		"phoneNumber": "11 91234-5678",
		"phoneNumberVerified": true,
		"addressLine1": "Rua das Flores 10",
		"addressLine2": "Apto 3",
		"addressLocality": "São Paulo",
		"addressRegion": "SP",
		"addressPostalCode": "01000-000",
		"addressCountry": "Brazil",
		"otpEnabled": true,
		"otpAuthenticatorDisabled": false
	},
	"attributes": [],
	"groups": [],
	"permissions": [],
	"consents": [],
	"sessions": [],
	"refreshTokens": [],
	"legalDocumentAcceptances": [],
	"profilePicture": null,
	"auditEvents": []
}`

func TestBuild_TheWrapperTheIdentifiersAndTheUser(t *testing.T) {
	exportedAt := time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC)

	document := Build(exportedUser(), Parts{}, "https://auth.example.com", exportedAt)

	encoded, err := json.Marshal(document)
	require.NoError(t, err)
	assert.JSONEq(t, exportedUserDocument, string(encoded))
}

// exportedAt is an instant: one taken in another zone is written in UTC, as the file name's date
// is (decision 6).
func TestBuild_ExportedAtIsWrittenInUTC(t *testing.T) {
	saoPaulo := time.FixedZone("BRT", -3*60*60)

	document := Build(exportedUser(), Parts{}, "https://auth.example.com", time.Date(2026, 11, 5, 22, 15, 0, 0, saoPaulo))

	encoded, err := json.Marshal(document)
	require.NoError(t, err)
	var parts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &parts))
	assert.JSONEq(t, `"2026-11-06T01:15:00Z"`, string(parts["exportedAt"]))
}

// A user with no birth date or timestamps has those as null, as GET /api/v1/admin/users/{id}
// answers them, and an empty list is [] rather than null, so a reader never tells "none" from
// "not read".
func TestBuild_AnEmptyListIsNeverNull(t *testing.T) {
	document := Build(&record.User{Id: 7, Subject: "s", Email: "e@example.com"}, Parts{}, "https://auth.example.com",
		time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))

	encoded, err := json.Marshal(document)
	require.NoError(t, err)
	var parts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &parts))
	for _, list := range []string{"attributes", "groups", "permissions", "consents", "sessions",
		"refreshTokens", "legalDocumentAcceptances", "auditEvents"} {
		assert.JSONEq(t, `[]`, string(parts[list]), list)
	}
	assert.JSONEq(t, `null`, string(parts["profilePicture"]))

	var user map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(parts["user"], &user))
	for _, field := range []string{"createdAt", "updatedAt", "birthDate"} {
		assert.JSONEq(t, `null`, string(user[field]), field)
	}
}

// Nothing secret is in the document: no password hash, two-factor secret, pending code or code
// hash, and no field that would carry one.
func TestBuild_CarriesNoSecret(t *testing.T) {
	document := Build(exportedUser(), Parts{}, "https://auth.example.com", time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC))

	encoded, err := json.Marshal(document)
	require.NoError(t, err)
	body := string(encoded)
	for _, secret := range []string{seededPasswordHash, seededOTPSecret, seededEmailCode,
		seededForgotPasswordCode, seededForgotPasswordHash} {
		assert.NotContains(t, body, secret)
	}
	lowered := strings.ToLower(body)
	for _, key := range []string{"password", "otpsecret", "verificationcode", "forgotpassword", "authstategeneration", "lastotpstep"} {
		assert.NotContains(t, lowered, key)
	}
}

// The file is named user-<id>-<date>.json, the date being exportedAt's in UTC (decision 6).
func TestFileName_IsTheUserIdAndTheUTCDate(t *testing.T) {
	saoPaulo := time.FixedZone("BRT", -3*60*60)
	for _, c := range []struct {
		name       string
		userId     int64
		exportedAt time.Time
		want       string
	}{
		{"the example in #781", 42, time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC), "user-42-2026-11-05.json"},
		{"late in the day west of UTC is the next UTC day", 7, time.Date(2026, 12, 31, 22, 0, 0, 0, saoPaulo), "user-7-2027-01-01.json"},
		{"a single-digit month and day", 1, time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC), "user-1-2026-03-04.json"},
	} {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, FileName(c.userId, c.exportedAt))
		})
	}
}
