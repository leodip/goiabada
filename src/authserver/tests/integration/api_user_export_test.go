package integration

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GET /api/v1/admin/users/{id}/export (#781): everything the auth server holds about one user, as
// one JSON document named for download. It answers only a token that reads both the users and the
// audit log (decision 1), is gzip-compressed for a caller that accepts it and never cached
// (decision 5), is named user-<id>-<date>.json (decision 6), and writes exported_user_data naming
// the user and who exported them (decision 8).

func userExportPath(id any) string {
	return fmt.Sprintf("/api/v1/admin/users/%v/export", id)
}

// exportAnswer is one export's answer: the status, the headers, and the body as it came off the
// wire, before any decompression.
type exportAnswer struct {
	status int
	header http.Header
	raw    []byte
}

// getUserExport asks for the export with the Accept-Encoding given, empty for none. The transport
// is told not to ask for gzip itself, so what arrives is what the server sent.
func getUserExport(t *testing.T, accessToken string, id any, acceptEncoding string) exportAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, appConfig.AuthServer.BaseURL+userExportPath(id), nil)
	require.NoError(t, err)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if acceptEncoding != "" {
		req.Header.Set("Accept-Encoding", acceptEncoding)
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		DisableCompression: true,
	}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return exportAnswer{status: resp.StatusCode, header: resp.Header, raw: raw}
}

// document is the answer's JSON, unpacked from gzip when the answer says it is gzip.
func (a exportAnswer) document(t *testing.T) []byte {
	t.Helper()
	if a.header.Get("Content-Encoding") != "gzip" {
		return a.raw
	}
	reader, err := gzip.NewReader(bytes.NewReader(a.raw))
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	return plain
}

// The secrets seeded on the exported user, none of which the answer may carry.
type exportSecrets struct {
	password, passwordHash, otpSecret, emailCode, resetCodeHash, recoveryCodeHash string
}

// newExportedUser is a user with a profile, an address, a phone and every secret the users table
// holds, plus a set of recovery codes.
func newExportedUser(t *testing.T) (*record.User, exportSecrets) {
	t.Helper()
	ctx := context.Background()
	secrets := exportSecrets{
		password:         fake.Password(14),
		otpSecret:        "EXPORTOTPSEED" + fake.LetterN(12),
		emailCode:        "export-email-code-" + fake.LetterN(8),
		resetCodeHash:    hashutil.HashString("export-reset-code-" + fake.LetterN(8)),
		recoveryCodeHash: hashutil.HashString("export-recovery-code-" + fake.LetterN(8)),
	}
	var err error
	secrets.passwordHash, err = passwordhash.Hash(secrets.password)
	require.NoError(t, err)
	otpSealed, err := dataCipher.Encrypt(secrets.otpSecret)
	require.NoError(t, err)
	emailCodeSealed, err := dataCipher.Encrypt(secrets.emailCode)
	require.NoError(t, err)

	user := &record.User{
		Enabled:                        true,
		Subject:                        fake.UUID(),
		Username:                       "export" + strings.ToLower(fake.LetterN(8)),
		GivenName:                      "Ana",
		MiddleName:                     "Maria",
		FamilyName:                     "Silva",
		Nickname:                       "Aninha",
		Website:                        "https://ana.example.com",
		Gender:                         "female",
		Email:                          "export-" + strings.ToLower(fake.LetterN(10)) + "@example.com",
		EmailVerified:                  true,
		EmailVerificationCodeEncrypted: emailCodeSealed,
		EmailVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now().UTC(), Valid: true},
		ZoneInfoCountryName:            "Brazil",
		ZoneInfo:                       "America/Sao_Paulo",
		Locale:                         "pt-BR",
		BirthDate:                      sql.NullTime{Time: time.Date(1990, 5, 17, 0, 0, 0, 0, time.UTC), Valid: true},
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
		PasswordHash:                   secrets.passwordHash,
		OTPSecretEncrypted:             otpSealed,
		OTPEnabled:                     true,
		ForgotPasswordCodeHash:         secrets.resetCodeHash,
	}
	require.NoError(t, database.CreateUser(ctx, nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		return database.ReplaceUserRecoveryCodes(ctx, tx, user.Id, []string{secrets.recoveryCodeHash})
	}))

	stored, err := database.GetUserById(ctx, nil, user.Id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	return stored, secrets
}

// expectedExport is the document for the user, exportedAt aside, written out by hand from decision
// 3: the wrapper, the identifiers, the user as GET /api/v1/admin/users/{id} answers it, and the
// parts the later slices fill, empty.
func expectedExport(user *record.User, issuer string) string {
	return fmt.Sprintf(`{
		"formatVersion": 1,
		"issuer": %q,
		"identifiers": {"id": %d, "subject": %q, "email": %q, "emailDigest": %q},
		"user": {
			"id": %d, "createdAt": %s, "updatedAt": %s, "enabled": true, "subject": %q,
			"username": %q, "givenName": "Ana", "middleName": "Maria", "familyName": "Silva",
			"nickname": "Aninha", "website": "https://ana.example.com", "gender": "female",
			"email": %q, "emailVerified": true, "zoneInfoCountryName": "Brazil",
			"zoneInfo": "America/Sao_Paulo", "locale": "pt-BR", "pageLanguage": "",
			"birthDate": %s, "phoneNumberCountryUniqueId": "BRA_0",
			"phoneNumberCountryCallingCode": "+55", "phoneNumber": "11 91234-5678",
			"phoneNumberVerified": true, "addressLine1": "Rua das Flores 10", "addressLine2": "Apto 3",
			"addressLocality": "São Paulo", "addressRegion": "SP", "addressPostalCode": "01000-000",
			"addressCountry": "Brazil", "otpEnabled": true, "otpAuthenticatorDisabled": false
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
	}`, issuer,
		user.Id, user.Subject, user.Email, hashutil.HashString(user.Email),
		user.Id, jsonTime(user.CreatedAt), jsonTime(user.UpdatedAt), user.Subject,
		user.Username, user.Email, jsonTime(user.BirthDate))
}

// jsonTime is a stored time as the admin API writes it: the instant, or null when none is stored.
// The values are the row read back, since each engine keeps its own precision.
func jsonTime(stored sql.NullTime) string {
	if !stored.Valid {
		return "null"
	}
	return `"` + stored.Time.Format(time.RFC3339Nano) + `"`
}

// storedIssuer is the issuer in the settings row, which the document names.
func storedIssuer(t *testing.T) string {
	t.Helper()
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	require.NotNil(t, settings)
	return settings.Issuer
}

// assertTheExport holds a 200 to the user's document, its headers and exportedAt, and answers the
// document's exportedAt.
func assertTheExport(t *testing.T, answer exportAnswer, user *record.User, before time.Time) time.Time {
	t.Helper()
	require.Equal(t, http.StatusOK, answer.status, "%s", answer.raw)
	assert.Equal(t, "application/json", answer.header.Get("Content-Type"))
	assert.Equal(t, "no-store", answer.header.Get("Cache-Control"), "the export is never cached")
	assert.Contains(t, answer.header.Values("Vary"), "Accept-Encoding")

	var parts map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(answer.document(t), &parts))
	var exportedAt time.Time
	require.NoError(t, json.Unmarshal(parts["exportedAt"], &exportedAt))
	assert.WithinDuration(t, before, exportedAt, time.Minute)
	assert.False(t, exportedAt.Before(before.Truncate(time.Second)), "exportedAt %v is before the request", exportedAt)
	delete(parts, "exportedAt")
	rest, err := json.Marshal(parts)
	require.NoError(t, err)
	assert.JSONEq(t, expectedExport(user, storedIssuer(t)), string(rest))

	assert.Equal(t, fmt.Sprintf(`attachment; filename="user-%d-%s.json"`, user.Id, exportedAt.UTC().Format("2006-01-02")),
		answer.header.Get("Content-Disposition"))
	return exportedAt
}

func TestAPIUserExport_AnswersTheUsersDocument(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	user, _ := newExportedUser(t)
	before := time.Now().UTC()

	answer := getUserExport(t, adminToken, user.Id, "")

	assertTheExport(t, answer, user, before)
	assert.Empty(t, answer.header.Get("Content-Encoding"), "a caller that names no encoding gets plain JSON")
}

// The 200 is gzip for a caller that accepts gzip, and plain JSON for one that refuses it.
func TestAPIUserExport_GzipForACallerThatAcceptsIt(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	user, _ := newExportedUser(t)

	for _, c := range []struct {
		acceptEncoding string
		gzip           bool
	}{
		{"gzip", true},
		{"gzip, deflate, br", true},
		{"br;q=1, gzip;q=0.5", true},
		{"gzip;q=0", false},
		{"identity", false},
	} {
		t.Run(c.acceptEncoding, func(t *testing.T) {
			before := time.Now().UTC()

			answer := getUserExport(t, adminToken, user.Id, c.acceptEncoding)

			if c.gzip {
				assert.Equal(t, "gzip", answer.header.Get("Content-Encoding"))
				assert.Equal(t, []byte{0x1f, 0x8b}, answer.raw[:2], "the body on the wire is gzip")
			} else {
				assert.Empty(t, answer.header.Get("Content-Encoding"))
			}
			assertTheExport(t, answer, user, before)
		})
	}
}

// Nothing secret is in the document: the raw body holds none of the secrets seeded on the user,
// and no field that would carry one.
func TestAPIUserExport_HoldsNoSecret(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	user, secrets := newExportedUser(t)

	answer := getUserExport(t, adminToken, user.Id, "")

	require.Equal(t, http.StatusOK, answer.status)
	body := string(answer.raw)
	for name, secret := range map[string]string{
		"the password":                  secrets.password,
		"the password hash":             secrets.passwordHash,
		"the OTP secret":                secrets.otpSecret,
		"the email verification code":   secrets.emailCode,
		"the password reset code hash":  secrets.resetCodeHash,
		"the recovery code's hash":      secrets.recoveryCodeHash,
		"the sealed OTP secret, base64": base64.StdEncoding.EncodeToString(user.OTPSecretEncrypted),
	} {
		assert.NotContains(t, body, secret, name)
	}
	lowered := strings.ToLower(body)
	for _, key := range []string{"password", "otpsecret", "recoverycode", "verificationcode"} {
		assert.NotContains(t, lowered, key)
	}
}

// The export answers only a token that reads both the users and the audit log: admin-read, manage,
// or manage-users together with manage-settings. manage-users alone is refused as a token with none
// of a route's scopes is (decision 1).
func TestAPIUserExport_TheScopeRule(t *testing.T) {
	user, _ := newExportedUser(t)

	for _, c := range []struct {
		permission string
		status     int
	}{
		{builtin.AdminReadPermissionIdentifier, http.StatusOK},
		{builtin.ManagePermissionIdentifier, http.StatusOK},
		{builtin.ManageUsersPermissionIdentifier, http.StatusForbidden},
		{builtin.ManageSettingsPermissionIdentifier, http.StatusForbidden},
		{builtin.ManageClientsPermissionIdentifier, http.StatusForbidden},
	} {
		t.Run("a client holding "+c.permission, func(t *testing.T) {
			token, client := createClientWithGranularScope(t, c.permission)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

			answer := getUserExport(t, token, user.Id, "")

			assert.Equal(t, c.status, answer.status, "%s", answer.raw)
			if c.status == http.StatusForbidden {
				assertExportErrorCode(t, answer, "INSUFFICIENT_SCOPE")
			}
		})
	}

	t.Run("a user holding manage-users and manage-settings", func(t *testing.T) {
		token, _ := createUserAccessTokenWithScope(t, "openid authserver:manage-users authserver:manage-settings")

		answer := getUserExport(t, token, user.Id, "")

		assert.Equal(t, http.StatusOK, answer.status, "%s", answer.raw)
	})

	t.Run("a user holding manage-users alone", func(t *testing.T) {
		token, _ := createUserAccessTokenWithScope(t, "openid authserver:manage-users")

		answer := getUserExport(t, token, user.Id, "")

		assert.Equal(t, http.StatusForbidden, answer.status, "%s", answer.raw)
		assertExportErrorCode(t, answer, "INSUFFICIENT_SCOPE")
	})

	t.Run("no token", func(t *testing.T) {
		answer := getUserExport(t, "", user.Id, "")

		assert.Equal(t, http.StatusUnauthorized, answer.status)
	})
}

func assertExportErrorCode(t *testing.T, answer exportAnswer, code string) {
	t.Helper()
	assert.Empty(t, answer.header.Get("Content-Encoding"), "an error answer is never compressed")
	assert.Empty(t, answer.header.Get("Content-Disposition"))
	var body map[string]any
	require.NoError(t, json.Unmarshal(answer.raw, &body), "%s", answer.raw)
	assert.Equal(t, code, body["error_code"])
}

// An id that names no user is 404 and a malformed one 400, as on every route on /users/{id}, each
// uncompressed whatever the caller accepts.
func TestAPIUserExport_Refusals(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)

	answer := getUserExport(t, adminToken, 999999999, "gzip")
	assert.Equal(t, http.StatusNotFound, answer.status)
	assertExportErrorCode(t, answer, "NOT_FOUND")

	answer = getUserExport(t, adminToken, "abc", "gzip")
	assert.Equal(t, http.StatusBadRequest, answer.status)
	assertExportErrorCode(t, answer, "VALIDATION_ERROR")
}

// exportEvents is the exported_user_data rows about the user, oldest first.
func exportEvents(t *testing.T, userId int64) []record.AuditLog {
	t.Helper()
	rows, err := database.GetAuditLogsByUserId(context.Background(), nil, userId)
	require.NoError(t, err)
	var events []record.AuditLog
	for _, row := range rows {
		if row.AuditEvent == audit.EventExportedUserData {
			events = append(events, row)
		}
	}
	return events
}

// Every export writes exported_user_data, naming the user exported in user_id and who exported
// them in logged_in_user, so a user's token fills both user columns and the audit log's user filter
// lists the entry under both people (decision 8).
func TestAPIUserExport_RecordsTheExport(t *testing.T) {
	requireDatabaseAuditLogs(t)
	user, _ := newExportedUser(t)
	token, administrator := createUserAccessTokenWithScope(t, "openid authserver:manage-users authserver:manage-settings")

	answer := getUserExport(t, token, user.Id, "gzip")
	require.Equal(t, http.StatusOK, answer.status, "%s", answer.raw)

	var events []record.AuditLog
	require.Eventually(t, func() bool {
		events = exportEvents(t, user.Id)
		return len(events) == 1
	}, afterResponseWait, 100*time.Millisecond, "one exported_user_data about the user")
	event := events[0]
	assert.Equal(t, "exported_user_data", event.AuditEvent, "the stored event name")
	assert.Equal(t, sql.NullInt64{Int64: user.Id, Valid: true}, event.UserId)
	assert.Equal(t, sql.NullInt64{Int64: administrator.Id, Valid: true}, event.LoggedInUserId)
	assert.JSONEq(t, fmt.Sprintf(`{"user_id": %d, "logged_in_user": %q}`, user.Id, administrator.Subject), event.Details)

	byAdministrator := exportEvents(t, administrator.Id)
	require.Len(t, byAdministrator, 1, "the entry is listed under the administrator too")
	assert.Equal(t, event.Id, byAdministrator[0].Id)
}

// A refused export or one of a user that does not exist writes nothing: the data never left.
func TestAPIUserExport_ARefusedExportRecordsNothing(t *testing.T) {
	requireDatabaseAuditLogs(t)
	user, _ := newExportedUser(t)
	token, administrator := createUserAccessTokenWithScope(t, "openid authserver:manage-users")

	answer := getUserExport(t, token, user.Id, "")
	require.Equal(t, http.StatusForbidden, answer.status)

	// A later export's event is what bounds the wait: once it is stored, the refused one would be too.
	adminToken, _ := createAdminClientWithToken(t)
	require.Equal(t, http.StatusOK, getUserExport(t, adminToken, user.Id, "").status)
	require.Eventually(t, func() bool { return len(exportEvents(t, user.Id)) >= 1 }, afterResponseWait, 100*time.Millisecond)

	assert.Len(t, exportEvents(t, user.Id), 1, "only the admitted export is recorded")
	assert.Empty(t, exportEvents(t, administrator.Id), "nothing names the refused caller")
}
