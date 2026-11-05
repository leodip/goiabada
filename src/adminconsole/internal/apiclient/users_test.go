package apiclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 2 for the user family (#350).
//
// The console used to decode api.UserResponse and rebuild a record.User from it, so a json tag
// renamed in core/api emptied one field of that rebuild and every page below it. It now hands the
// decoded response to the handlers and the templates read the response's own field names, which
// removes the rebuild and leaves exactly one place where a renamed tag is still invisible: the
// decode itself. So the body here is written as literal bytes rather than marshalled from the
// struct, because a body produced by the same tags it is meant to check proves nothing.
//
// The three dates are the other half. They were sql.NullTime on the way back and are *time.Time
// now, which is the difference between a template printing "01 Jan 0001" and printing nothing, so
// a present one and an absent one are both read.
const userBodyFields = `
	"id": 42,
	"createdAt": "2026-01-02T03:04:05Z",
	"updatedAt": null,
	"enabled": true,
	"subject": "3f2a1c4e-5b6d-4e8f-9a0b-1c2d3e4f5a6b",
	"username": "jdoe",
	"givenName": "Jane",
	"middleName": "Q",
	"familyName": "Doe",
	"nickname": "jd",
	"website": "https://example.com",
	"gender": "female",
	"email": "jane@example.com",
	"emailVerified": true,
	"zoneInfoCountryName": "Brazil",
	"zoneInfo": "America/Sao_Paulo",
	"locale": "pt-BR",
	"birthDate": "1990-05-15T00:00:00Z",
	"phoneNumberCountryUniqueId": "BRA_0",
	"phoneNumberCountryCallingCode": "+55",
	"phoneNumber": "999999999",
	"phoneNumberVerified": true,
	"addressLine1": "Rua A, 1",
	"addressLine2": "apto 2",
	"addressLocality": "Sao Paulo",
	"addressRegion": "SP",
	"addressPostalCode": "01000-000",
	"addressCountry": "BRA",
	"otpEnabled": true`

func serves(t *testing.T, body string) (*AuthServerClient, func() (string, string)) {
	t.Helper()
	return servesStatus(t, http.StatusOK, body)
}

// servesStatus is serves with the status named, for the creating methods: each of those treats
// anything but 201 as an API error, so a 200 here would exercise the error path instead of the
// decode the case is about.
func servesStatus(t *testing.T, status int, body string) (*AuthServerClient, func() (string, string)) {
	t.Helper()

	var gotPath, gotAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return NewAuthServerClient(server.URL, nil, nil), func() (string, string) { return gotPath, gotAuthorization }
}

func TestAuthServerClient_GetUserByIdDecodesEveryFieldTheConsoleBinds(t *testing.T) {
	client, recorded := serves(t, `{"user":{`+userBodyFields+`}}`)

	user, err := client.GetUserById(context.Background(), "an-access-token", 42)
	require.NoError(t, err)
	require.NotNil(t, user)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/admin/users/42", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	assert.Equal(t, int64(42), user.Id)
	assert.True(t, user.Enabled)
	assert.Equal(t, "3f2a1c4e-5b6d-4e8f-9a0b-1c2d3e4f5a6b", user.Subject)
	assert.Equal(t, "jdoe", user.Username)
	assert.Equal(t, "Jane", user.GivenName)
	assert.Equal(t, "Q", user.MiddleName)
	assert.Equal(t, "Doe", user.FamilyName)
	assert.Equal(t, "jd", user.Nickname)
	assert.Equal(t, "https://example.com", user.Website)
	assert.Equal(t, "female", user.Gender)
	assert.Equal(t, "jane@example.com", user.Email)
	assert.True(t, user.EmailVerified)
	assert.Equal(t, "Brazil", user.ZoneInfoCountryName)
	assert.Equal(t, "America/Sao_Paulo", user.ZoneInfo)
	assert.Equal(t, "pt-BR", user.Locale)
	assert.Equal(t, "BRA_0", user.PhoneNumberCountryUniqueId)
	assert.Equal(t, "+55", user.PhoneNumberCountryCallingCode)
	assert.Equal(t, "999999999", user.PhoneNumber)
	assert.True(t, user.PhoneNumberVerified)
	assert.Equal(t, "Rua A, 1", user.AddressLine1)
	assert.Equal(t, "apto 2", user.AddressLine2)
	assert.Equal(t, "Sao Paulo", user.AddressLocality)
	assert.Equal(t, "SP", user.AddressRegion)
	assert.Equal(t, "01000-000", user.AddressPostalCode)
	assert.Equal(t, "BRA", user.AddressCountry)
	assert.True(t, user.OTPEnabled)

	require.NotNil(t, user.CreatedAt, "a present timestamp must arrive as a time, not as nil")
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), user.CreatedAt.UTC())
	require.NotNil(t, user.BirthDate)
	assert.Equal(t, time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC), user.BirthDate.UTC())
	assert.Nil(t, user.UpdatedAt, "a null timestamp must arrive as nil, which is what the page tests for")
}

// The paginated list is the console's other decode of this shape, and it feeds the three admin
// lists' PageResult directly rather than one row at a time.
func TestAuthServerClient_SearchUsersPaginatedReturnsThePagesUsersAndItsTotal(t *testing.T) {
	client, recorded := serves(t, `{"users":[{`+userBodyFields+`},{"id":43,"email":"other@example.com"}],"total":73}`)

	users, total, err := client.SearchUsersPaginated(context.Background(), "an-access-token", "jane", 4, 10)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/search", gotPath)

	assert.Equal(t, 73, total, "the total drives the paginator, not the length of this page")
	require.Len(t, users, 2)
	assert.Equal(t, int64(42), users[0].Id)
	assert.Equal(t, "jane@example.com", users[0].Email)
	assert.Equal(t, int64(43), users[1].Id)
	assert.Equal(t, "other@example.com", users[1].Email)
}

// The user's export reaches the browser as the auth server sent it (#781 decision 5): the console
// asks for gzip and hands back the compressed bytes and the headers that describe them, never
// decoding them, so the browser unpacks the file it saves.
func TestAuthServerClient_GetUserExportHandsBackTheCompressedBytesAndTheirHeaders(t *testing.T) {
	// Not a real gzip stream: bytes a decoding client could not have passed through unchanged.
	compressed := []byte{0x1f, 0x8b, 0x08, 0x00, 'n', 'o', 't', '-', 'd', 'e', 'c', 'o', 'd', 'e', 'd'}
	var gotPath, gotAuthorization, gotAcceptEncoding string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuthorization = r.Header.Get("Authorization")
		gotAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Disposition", `attachment; filename="user-42-2026-11-05.json"`)
		w.Header().Set("Content-Length", "15")
		_, _ = w.Write(compressed)
	}))
	t.Cleanup(server.Close)
	client := NewAuthServerClient(server.URL, nil, nil)

	export, err := client.GetUserExport(context.Background(), "an-access-token", 42)
	require.NoError(t, err)
	defer func() { _ = export.Body.Close() }()
	body, err := io.ReadAll(export.Body)
	require.NoError(t, err)

	assert.Equal(t, "/api/v1/admin/users/42/export", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)
	assert.Equal(t, "gzip", gotAcceptEncoding, "the console asks for the compressed answer")
	assert.Equal(t, compressed, body, "the bytes as they arrived, not decoded")
	assert.Equal(t, "application/json", export.ContentType)
	assert.Equal(t, "gzip", export.ContentEncoding)
	assert.Equal(t, `attachment; filename="user-42-2026-11-05.json"`, export.ContentDisposition)
	assert.Equal(t, "15", export.ContentLength)
}

// An auth server answering plain JSON, which it does for a caller not accepting gzip, is passed
// through plain: no encoding is claimed for bytes that carry none.
func TestAuthServerClient_GetUserExportClaimsNoEncodingForAPlainAnswer(t *testing.T) {
	client, _ := serves(t, `{"formatVersion":1}`)

	export, err := client.GetUserExport(context.Background(), "an-access-token", 42)
	require.NoError(t, err)
	defer func() { _ = export.Body.Close() }()
	body, err := io.ReadAll(export.Body)
	require.NoError(t, err)

	assert.Equal(t, `{"formatVersion":1}`, string(body))
	assert.Empty(t, export.ContentEncoding)
	assert.Empty(t, export.ContentDisposition)
}

// The document is never read under the 1 MiB ceiling every other answer is (decision 5): 30,000
// audit events are 1.2 MB gzipped. It is read by the caller, after the method returned, so the
// call's deadline must outlive the return.
func TestAuthServerClient_GetUserExportPassesAnAnswerPastTheCeilingWhole(t *testing.T) {
	large := strings.Repeat("x", maxAPIResponseBytes+4096)
	client, _ := serves(t, large)

	export, err := client.GetUserExport(context.Background(), "an-access-token", 42)
	require.NoError(t, err)
	defer func() { _ = export.Body.Close() }()
	body, err := io.ReadAll(export.Body)
	require.NoError(t, err)

	assert.Len(t, body, maxAPIResponseBytes+4096)
}

// The call has five minutes, the auth server's own bound on writing the answer, instead of the ten
// seconds every other call has (decision 5).
func TestAuthServerClient_GetUserExportHasFiveMinutes(t *testing.T) {
	client := NewAuthServerClient("http://auth.example.com", nil, nil)
	var deadline time.Time
	var hasDeadline bool
	client.httpClient = &http.Client{
		Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			deadline, hasDeadline = r.Context().Deadline()
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Request:    r,
			}, nil
		}),
	}

	started := time.Now()
	export, err := client.GetUserExport(context.Background(), "an-access-token", 42)
	require.NoError(t, err)
	_ = export.Body.Close()

	require.True(t, hasDeadline, "the call carries a deadline")
	assert.WithinDuration(t, started.Add(5*time.Minute), deadline, 5*time.Second)
}
