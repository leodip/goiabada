package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 2 for the user family (#350).
//
// The console used to decode api.UserResponse and rebuild a models.User from it, so a json tag
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

	return NewAuthServerClient(server.URL), func() (string, string) { return gotPath, gotAuthorization }
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

// A user attribute takes the same path and has the same exposure: four of its five fields are what
// the attributes page renders, and the fifth decides which token the value reaches.
func TestAuthServerClient_GetUserAttributesByUserIdDecodesTheAttributeShape(t *testing.T) {
	client, recorded := serves(t, `{"attributes":[{"id":7,"createdAt":"2026-01-02T03:04:05Z","updatedAt":null,`+
		`"key":"department","value":"engineering","includeInIdToken":true,"includeInAccessToken":false,"userId":42}]}`)

	attributes, err := client.GetUserAttributesByUserId(context.Background(), "an-access-token", 42)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/42/attributes", gotPath)

	require.Len(t, attributes, 1)
	assert.Equal(t, int64(7), attributes[0].Id)
	assert.Equal(t, "department", attributes[0].Key)
	assert.Equal(t, "engineering", attributes[0].Value)
	assert.True(t, attributes[0].IncludeInIdToken)
	assert.False(t, attributes[0].IncludeInAccessToken)
	assert.Equal(t, int64(42), attributes[0].UserId)
	require.NotNil(t, attributes[0].CreatedAt)
	assert.Equal(t, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), attributes[0].CreatedAt.UTC())
}

// The consents page reads the client's identifier and description off the consent itself, where it
// used to read them off a models.Client the console assembled beside it, and it dates each row from
// grantedAt. All three are flat keys on the wire and none of them is the consent's own id, so a
// decode that filled the id and nothing else would render a table of blank rows.
func TestAuthServerClient_GetUserConsentsDecodesTheClientColumnsAndTheGrant(t *testing.T) {
	client, recorded := serves(t, `{"consents":[{"id":5,"clientId":3,"userId":42,"scope":"openid profile",`+
		`"grantedAt":"2026-02-03T04:05:06Z","clientIdentifier":"web-app","clientDescription":"The web app"},`+
		`{"id":6,"clientId":4,"userId":42,"scope":"openid","grantedAt":null,"clientIdentifier":"other"}]}`)

	consents, err := client.GetUserConsents(context.Background(), "an-access-token", 42)
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/users/42/consents", gotPath)

	require.Len(t, consents, 2)
	assert.Equal(t, int64(5), consents[0].Id)
	assert.Equal(t, "openid profile", consents[0].Scope)
	assert.Equal(t, "web-app", consents[0].ClientIdentifier)
	assert.Equal(t, "The web app", consents[0].ClientDescription)
	require.NotNil(t, consents[0].GrantedAt)
	assert.Equal(t, time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC), consents[0].GrantedAt.UTC())

	assert.Nil(t, consents[1].GrantedAt, "an absent grant must reach the handler as nil rather than as a zero time")
}
