package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Sensitive-field exclusion
//
// models.User carries secrets that must never reach an API client: the password
// hash, the TOTP seed (plaintext and encrypted), and the email / phone /
// forgot-password verification codes. ToUserResponse deliberately omits all of
// them. Nothing else in the codebase enforces that, so the two tests below do:
// one guards the response struct's shape, the other guards the mapper's output.
// =============================================================================

// sensitiveUserFields are the models.User fields that must never be exposed
// through UserResponse, by field name or by JSON key.
var sensitiveUserFields = []string{
	"PasswordHash",
	"OTPSecret",
	"OTPSecretEncrypted",
	"EmailVerificationCodeEncrypted",
	"EmailVerificationCodeIssuedAt",
	"PhoneNumberVerificationCodeEncrypted",
	"PhoneNumberVerificationCodeIssuedAt",
	"ForgotPasswordCodeEncrypted",
	"ForgotPasswordCodeIssuedAt",
	"OtpEnrollmentSecretEncrypted",
	"OtpEnrollmentIssuedAt",
}

// This catches a sensitive field being added to UserResponse even before any
// mapper populates it, which a value-based test alone would miss.
func TestUserResponse_StructHasNoSensitiveFields(t *testing.T) {
	responseType := reflect.TypeOf(UserResponse{})

	for i := 0; i < responseType.NumField(); i++ {
		field := responseType.Field(i)
		jsonKey := strings.Split(field.Tag.Get("json"), ",")[0]

		for _, forbidden := range sensitiveUserFields {
			assert.NotEqual(t, forbidden, field.Name,
				"UserResponse must not expose the sensitive field %q", forbidden)
			assert.NotEqual(t, strings.ToLower(forbidden), strings.ToLower(jsonKey),
				"UserResponse must not expose a JSON key for the sensitive field %q", forbidden)
		}
	}
}

// A user fully populated with recognizable secrets must serialize without any
// trace of them.
func TestToUserResponse_DoesNotLeakSecrets(t *testing.T) {
	otpSecretEncrypted := []byte("SENTINEL-otp-secret-encrypted")
	emailCodeEncrypted := []byte("SENTINEL-email-verification-code")
	phoneCodeEncrypted := []byte("SENTINEL-phone-verification-code")
	forgotCodeEncrypted := []byte("SENTINEL-forgot-password-code")
	otpEnrollmentEncrypted := []byte("SENTINEL-otp-enrollment-key-url")

	user := &models.User{
		Id:                                   1,
		Email:                                "user@example.com",
		PasswordHash:                         "SENTINEL-password-hash",
		OTPSecret:                            "SENTINEL-otp-secret-plaintext",
		OTPSecretEncrypted:                   otpSecretEncrypted,
		EmailVerificationCodeEncrypted:       emailCodeEncrypted,
		EmailVerificationCodeIssuedAt:        sql.NullTime{Time: time.Now(), Valid: true},
		PhoneNumberVerificationCodeEncrypted: phoneCodeEncrypted,
		PhoneNumberVerificationCodeIssuedAt:  sql.NullTime{Time: time.Now(), Valid: true},
		ForgotPasswordCodeEncrypted:          forgotCodeEncrypted,
		ForgotPasswordCodeIssuedAt:           sql.NullTime{Time: time.Now(), Valid: true},
		OtpEnrollmentSecretEncrypted:         otpEnrollmentEncrypted,
		OtpEnrollmentIssuedAt:                sql.NullTime{Time: time.Now(), Valid: true},
	}

	resp := ToUserResponse(user)
	assert.NotNil(t, resp)

	marshalled, err := json.Marshal(resp)
	assert.NoError(t, err)
	payload := string(marshalled)

	// Plaintext secrets.
	assert.NotContains(t, payload, "SENTINEL-password-hash")
	assert.NotContains(t, payload, "SENTINEL-otp-secret-plaintext")

	// Byte-slice secrets would serialize as base64, so check that encoding too.
	for _, secret := range [][]byte{otpSecretEncrypted, emailCodeEncrypted, phoneCodeEncrypted,
		forgotCodeEncrypted, otpEnrollmentEncrypted} {
		assert.NotContains(t, payload, string(secret))
		assert.NotContains(t, payload, base64.StdEncoding.EncodeToString(secret))
	}

	// And no key named after any of them.
	var asMap map[string]any
	assert.NoError(t, json.Unmarshal(marshalled, &asMap))
	for key := range asMap {
		for _, forbidden := range sensitiveUserFields {
			assert.NotEqual(t, strings.ToLower(forbidden), strings.ToLower(key),
				"serialized user must not contain a %q key", forbidden)
		}
	}

	// The non-sensitive data is still there, so this is not passing by mapping nothing.
	assert.Equal(t, "user@example.com", resp.Email)
}

// ToClientResponse intentionally leaves ClientSecret empty; the handler sets it
// only on the detail endpoint after decryption. Combined with `omitempty` that
// means list responses carry no clientSecret key at all.
func TestToClientResponse_DoesNotPopulateClientSecret(t *testing.T) {
	client := &models.Client{
		Id:                    1,
		ClientIdentifier:      "some-client",
		ClientSecretEncrypted: []byte("SENTINEL-client-secret-encrypted"),
		Enabled:               true,
	}

	resp := ToClientResponse(client)
	assert.NotNil(t, resp)
	assert.Equal(t, "", resp.ClientSecret, "the mapper must not populate the client secret")

	marshalled, err := json.Marshal(resp)
	assert.NoError(t, err)
	payload := string(marshalled)

	assert.NotContains(t, payload, "SENTINEL-client-secret-encrypted")
	assert.NotContains(t, payload, base64.StdEncoding.EncodeToString(client.ClientSecretEncrypted))
	assert.NotContains(t, payload, "clientSecret", "omitempty must drop the key when the secret is unset")
}

func TestToClientResponse_EmitsClientSecretOnceHandlerSetsIt(t *testing.T) {
	resp := ToClientResponse(&models.Client{Id: 1, ClientIdentifier: "some-client"})
	resp.ClientSecret = "decrypted-by-handler"

	marshalled, err := json.Marshal(resp)
	assert.NoError(t, err)

	assert.Contains(t, string(marshalled), `"clientSecret":"decrypted-by-handler"`)
}

// ToUser rebuilds a models.User from the DTO, and by design cannot restore the
// secrets the DTO never carried. Pinning that keeps the asymmetry explicit: a
// round-tripped user is not safe to persist over an existing row.
func TestUserResponse_ToUser_LeavesSecretsEmpty(t *testing.T) {
	resp := ToUserResponse(&models.User{
		Id:           1,
		Email:        "user@example.com",
		PasswordHash: "SENTINEL-password-hash",
		OTPSecret:    "SENTINEL-otp-secret-plaintext",
	})

	roundTripped := resp.ToUser()

	assert.Equal(t, "user@example.com", roundTripped.Email)
	assert.Equal(t, "", roundTripped.PasswordHash)
	assert.Equal(t, "", roundTripped.OTPSecret)
	assert.Nil(t, roundTripped.OTPSecretEncrypted)
}

// =============================================================================
// ToUserResponse / ToUser field mapping
// =============================================================================

func TestToUserResponse_MapsAllFields(t *testing.T) {
	createdAt := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	updatedAt := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	birthDate := time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC)
	subject := uuid.New()

	user := &models.User{
		Id:                            7,
		CreatedAt:                     sql.NullTime{Time: createdAt, Valid: true},
		UpdatedAt:                     sql.NullTime{Time: updatedAt, Valid: true},
		Enabled:                       true,
		Subject:                       subject,
		Username:                      "jdoe",
		GivenName:                     "Jane",
		MiddleName:                    "Q",
		FamilyName:                    "Doe",
		Nickname:                      "jd",
		Website:                       "https://example.com",
		Gender:                        "female",
		Email:                         "jane@example.com",
		EmailVerified:                 true,
		ZoneInfoCountryName:           "Brazil",
		ZoneInfo:                      "America/Sao_Paulo",
		Locale:                        "pt-BR",
		BirthDate:                     sql.NullTime{Time: birthDate, Valid: true},
		PhoneNumberCountryUniqueId:    "BRA_0",
		PhoneNumberCountryCallingCode: "55",
		PhoneNumber:                   "11999999999",
		PhoneNumberVerified:           true,
		AddressLine1:                  "Rua A, 1",
		AddressLine2:                  "Apto 2",
		AddressLocality:               "Sao Paulo",
		AddressRegion:                 "SP",
		AddressPostalCode:             "01000-000",
		AddressCountry:                "BR",
		OTPEnabled:                    true,
		Groups:                        []models.Group{{Id: 1, GroupIdentifier: "admins"}},
		Permissions:                   []models.Permission{{Id: 2, PermissionIdentifier: "read"}},
		Attributes:                    []models.UserAttribute{{Id: 3, Key: "k", Value: "v"}},
	}

	resp := ToUserResponse(user)

	assert.Equal(t, int64(7), resp.Id)
	assert.Equal(t, &createdAt, resp.CreatedAt)
	assert.Equal(t, &updatedAt, resp.UpdatedAt)
	assert.True(t, resp.Enabled)
	assert.Equal(t, subject, resp.Subject)
	assert.Equal(t, "jdoe", resp.Username)
	assert.Equal(t, "Jane", resp.GivenName)
	assert.Equal(t, "Q", resp.MiddleName)
	assert.Equal(t, "Doe", resp.FamilyName)
	assert.Equal(t, "jd", resp.Nickname)
	assert.Equal(t, "https://example.com", resp.Website)
	assert.Equal(t, "female", resp.Gender)
	assert.Equal(t, "jane@example.com", resp.Email)
	assert.True(t, resp.EmailVerified)
	assert.Equal(t, "Brazil", resp.ZoneInfoCountryName)
	assert.Equal(t, "America/Sao_Paulo", resp.ZoneInfo)
	assert.Equal(t, "pt-BR", resp.Locale)
	assert.Equal(t, &birthDate, resp.BirthDate)
	assert.Equal(t, "BRA_0", resp.PhoneNumberCountryUniqueId)
	assert.Equal(t, "55", resp.PhoneNumberCountryCallingCode)
	assert.Equal(t, "11999999999", resp.PhoneNumber)
	assert.True(t, resp.PhoneNumberVerified)
	assert.Equal(t, "Rua A, 1", resp.AddressLine1)
	assert.Equal(t, "Apto 2", resp.AddressLine2)
	assert.Equal(t, "Sao Paulo", resp.AddressLocality)
	assert.Equal(t, "SP", resp.AddressRegion)
	assert.Equal(t, "01000-000", resp.AddressPostalCode)
	assert.Equal(t, "BR", resp.AddressCountry)
	assert.True(t, resp.OTPEnabled)
	assert.Equal(t, user.Groups, resp.Groups)
	assert.Equal(t, user.Permissions, resp.Permissions)
	assert.Len(t, resp.Attributes, 1)
	assert.Equal(t, "k", resp.Attributes[0].Key)
}

// Invalid sql.NullTime values must become nil pointers rather than the zero time.
func TestToUserResponse_InvalidNullTimesBecomeNil(t *testing.T) {
	resp := ToUserResponse(&models.User{
		Id:        1,
		CreatedAt: sql.NullTime{Valid: false},
		UpdatedAt: sql.NullTime{Valid: false},
		BirthDate: sql.NullTime{Valid: false},
	})

	assert.Nil(t, resp.CreatedAt)
	assert.Nil(t, resp.UpdatedAt)
	assert.Nil(t, resp.BirthDate)
}

func TestUserResponse_ToUser_RoundTripsTimes(t *testing.T) {
	createdAt := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	birthDate := time.Date(1990, 5, 15, 0, 0, 0, 0, time.UTC)

	original := &models.User{
		Id:         9,
		Email:      "rt@example.com",
		CreatedAt:  sql.NullTime{Time: createdAt, Valid: true},
		BirthDate:  sql.NullTime{Time: birthDate, Valid: true},
		Attributes: []models.UserAttribute{{Id: 1, Key: "k", Value: "v"}},
	}

	roundTripped := ToUserResponse(original).ToUser()

	assert.Equal(t, int64(9), roundTripped.Id)
	assert.Equal(t, "rt@example.com", roundTripped.Email)
	assert.True(t, roundTripped.CreatedAt.Valid)
	assert.Equal(t, createdAt, roundTripped.CreatedAt.Time)
	assert.True(t, roundTripped.BirthDate.Valid)
	assert.Equal(t, birthDate, roundTripped.BirthDate.Time)
	assert.False(t, roundTripped.UpdatedAt.Valid, "an absent time must stay invalid")
	assert.Len(t, roundTripped.Attributes, 1)
	assert.Equal(t, "k", roundTripped.Attributes[0].Key)
}

func TestToUserResponses_MapsEachUserDistinctly(t *testing.T) {
	users := []models.User{
		{Id: 1, Email: "one@example.com"},
		{Id: 2, Email: "two@example.com"},
		{Id: 3, Email: "three@example.com"},
	}

	responses := ToUserResponses(users)

	assert.Len(t, responses, 3)
	assert.Equal(t, "one@example.com", responses[0].Email)
	assert.Equal(t, "two@example.com", responses[1].Email)
	assert.Equal(t, "three@example.com", responses[2].Email)
}

// =============================================================================
// Nil handling
//
// Every mapper guards against a nil input. These are one-liners individually,
// but a nil slip here is a panic in a request handler.
// =============================================================================

func TestMappers_NilInputReturnsNil(t *testing.T) {
	assert.Nil(t, ToUserResponse(nil))
	assert.Nil(t, ToUserResponses(nil))
	assert.Nil(t, ToUserAttributeResponse(nil))
	assert.Nil(t, ToUserAttributeResponses(nil))
	assert.Nil(t, ToUserSessionResponse(nil))
	assert.Nil(t, ToUserConsentResponse(nil))
	assert.Nil(t, ToUserConsentResponses(nil))
	assert.Nil(t, ToGroupResponse(nil, 0))
	assert.Nil(t, ToGroupAttributeResponse(nil))
	assert.Nil(t, ToGroupAttributeResponses(nil))
	assert.Nil(t, ToPermissionResponse(nil))
	assert.Nil(t, ToPermissionResponses(nil))
	assert.Nil(t, ToResourceResponse(nil))
	assert.Nil(t, ToResourceResponses(nil))
	assert.Nil(t, ToClientResponse(nil))

	var nilUserResp *UserResponse
	assert.Nil(t, nilUserResp.ToUser())
	var nilAttrResp *UserAttributeResponse
	assert.Nil(t, nilAttrResp.ToUserAttribute())
	var nilGroupResp *GroupResponse
	assert.Nil(t, nilGroupResp.ToGroup())
	var nilGroupAttrResp *GroupAttributeResponse
	assert.Nil(t, nilGroupAttrResp.ToGroupAttribute())
}

// The group and client list mappers return an empty slice rather than nil, so
// their JSON is `[]` instead of `null`. The user list mapper returns nil. That
// inconsistency is load-bearing for API clients, so it is pinned here.
func TestListMappers_NilSliceBehaviorDiffersByType(t *testing.T) {
	assert.Equal(t, []GroupResponse{}, ToGroupResponses(nil, nil))
	assert.Equal(t, []ClientResponse{}, ToClientResponses(nil))
	assert.Nil(t, ToUserResponses(nil))

	groupsJSON, err := json.Marshal(ToGroupResponses(nil, nil))
	assert.NoError(t, err)
	assert.Equal(t, "[]", string(groupsJSON))

	usersJSON, err := json.Marshal(ToUserResponses(nil))
	assert.NoError(t, err)
	assert.Equal(t, "null", string(usersJSON))
}

// =============================================================================
// ToUserSessionResponse
// =============================================================================

func TestToUserSessionResponse_MapsFields(t *testing.T) {
	started := time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)
	lastAccessed := time.Date(2024, 3, 1, 11, 0, 0, 0, time.UTC)
	authTime := time.Date(2024, 3, 1, 10, 0, 5, 0, time.UTC)

	session := &models.UserSession{
		Id:                3,
		SessionIdentifier: "session-abc",
		Started:           started,
		LastAccessed:      lastAccessed,
		AuthMethods:       "pwd otp",
		AcrLevel:          "urn:goiabada:level2_mandatory",
		AuthTime:          authTime,
		IpAddress:         "10.0.0.1",
		DeviceName:        "Pixel",
		DeviceType:        "mobile",
		DeviceOS:          "Android",
		UserId:            42,
	}

	resp := ToUserSessionResponse(session)

	assert.Equal(t, int64(3), resp.Id)
	assert.Equal(t, "session-abc", resp.SessionIdentifier)
	assert.Equal(t, &started, resp.Started)
	assert.Equal(t, &lastAccessed, resp.LastAccessed)
	assert.Equal(t, "pwd otp", resp.AuthMethods)
	assert.Equal(t, "urn:goiabada:level2_mandatory", resp.AcrLevel)
	assert.Equal(t, &authTime, resp.AuthTime)
	assert.Equal(t, "10.0.0.1", resp.IpAddress)
	assert.Equal(t, "Pixel", resp.DeviceName)
	assert.Equal(t, "mobile", resp.DeviceType)
	assert.Equal(t, "Android", resp.DeviceOS)
	assert.Equal(t, int64(42), resp.UserId)
}

// Started, LastAccessed and AuthTime are plain time.Time, so absence is the
// zero value rather than an invalid NullTime.
func TestToUserSessionResponse_ZeroTimesBecomeNil(t *testing.T) {
	resp := ToUserSessionResponse(&models.UserSession{Id: 1})

	assert.Nil(t, resp.Started)
	assert.Nil(t, resp.LastAccessed)
	assert.Nil(t, resp.AuthTime)
	assert.Nil(t, resp.CreatedAt)
	assert.Nil(t, resp.UpdatedAt)
}

// The level2AuthConfigHasChanged field was published on both session response
// schemas and described a per-session boolean that no longer decides anything.
// It is gone from the wire, and the deletions that removed it are otherwise
// invisible to a test: TestOpenAPI_DescribesEveryAPIRoute checks no response
// body at all, so nothing else fails if the field comes back (#242).
func TestUserSessionResponses_OmitLevel2AuthConfigHasChanged(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value interface{}
	}{
		{"UserSessionResponse", UserSessionResponse{Id: 1}},
		{"EnhancedUserSessionResponse", EnhancedUserSessionResponse{Id: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.value)
			assert.NoError(t, err)

			var decoded map[string]interface{}
			assert.NoError(t, json.Unmarshal(raw, &decoded))

			_, present := decoded["level2AuthConfigHasChanged"]
			assert.False(t, present, "level2AuthConfigHasChanged must not be published on %s", tc.name)
		})
	}
}

// =============================================================================
// ToUserConsentResponse
// =============================================================================

func TestToUserConsentResponse_IncludesClientDetailsWhenClientLoaded(t *testing.T) {
	grantedAt := time.Date(2024, 4, 1, 9, 0, 0, 0, time.UTC)

	consent := &models.UserConsent{
		Id:        5,
		ClientId:  11,
		UserId:    22,
		Scope:     "openid profile",
		GrantedAt: sql.NullTime{Time: grantedAt, Valid: true},
		Client: models.Client{
			Id:               11,
			ClientIdentifier: "web-app",
			Description:      "The web app",
		},
	}

	resp := ToUserConsentResponse(consent)

	assert.Equal(t, int64(5), resp.Id)
	assert.Equal(t, int64(11), resp.ClientId)
	assert.Equal(t, int64(22), resp.UserId)
	assert.Equal(t, "openid profile", resp.Scope)
	assert.Equal(t, &grantedAt, resp.GrantedAt)
	assert.Equal(t, "web-app", resp.ClientIdentifier)
	assert.Equal(t, "The web app", resp.ClientDescription)
}

// Client details are only copied when the association was actually loaded,
// which the mapper detects via a non-zero Client.Id.
func TestToUserConsentResponse_OmitsClientDetailsWhenClientNotLoaded(t *testing.T) {
	resp := ToUserConsentResponse(&models.UserConsent{
		Id:       5,
		ClientId: 11,
		Scope:    "openid",
		Client:   models.Client{}, // not loaded
	})

	assert.Equal(t, "", resp.ClientIdentifier)
	assert.Equal(t, "", resp.ClientDescription)
}

func TestToUserConsentResponses_MapsEachConsentDistinctly(t *testing.T) {
	responses := ToUserConsentResponses([]models.UserConsent{
		{Id: 1, Scope: "openid"},
		{Id: 2, Scope: "profile"},
	})

	assert.Len(t, responses, 2)
	assert.Equal(t, "openid", responses[0].Scope)
	assert.Equal(t, "profile", responses[1].Scope)
}

// =============================================================================
// Groups, permissions, resources, attributes
// =============================================================================

func TestToGroupResponse_MapsFieldsAndMemberCount(t *testing.T) {
	group := &models.Group{
		Id:                   4,
		GroupIdentifier:      "admins",
		Description:          "Administrators",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
	}

	resp := ToGroupResponse(group, 17)

	assert.Equal(t, int64(4), resp.Id)
	assert.Equal(t, "admins", resp.GroupIdentifier)
	assert.Equal(t, "Administrators", resp.Description)
	assert.True(t, resp.IncludeInIdToken)
	assert.False(t, resp.IncludeInAccessToken)
	assert.Equal(t, 17, resp.MemberCount, "member count comes from the argument, not the model")
}

func TestToGroupResponses_AppliesMemberCountsPerGroup(t *testing.T) {
	groups := []models.Group{
		{Id: 1, GroupIdentifier: "a"},
		{Id: 2, GroupIdentifier: "b"},
		{Id: 3, GroupIdentifier: "c"},
	}
	memberCounts := map[int64]int{1: 10, 3: 30}

	responses := ToGroupResponses(groups, memberCounts)

	assert.Len(t, responses, 3)
	assert.Equal(t, 10, responses[0].MemberCount)
	assert.Equal(t, 0, responses[1].MemberCount, "a group missing from the map gets zero")
	assert.Equal(t, 30, responses[2].MemberCount)
	assert.Equal(t, "a", responses[0].GroupIdentifier)
	assert.Equal(t, "c", responses[2].GroupIdentifier)
}

func TestToGroupResponses_NilMemberCountsYieldsZeroes(t *testing.T) {
	responses := ToGroupResponses([]models.Group{{Id: 1, GroupIdentifier: "a"}}, nil)

	assert.Len(t, responses, 1)
	assert.Equal(t, 0, responses[0].MemberCount)
}

func TestToGroupResponses_EmptySliceYieldsEmptySlice(t *testing.T) {
	assert.Equal(t, []GroupResponse{}, ToGroupResponses([]models.Group{}, nil))
}

func TestGroupResponse_ToGroup_RoundTrip(t *testing.T) {
	createdAt := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)

	original := &models.Group{
		Id:                   4,
		GroupIdentifier:      "admins",
		Description:          "Administrators",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		CreatedAt:            sql.NullTime{Time: createdAt, Valid: true},
	}

	roundTripped := ToGroupResponse(original, 5).ToGroup()

	assert.Equal(t, int64(4), roundTripped.Id)
	assert.Equal(t, "admins", roundTripped.GroupIdentifier)
	assert.Equal(t, "Administrators", roundTripped.Description)
	assert.True(t, roundTripped.IncludeInIdToken)
	assert.True(t, roundTripped.IncludeInAccessToken)
	assert.Equal(t, 5, roundTripped.MemberCount)
	assert.True(t, roundTripped.CreatedAt.Valid)
	assert.Equal(t, createdAt, roundTripped.CreatedAt.Time)
	assert.False(t, roundTripped.UpdatedAt.Valid)
}

func TestToPermissionResponse_IncludesNestedResource(t *testing.T) {
	perm := &models.Permission{
		Id:                   8,
		PermissionIdentifier: "read",
		Description:          "Read access",
		ResourceId:           10,
		Resource: models.Resource{
			Id:                 10,
			ResourceIdentifier: "backend-svc",
			Description:        "Backend service",
		},
	}

	resp := ToPermissionResponse(perm)

	assert.Equal(t, int64(8), resp.Id)
	assert.Equal(t, "read", resp.PermissionIdentifier)
	assert.Equal(t, "Read access", resp.Description)
	assert.Equal(t, int64(10), resp.ResourceId)
	assert.Equal(t, int64(10), resp.Resource.Id)
	assert.Equal(t, "backend-svc", resp.Resource.ResourceIdentifier)
	assert.Equal(t, "Backend service", resp.Resource.Description)
}

func TestToPermissionResponses_MapsEachPermissionDistinctly(t *testing.T) {
	responses := ToPermissionResponses([]models.Permission{
		{Id: 1, PermissionIdentifier: "read"},
		{Id: 2, PermissionIdentifier: "write"},
	})

	assert.Len(t, responses, 2)
	assert.Equal(t, "read", responses[0].PermissionIdentifier)
	assert.Equal(t, "write", responses[1].PermissionIdentifier)
}

func TestToResourceResponses_MapsEachResourceDistinctly(t *testing.T) {
	responses := ToResourceResponses([]models.Resource{
		{Id: 1, ResourceIdentifier: "svc-a"},
		{Id: 2, ResourceIdentifier: "svc-b"},
	})

	assert.Len(t, responses, 2)
	assert.Equal(t, "svc-a", responses[0].ResourceIdentifier)
	assert.Equal(t, "svc-b", responses[1].ResourceIdentifier)
}

func TestToUserAttributeResponse_RoundTrip(t *testing.T) {
	createdAt := time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 7, 2, 0, 0, 0, 0, time.UTC)

	original := &models.UserAttribute{
		Id:                   3,
		Key:                  "department",
		Value:                "engineering",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
		UserId:               42,
		CreatedAt:            sql.NullTime{Time: createdAt, Valid: true},
		UpdatedAt:            sql.NullTime{Time: updatedAt, Valid: true},
	}

	resp := ToUserAttributeResponse(original)
	assert.Equal(t, "department", resp.Key)
	assert.Equal(t, "engineering", resp.Value)
	assert.True(t, resp.IncludeInIdToken)
	assert.False(t, resp.IncludeInAccessToken)
	assert.Equal(t, int64(42), resp.UserId)
	assert.Equal(t, &createdAt, resp.CreatedAt)
	assert.Equal(t, &updatedAt, resp.UpdatedAt)

	roundTripped := resp.ToUserAttribute()
	assert.Equal(t, original.Id, roundTripped.Id)
	assert.Equal(t, original.Key, roundTripped.Key)
	assert.Equal(t, original.Value, roundTripped.Value)
	assert.Equal(t, original.UserId, roundTripped.UserId)
	assert.True(t, roundTripped.CreatedAt.Valid)
	assert.Equal(t, createdAt, roundTripped.CreatedAt.Time)
}

func TestToUserAttributeResponses_MapsEachAttributeDistinctly(t *testing.T) {
	responses := ToUserAttributeResponses([]models.UserAttribute{
		{Id: 1, Key: "a", Value: "1"},
		{Id: 2, Key: "b", Value: "2"},
	})

	assert.Len(t, responses, 2)
	assert.Equal(t, "a", responses[0].Key)
	assert.Equal(t, "b", responses[1].Key)
}

func TestToGroupAttributeResponse_RoundTrip(t *testing.T) {
	createdAt := time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC)

	original := &models.GroupAttribute{
		Id:                   3,
		Key:                  "tier",
		Value:                "gold",
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
		GroupId:              9,
		CreatedAt:            sql.NullTime{Time: createdAt, Valid: true},
	}

	resp := ToGroupAttributeResponse(original)
	assert.Equal(t, "tier", resp.Key)
	assert.Equal(t, "gold", resp.Value)
	assert.Equal(t, int64(9), resp.GroupId)
	assert.Equal(t, &createdAt, resp.CreatedAt)
	assert.Nil(t, resp.UpdatedAt)

	roundTripped := resp.ToGroupAttribute()
	assert.Equal(t, original.Id, roundTripped.Id)
	assert.Equal(t, original.Key, roundTripped.Key)
	assert.Equal(t, original.Value, roundTripped.Value)
	assert.Equal(t, original.GroupId, roundTripped.GroupId)
	assert.True(t, roundTripped.CreatedAt.Valid)
	assert.False(t, roundTripped.UpdatedAt.Valid)
}

func TestToGroupAttributeResponses_MapsEachAttributeDistinctly(t *testing.T) {
	responses := ToGroupAttributeResponses([]models.GroupAttribute{
		{Id: 1, Key: "a"},
		{Id: 2, Key: "b"},
	})

	assert.Len(t, responses, 2)
	assert.Equal(t, "a", responses[0].Key)
	assert.Equal(t, "b", responses[1].Key)
}

// =============================================================================
// ToClientResponse field mapping
// =============================================================================

func TestToClientResponse_MapsFields(t *testing.T) {
	pkceRequired := true
	implicitEnabled := false

	client := &models.Client{
		Id:                                      12,
		ClientIdentifier:                        "web-app",
		Description:                             "The web app",
		WebsiteURL:                              "https://app.example.com",
		DisplayName:                             "Web App",
		Enabled:                                 true,
		ConsentRequired:                         true,
		CreatedViaDCR:                           true,
		ShowLogo:                                true,
		IsPublic:                                false,
		AuthorizationCodeEnabled:                true,
		ClientCredentialsEnabled:                true,
		PKCERequired:                            &pkceRequired,
		ImplicitGrantEnabled:                    &implicitEnabled,
		ResourceOwnerPasswordCredentialsEnabled: nil,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
		RedirectURIs:                            []models.RedirectURI{{Id: 1, URI: "https://app.example.com/cb"}},
		WebOrigins:                              []models.WebOrigin{{Id: 1, Origin: "https://app.example.com"}},
	}

	resp := ToClientResponse(client)

	assert.Equal(t, int64(12), resp.Id)
	assert.Equal(t, "web-app", resp.ClientIdentifier)
	assert.Equal(t, "The web app", resp.Description)
	assert.Equal(t, "https://app.example.com", resp.WebsiteURL)
	assert.Equal(t, "Web App", resp.DisplayName)
	assert.True(t, resp.Enabled)
	assert.True(t, resp.ConsentRequired)
	assert.True(t, resp.CreatedViaDCR)
	assert.True(t, resp.ShowLogo)
	assert.False(t, resp.IsPublic)
	assert.True(t, resp.AuthorizationCodeEnabled)
	assert.True(t, resp.ClientCredentialsEnabled)
	assert.Equal(t, &pkceRequired, resp.PKCERequired)
	assert.Equal(t, &implicitEnabled, resp.ImplicitGrantEnabled)
	assert.Nil(t, resp.ResourceOwnerPasswordCredentialsEnabled,
		"nil must survive the mapping so the global setting still applies")
	assert.Equal(t, 300, resp.TokenExpirationInSeconds)
	assert.Equal(t, 3600, resp.RefreshTokenOfflineIdleTimeoutInSeconds)
	assert.Equal(t, 86400, resp.RefreshTokenOfflineMaxLifetimeInSeconds)
	assert.Equal(t, client.RedirectURIs, resp.RedirectURIs)
	assert.Equal(t, client.WebOrigins, resp.WebOrigins)
	assert.Equal(t, client.IsSystemLevelClient(), resp.IsSystemLevelClient)
}

// TestToClientResponse_CreatedViaDCRIsCopiedNotAssumed pins the other half of the mapping. The
// fixture above is self-registered, so a mapper that hardcoded true would satisfy it; an
// administrator-created client is what says the value is read off the client. The admin console
// badges self-registered clients straight off this field, so a mapper stuck on either value would
// mark every client or none of them (#108).
func TestToClientResponse_CreatedViaDCRIsCopiedNotAssumed(t *testing.T) {
	resp := ToClientResponse(&models.Client{ClientIdentifier: "web-app", CreatedViaDCR: false})
	assert.False(t, resp.CreatedViaDCR)
}

// =============================================================================
// Audit timestamps
//
// Every mapper copies createdAt / updatedAt out of a sql.NullTime, and each one
// does it with its own pair of branches. These are the timestamps an admin sees
// in the console, so both the present and absent cases are worth pinning across
// the mappers rather than only on UserResponse.
// =============================================================================

func TestMappers_CopyCreatedAtAndUpdatedAt(t *testing.T) {
	createdAt := time.Date(2024, 9, 1, 8, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 9, 2, 9, 30, 0, 0, time.UTC)
	valid := sql.NullTime{Time: createdAt, Valid: true}
	validUpdated := sql.NullTime{Time: updatedAt, Valid: true}

	t.Run("user session", func(t *testing.T) {
		resp := ToUserSessionResponse(&models.UserSession{
			Id: 1, CreatedAt: valid, UpdatedAt: validUpdated,
		})
		assert.Equal(t, &createdAt, resp.CreatedAt)
		assert.Equal(t, &updatedAt, resp.UpdatedAt)
	})

	t.Run("user consent", func(t *testing.T) {
		resp := ToUserConsentResponse(&models.UserConsent{
			Id: 1, CreatedAt: valid, UpdatedAt: validUpdated,
		})
		assert.Equal(t, &createdAt, resp.CreatedAt)
		assert.Equal(t, &updatedAt, resp.UpdatedAt)
		assert.Nil(t, resp.GrantedAt, "an ungranted consent has no grantedAt")
	})

	t.Run("group", func(t *testing.T) {
		resp := ToGroupResponse(&models.Group{Id: 1, CreatedAt: valid, UpdatedAt: validUpdated}, 0)
		assert.Equal(t, &createdAt, resp.CreatedAt)
		assert.Equal(t, &updatedAt, resp.UpdatedAt)

		back := resp.ToGroup()
		assert.True(t, back.CreatedAt.Valid)
		assert.True(t, back.UpdatedAt.Valid)
		assert.Equal(t, updatedAt, back.UpdatedAt.Time)
	})

	t.Run("group attribute", func(t *testing.T) {
		resp := ToGroupAttributeResponse(&models.GroupAttribute{
			Id: 1, CreatedAt: valid, UpdatedAt: validUpdated,
		})
		assert.Equal(t, &createdAt, resp.CreatedAt)
		assert.Equal(t, &updatedAt, resp.UpdatedAt)

		back := resp.ToGroupAttribute()
		assert.True(t, back.CreatedAt.Valid)
		assert.True(t, back.UpdatedAt.Valid)
		assert.Equal(t, updatedAt, back.UpdatedAt.Time)
	})

	t.Run("user attribute", func(t *testing.T) {
		back := ToUserAttributeResponse(&models.UserAttribute{
			Id: 1, CreatedAt: valid, UpdatedAt: validUpdated,
		}).ToUserAttribute()
		assert.True(t, back.CreatedAt.Valid)
		assert.True(t, back.UpdatedAt.Valid)
		assert.Equal(t, updatedAt, back.UpdatedAt.Time)
	})

	t.Run("user round trip", func(t *testing.T) {
		back := ToUserResponse(&models.User{
			Id: 1, CreatedAt: valid, UpdatedAt: validUpdated,
		}).ToUser()
		assert.True(t, back.CreatedAt.Valid)
		assert.True(t, back.UpdatedAt.Valid)
		assert.Equal(t, updatedAt, back.UpdatedAt.Time)
		assert.False(t, back.BirthDate.Valid, "an absent birth date must stay invalid")
	})

	t.Run("client", func(t *testing.T) {
		resp := ToClientResponse(&models.Client{Id: 1, CreatedAt: valid, UpdatedAt: validUpdated})
		assert.Equal(t, &createdAt, resp.CreatedAt)
		assert.Equal(t, &updatedAt, resp.UpdatedAt)
	})
}

func TestToClientResponses_MapsEachClientDistinctly(t *testing.T) {
	responses := ToClientResponses([]models.Client{
		{Id: 1, ClientIdentifier: "one"},
		{Id: 2, ClientIdentifier: "two"},
	})

	assert.Len(t, responses, 2)
	assert.Equal(t, "one", responses[0].ClientIdentifier)
	assert.Equal(t, "two", responses[1].ClientIdentifier)
}

func TestToClientResponses_EmptySliceYieldsEmptySlice(t *testing.T) {
	assert.Equal(t, []ClientResponse{}, ToClientResponses([]models.Client{}))
}
