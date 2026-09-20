package apimapping

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// The wire bytes, one literal per shape
//
// Everything below marshals a response the way an http.ResponseWriter does and
// compares the result against a literal string, in the shape core/api's own
// session_wire_test.go uses. The point is not that the mappers copy fields --
// mapping_test.go owns that -- but that the bytes leaving this server are a
// thing somebody has written down. A field renamed, a json tag edited, a nested
// type swapped or a nil slice that starts marshalling as [] instead of null all
// fail here, naming the family they moved.
//
// These literals were first written against the bytes as they were, capitalised
// nested keys and {"Time":...,"Valid":...} objects included, so that replacing
// those shapes would be a diff a reviewer reads rather than a claim. That
// replacement has now happened: models.Group and models.Permission left
// UserResponse entirely, and models.RedirectURI and models.WebOrigin became
// api.RedirectURIResponse and api.WebOriginResponse, lowerCamelCase with a
// *time.Time that is null when the column is NULL. What the literals do from
// here is stop any other change moving a shape by accident (#350).
//
// There is no decode half here, unlike session_wire_test.go: a mapper is
// one-way, and the response types the admin console decodes are round-tripped
// by the ToUser / ToGroup cases in mapping_test.go.
// =============================================================================

var (
	wireCreated = time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC)
	wireUpdated = time.Date(2026, 9, 16, 11, 0, 0, 0, time.UTC)
	wireGranted = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	wireStarted = time.Date(2026, 9, 16, 9, 0, 0, 0, time.UTC)
	wireTouched = time.Date(2026, 9, 16, 9, 30, 0, 0, time.UTC)
	wireBorn    = time.Date(1990, 1, 2, 0, 0, 0, 0, time.UTC)
)

func wireNullTime(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t, Valid: true}
}

type wireCase struct {
	name string
	// value is marshalled as-is, so a case that means to pin a mapper's output
	// calls the mapper here rather than building the response by hand.
	value   any
	literal string
}

func runWireCases(t *testing.T, cases []wireCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.value)
			require.NoError(t, err)
			assert.Equal(t, tc.literal, string(encoded))
		})
	}
}

// -----------------------------------------------------------------------------
// The nested shapes, named once
//
// These two are the last persistence models that reached the wire through a
// field of a response type, and they no longer do: each is an api DTO now, with
// lowerCamelCase keys and a *time.Time that is null rather than
// {"Time":"0001-01-01T00:00:00Z","Valid":false} when the column is NULL. The
// four shapes that used to sit beside them here -- models.Group,
// models.Permission and its nested models.Resource, and the NullTime object
// itself -- have no position on the wire left to pin: UserResponse carries
// neither collection (#350).
// -----------------------------------------------------------------------------

const (
	wireRedirectURIJSON = `{"id":1,"createdAt":"2026-09-16T10:00:00Z",` +
		`"uri":"https://app.example/cb","clientId":3}`

	// The one nested NULL timestamp in this file, and the whole of what the
	// {"Time":...,"Valid":...} object became.
	wireWebOriginJSON = `{"id":2,"createdAt":null,"origin":"https://app.example","clientId":3}`
)

func wireGroupModel() models.Group {
	return models.Group{
		Id:                   2,
		CreatedAt:            wireNullTime(wireCreated),
		UpdatedAt:            wireNullTime(wireUpdated),
		GroupIdentifier:      "admins",
		Description:          "administrators",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
		MemberCount:          3,
	}
}

func wireResourceModel() models.Resource {
	return models.Resource{
		Id:                 9,
		CreatedAt:          wireNullTime(wireCreated),
		ResourceIdentifier: "backend-svc",
		Description:        "the backend service",
	}
}

func wirePermissionModel() models.Permission {
	return models.Permission{
		Id:                   5,
		CreatedAt:            wireNullTime(wireCreated),
		UpdatedAt:            wireNullTime(wireUpdated),
		PermissionIdentifier: "read-all",
		Description:          "read everything",
		ResourceId:           9,
		Resource:             wireResourceModel(),
	}
}

func wireUserAttributeModel() models.UserAttribute {
	return models.UserAttribute{
		Id:                   11,
		CreatedAt:            wireNullTime(wireCreated),
		UpdatedAt:            wireNullTime(wireUpdated),
		Key:                  "department",
		Value:                "engineering",
		IncludeInIdToken:     true,
		IncludeInAccessToken: false,
		UserId:               7,
	}
}

const wireUserAttributeJSON = `{"id":11,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
	`"key":"department","value":"engineering","includeInIdToken":true,"includeInAccessToken":false,"userId":7}`

// -----------------------------------------------------------------------------
// The user family
// -----------------------------------------------------------------------------

func wireUserModel() *models.User {
	return &models.User{
		Id:                            7,
		CreatedAt:                     wireNullTime(wireCreated),
		UpdatedAt:                     wireNullTime(wireUpdated),
		Enabled:                       true,
		Subject:                       "3b9f1a2c-0000-4000-8000-000000000001",
		Username:                      "alice",
		GivenName:                     "Alice",
		MiddleName:                    "Q",
		FamilyName:                    "Smith",
		Nickname:                      "al",
		Website:                       "https://alice.example",
		Gender:                        "female",
		Email:                         "alice@example.com",
		EmailVerified:                 true,
		ZoneInfoCountryName:           "Brazil",
		ZoneInfo:                      "America/Sao_Paulo",
		Locale:                        "pt-BR",
		BirthDate:                     wireNullTime(wireBorn),
		PhoneNumberCountryUniqueId:    "BRA_55",
		PhoneNumberCountryCallingCode: "55",
		PhoneNumber:                   "11 99999-0000",
		PhoneNumberVerified:           true,
		AddressLine1:                  "Rua Um, 100",
		AddressLine2:                  "apto 2",
		AddressLocality:               "Sao Paulo",
		AddressRegion:                 "SP",
		AddressPostalCode:             "01000-000",
		AddressCountry:                "BRA",
		OTPEnabled:                    true,
	}
}

// wirePopulatedUserJSON is ToUserResponse over wireUserModel with one group, one
// permission and one attribute loaded on the model. It ends at otpEnabled: the
// three collection keys that used to follow are gone, and the fixture keeps
// loading all three so that this literal is what says so (#350).
const wirePopulatedUserJSON = `{"id":7,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
	`"enabled":true,"subject":"3b9f1a2c-0000-4000-8000-000000000001","username":"alice","givenName":"Alice",` +
	`"middleName":"Q","familyName":"Smith","nickname":"al","website":"https://alice.example","gender":"female",` +
	`"email":"alice@example.com","emailVerified":true,"zoneInfoCountryName":"Brazil",` +
	`"zoneInfo":"America/Sao_Paulo","locale":"pt-BR","birthDate":"1990-01-02T00:00:00Z",` +
	`"phoneNumberCountryUniqueId":"BRA_55","phoneNumberCountryCallingCode":"55","phoneNumber":"11 99999-0000",` +
	`"phoneNumberVerified":true,"addressLine1":"Rua Um, 100","addressLine2":"apto 2",` +
	`"addressLocality":"Sao Paulo","addressRegion":"SP","addressPostalCode":"01000-000","addressCountry":"BRA",` +
	`"otpEnabled":true}`

// wireBareUserFields is ToUserResponse over a models.User carrying nothing but
// its id, with no braces: brace-free so the annotated wrappers further down can
// show how an embedded UserResponse flattens into its container.
func wireBareUserFields() string {
	return `"id":7,"createdAt":null,"updatedAt":null,"enabled":false,"subject":"","username":"",` +
		`"givenName":"","middleName":"","familyName":"","nickname":"","website":"","gender":"","email":"",` +
		`"emailVerified":false,"zoneInfoCountryName":"","zoneInfo":"","locale":"","birthDate":null,` +
		`"phoneNumberCountryUniqueId":"","phoneNumberCountryCallingCode":"","phoneNumber":"",` +
		`"phoneNumberVerified":false,"addressLine1":"","addressLine2":"","addressLocality":"",` +
		`"addressRegion":"","addressPostalCode":"","addressCountry":"","otpEnabled":false`
}

func TestWireJSON_UserFamily(t *testing.T) {
	populated := wireUserModel()
	populated.Groups = []models.Group{wireGroupModel()}
	populated.Permissions = []models.Permission{wirePermissionModel()}
	populated.Attributes = []models.UserAttribute{wireUserAttributeModel()}

	attribute := wireUserAttributeModel()

	empty := &models.User{
		Id:          7,
		Groups:      []models.Group{},
		Permissions: []models.Permission{},
		Attributes:  []models.UserAttribute{},
	}

	runWireCases(t, []wireCase{
		{
			name:    "populated, with every collection loaded on the model",
			value:   ToUserResponse(populated),
			literal: wirePopulatedUserJSON,
		},
		{
			// A user loaded without its collections, which was 20 of the 23
			// ToUserResponse call sites: every timestamp is NULL.
			name:    "NULL timestamps",
			value:   ToUserResponse(&models.User{Id: 7}),
			literal: "{" + wireBareUserFields() + "}",
		},
		{
			// The empty-slice and nil-slice spellings used to be the only thing
			// the two rows above disagreed about. They agree byte for byte now,
			// which is the same fact from the other side: what a handler loaded
			// onto the model cannot reach this body (#350).
			name:    "empty collections are the same bytes as none at all",
			value:   ToUserResponse(empty),
			literal: "{" + wireBareUserFields() + "}",
		},
		{
			name:    "UserAttributeResponse",
			value:   ToUserAttributeResponse(&attribute),
			literal: wireUserAttributeJSON,
		},
		{
			name: "UserAttributeResponse with NULL timestamps",
			value: ToUserAttributeResponse(&models.UserAttribute{
				Id: 11, Key: "department", Value: "engineering", UserId: 7,
			}),
			literal: `{"id":11,"createdAt":null,"updatedAt":null,"key":"department","value":"engineering",` +
				`"includeInIdToken":false,"includeInAccessToken":false,"userId":7}`,
		},
	})
}

// TestWireJSON_UserResponseOmitsTheNestedCollections says in key names what the
// user family's literals say in bytes: groups, permissions and attributes are
// absent from a user body, not present and null.
//
// The three used to be fields of UserResponse and were wrong in three different
// ways. groups and permissions were populated at exactly three of the 23
// ToUserResponse call sites, all of them responses that already carried the same
// rows beside them as GroupResponse and PermissionResponse -- so GET
// /users/{id}/groups marshalled one group twice in one body, in two spellings,
// and the two copies disagreed, because the sibling got the member counts the
// handler had queried and the nested copy got the raw model's zero. attributes
// had no loader at all: the only handler that reads them writes
// GetUserAttributesResponse. In the other 20 responses all three were null.
//
// Re-adding any of them would fail the literals above too, but it would fail
// them as an unexplained byte diff. This is the row that names what is missing
// and why, and the three endpoints that serve the data instead (#350).
func TestWireJSON_UserResponseOmitsTheNestedCollections(t *testing.T) {
	loaded := wireUserModel()
	loaded.Groups = []models.Group{wireGroupModel()}
	loaded.Permissions = []models.Permission{wirePermissionModel()}
	loaded.Attributes = []models.UserAttribute{wireUserAttributeModel()}

	encoded, err := json.Marshal(ToUserResponse(loaded))
	require.NoError(t, err)

	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(encoded, &body))

	for key, served := range map[string]string{
		"groups":      "GET /api/v1/admin/users/{id}/groups",
		"permissions": "GET /api/v1/admin/users/{id}/permissions",
		"attributes":  "GET /api/v1/admin/users/{id}/attributes",
	} {
		_, present := body[key]
		assert.False(t, present, "a user body must not carry %q at all, not even as null: %s is "+
			"what serves it", key, served)
	}

	// The scalars are still there, so an empty body cannot be what passed the loop above.
	assert.Contains(t, body, "id")
	assert.Contains(t, body, "otpEnabled")
}

func TestWireJSON_UserSessionFamily(t *testing.T) {
	populated := &models.UserSession{
		Id:                21,
		CreatedAt:         wireNullTime(wireCreated),
		UpdatedAt:         wireNullTime(wireUpdated),
		SessionIdentifier: "b1c2d3",
		Started:           wireStarted,
		LastAccessed:      wireTouched,
		AuthMethods:       "pwd otp",
		AcrLevel:          string(models.AcrLevel2Optional),
		AuthTime:          wireStarted,
		IpAddress:         "203.0.113.7",
		DeviceName:        "Firefox",
		DeviceType:        "Desktop",
		DeviceOS:          "Linux",
		UserAgent:         "Mozilla/5.0",
		UserId:            7,
	}

	// The detail form is what the three list endpoints return. It embeds
	// UserSessionResponse, so this is also where the embedding is pinned: the base
	// has to flatten into the same object rather than nest under a key, which is
	// what the OpenAPI allOf claims and what every generated client will assume.
	detail := *ToUserSessionDetailResponse(&models.UserSession{
		Id:                21,
		CreatedAt:         wireNullTime(wireCreated),
		UpdatedAt:         wireNullTime(wireUpdated),
		SessionIdentifier: "b1c2d3",
		Started:           wireStarted,
		LastAccessed:      wireTouched,
		AuthMethods:       "pwd otp",
		AcrLevel:          string(models.AcrLevel2Optional),
		AuthTime:          wireStarted,
		IpAddress:         "203.0.113.7",
		DeviceName:        "Firefox",
		DeviceType:        "Desktop",
		DeviceOS:          "Linux",
		UserAgent:         "Mozilla/5.0",
		UserId:            7,
		Clients: []models.UserSessionClient{
			{ClientId: 5, Client: models.Client{Id: 5, ClientIdentifier: "admin-console-client"}},
		},
	}, "")

	runWireCases(t, []wireCase{
		{
			name:  "UserSessionResponse, populated",
			value: ToUserSessionResponse(populated),
			literal: `{"id":21,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				`"sessionIdentifier":"b1c2d3","started":"2026-09-16T09:00:00Z",` +
				`"lastAccessed":"2026-09-16T09:30:00Z","authMethods":"pwd otp",` +
				`"acrLevel":"urn:goiabada:level2_optional","authTime":"2026-09-16T09:00:00Z",` +
				`"ipAddress":"203.0.113.7","deviceName":"Firefox","deviceType":"Desktop","deviceOS":"Linux",` +
				`"userAgent":"Mozilla/5.0","userId":7}`,
		},
		{
			// A zero time.Time is not a NULL column, but both reach the wire as
			// null. The mapper is what decides that, and this is where it shows.
			name:  "UserSessionResponse, zero times become null",
			value: ToUserSessionResponse(&models.UserSession{Id: 21, UserId: 7}),
			literal: `{"id":21,"createdAt":null,"updatedAt":null,"sessionIdentifier":"","started":null,` +
				`"lastAccessed":null,"authMethods":"","acrLevel":"","authTime":null,"ipAddress":"",` +
				`"deviceName":"","deviceType":"","deviceOS":"","userAgent":"","userId":7}`,
		},
		{
			// The five keys this literal does not contain are the point of it:
			// startedAt, durationSinceStarted, lastAccessedAt,
			// durationSinceLastAccessed and isValid were published here until
			// #373, four of them an English date and a Go duration computed from
			// instants already in this same object, the fifth a constant true.
			// A byte-for-byte literal is what fails if any of them comes back.
			name:  "UserSessionDetailResponse, populated",
			value: detail,
			literal: `{"id":21,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				`"sessionIdentifier":"b1c2d3","started":"2026-09-16T09:00:00Z",` +
				`"lastAccessed":"2026-09-16T09:30:00Z","authMethods":"pwd otp",` +
				`"acrLevel":"urn:goiabada:level2_optional","authTime":"2026-09-16T09:00:00Z",` +
				`"ipAddress":"203.0.113.7","deviceName":"Firefox","deviceType":"Desktop","deviceOS":"Linux",` +
				`"userAgent":"Mozilla/5.0","userId":7,"isCurrent":false,` +
				`"clientIdentifiers":["admin-console-client"]}`,
		},
		{
			// isCurrent true, which no other row here carries, and the empty
			// client list the mapper must publish as [] rather than null.
			name:  "UserSessionDetailResponse, current and no clients",
			value: *ToUserSessionDetailResponse(&models.UserSession{Id: 21, SessionIdentifier: "b1c2d3", UserId: 7}, "b1c2d3"),
			literal: `{"id":21,"createdAt":null,"updatedAt":null,"sessionIdentifier":"b1c2d3","started":null,` +
				`"lastAccessed":null,"authMethods":"","acrLevel":"","authTime":null,"ipAddress":"",` +
				`"deviceName":"","deviceType":"","deviceOS":"","userAgent":"","userId":7,` +
				`"isCurrent":true,"clientIdentifiers":[]}`,
		},
		{
			// The declared struct with nothing built it: a nil ClientIdentifiers
			// reaches the wire as null, which is why the mapper never leaves it
			// nil. Kept so the difference between the two is visible here rather
			// than asserted only in the mapper's own table.
			name:  "UserSessionDetailResponse, a nil client list is null",
			value: api.UserSessionDetailResponse{UserSessionResponse: api.UserSessionResponse{Id: 21, UserId: 7}},
			literal: `{"id":21,"createdAt":null,"updatedAt":null,"sessionIdentifier":"","started":null,` +
				`"lastAccessed":null,"authMethods":"","acrLevel":"","authTime":null,"ipAddress":"",` +
				`"deviceName":"","deviceType":"","deviceOS":"","userAgent":"","userId":7,` +
				`"isCurrent":false,"clientIdentifiers":null}`,
		},
	})
}

func TestWireJSON_UserConsentFamily(t *testing.T) {
	consent := func() *models.UserConsent {
		return &models.UserConsent{
			Id:        31,
			CreatedAt: wireNullTime(wireCreated),
			UpdatedAt: wireNullTime(wireUpdated),
			UserId:    7,
			ClientId:  3,
			Scope:     "openid profile",
			GrantedAt: wireNullTime(wireGranted),
		}
	}

	withClient := consent()
	withClient.Client = models.Client{Id: 3, ClientIdentifier: "web-app", Description: "the web app"}

	runWireCases(t, []wireCase{
		{
			name:  "client loaded",
			value: ToUserConsentResponse(withClient),
			literal: `{"id":31,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				`"clientId":3,"userId":7,"scope":"openid profile","grantedAt":"2026-09-16T12:00:00Z",` +
				`"clientIdentifier":"web-app","clientDescription":"the web app"}`,
		},
		{
			// The consent rows a list endpoint returns without joining the
			// client: the two client keys are present and empty rather than
			// absent, so a consumer reading them gets "" and not undefined.
			name:  "client not loaded",
			value: ToUserConsentResponse(consent()),
			literal: `{"id":31,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				`"clientId":3,"userId":7,"scope":"openid profile","grantedAt":"2026-09-16T12:00:00Z",` +
				`"clientIdentifier":"","clientDescription":""}`,
		},
	})
}

// -----------------------------------------------------------------------------
// The group, permission and resource families
// -----------------------------------------------------------------------------

// wireGroupResponseFields is ToGroupResponse over wireGroupModel with a member
// count of 3, brace-free for the annotated wrapper below.
const wireGroupResponseFields = `"id":2,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
	`"groupIdentifier":"admins","description":"administrators","includeInIdToken":true,` +
	`"includeInAccessToken":false,"memberCount":3`

func TestWireJSON_GroupFamily(t *testing.T) {
	group := wireGroupModel()

	runWireCases(t, []wireCase{
		{
			name:    "GroupResponse, populated",
			value:   ToGroupResponse(&group, 3),
			literal: "{" + wireGroupResponseFields + "}",
		},
		{
			name:  "GroupResponse, NULL timestamps",
			value: ToGroupResponse(&models.Group{Id: 2, GroupIdentifier: "admins"}, 0),
			literal: `{"id":2,"createdAt":null,"updatedAt":null,"groupIdentifier":"admins","description":"",` +
				`"includeInIdToken":false,"includeInAccessToken":false,"memberCount":0}`,
		},
		{
			name: "GroupAttributeResponse",
			value: ToGroupAttributeResponse(&models.GroupAttribute{
				Id:               41,
				CreatedAt:        wireNullTime(wireCreated),
				UpdatedAt:        wireNullTime(wireUpdated),
				Key:              "cost-centre",
				Value:            "ops",
				IncludeInIdToken: true,
				GroupId:          2,
			}),
			literal: `{"id":41,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				`"key":"cost-centre","value":"ops","includeInIdToken":true,"includeInAccessToken":false,` +
				`"groupId":2}`,
		},
		{
			name: "GroupAttributeResponse with NULL timestamps",
			value: ToGroupAttributeResponse(&models.GroupAttribute{
				Id: 41, Key: "cost-centre", Value: "ops", GroupId: 2,
			}),
			literal: `{"id":41,"createdAt":null,"updatedAt":null,"key":"cost-centre","value":"ops",` +
				`"includeInIdToken":false,"includeInAccessToken":false,"groupId":2}`,
		},
	})
}

func TestWireJSON_PermissionAndResourceFamilies(t *testing.T) {
	permission := wirePermissionModel()
	resource := wireResourceModel()

	const resourceJSON = `{"id":9,"resourceIdentifier":"backend-svc","description":"the backend service",` +
		`"isSystemLevelResource":false}`

	runWireCases(t, []wireCase{
		{
			// PermissionResponse publishes neither timestamp, so the nested
			// ResourceResponse is the whole of what a permission carries beyond
			// its own three scalars.
			name:  "PermissionResponse, with its nested resource",
			value: ToPermissionResponse(&permission),
			literal: `{"id":5,"permissionIdentifier":"read-all","description":"read everything",` +
				`"resourceId":9,"resource":` + resourceJSON + `}`,
		},
		{
			name:    "ResourceResponse",
			value:   ToResourceResponse(&resource),
			literal: resourceJSON,
		},
		{
			// The auth server's own resource. The admin console used to ask
			// models.Resource.IsSystemLevelResource() about this one, because
			// the answer was on no response. It is on this shape now, and the
			// pair of rows -- false above, true here -- is what says the mapper
			// asks the model rather than writing a constant (#350).
			name: "ResourceResponse for the system-level resource",
			value: ToResourceResponse(&models.Resource{
				Id:                 1,
				ResourceIdentifier: constants.AuthServerResourceIdentifier,
				Description:        "Goiabada auth server",
			}),
			literal: `{"id":1,"resourceIdentifier":"authserver","description":"Goiabada auth server",` +
				`"isSystemLevelResource":true}`,
		},
	})
}

// -----------------------------------------------------------------------------
// The client family
// -----------------------------------------------------------------------------

func TestWireJSON_ClientFamily(t *testing.T) {
	pkceRequired := true
	ropcEnabled := false

	client := &models.Client{
		Id:                                      3,
		CreatedAt:                               wireNullTime(wireCreated),
		UpdatedAt:                               wireNullTime(wireUpdated),
		ClientIdentifier:                        "web-app",
		Description:                             "the web app",
		WebsiteURL:                              "https://app.example",
		DisplayName:                             "Web App",
		Enabled:                                 true,
		ConsentRequired:                         true,
		ShowLogo:                                true,
		ShowDisplayName:                         true,
		ShowWebsiteURL:                          true,
		AuthorizationCodeEnabled:                true,
		PKCERequired:                            &pkceRequired,
		ResourceOwnerPasswordCredentialsEnabled: &ropcEnabled,
		TokenExpirationInSeconds:                300,
		RefreshTokenOfflineIdleTimeoutInSeconds: 3600,
		RefreshTokenOfflineMaxLifetimeInSeconds: 86400,
		IncludeOpenIDConnectClaimsInAccessToken: "on",
		IncludeOpenIDConnectClaimsInIdToken:     "off",
		DefaultAcrLevel:                         models.AcrLevel1,
		RedirectURIs: []models.RedirectURI{{
			Id:        1,
			CreatedAt: wireNullTime(wireCreated),
			URI:       "https://app.example/cb",
			ClientId:  3,
		}},
		// CreatedAt left NULL on purpose: it is the nested column that used to
		// reach the wire as a two-field object and now reads null.
		WebOrigins: []models.WebOrigin{{
			Id:       2,
			Origin:   "https://app.example",
			ClientId: 3,
		}},
	}

	// clientScalars is everything between the identifier and the two collections.
	// Split out so the nil-collection row below can reuse it with a different
	// clientIdentifier without restating twenty-odd keys.
	clientScalars := func(identifier string, systemLevel bool) string {
		scalars := `"clientIdentifier":"` + identifier + `","description":"the web app",` +
			`"websiteUrl":"https://app.example","displayName":"Web App","enabled":true,` +
			`"consentRequired":true,"createdViaDcr":false,"showLogo":true,"showDisplayName":true,` +
			`"showDescription":false,"showWebsiteUrl":true,"isPublic":false,"isSystemLevelClient":`
		if systemLevel {
			scalars += `true`
		} else {
			scalars += `false`
		}
		return scalars + `,"authorizationCodeEnabled":true,"clientCredentialsEnabled":false,` +
			`"pkceRequired":true,"implicitGrantEnabled":null,` +
			`"resourceOwnerPasswordCredentialsEnabled":false,"tokenExpirationInSeconds":300,` +
			`"refreshTokenOfflineIdleTimeoutInSeconds":3600,` +
			`"refreshTokenOfflineMaxLifetimeInSeconds":86400,` +
			`"includeOpenIDConnectClaimsInAccessToken":"on",` +
			`"includeOpenIDConnectClaimsInIdToken":"off","defaultAcrLevel":"urn:goiabada:level1"`
	}

	systemLevel := *client
	systemLevel.ClientIdentifier = constants.AdminConsoleClientIdentifier
	systemLevel.RedirectURIs = nil
	systemLevel.WebOrigins = nil

	runWireCases(t, []wireCase{
		{
			// clientSecret is absent, not empty: the mapper never sets it and the
			// tag is omitempty, so only the detail handler that decrypts it puts
			// it on the wire.
			name:  "populated, with the nested redirect URI and web origin DTOs",
			value: ToClientResponse(client),
			literal: `{"id":3,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				clientScalars("web-app", false) +
				`,"redirectURIs":[` + wireRedirectURIJSON + `],"webOrigins":[` +
				wireWebOriginJSON + `]}`,
		},
		{
			name:  "nil collections, and a system-level client",
			value: ToClientResponse(&systemLevel),
			literal: `{"id":3,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				clientScalars(constants.AdminConsoleClientIdentifier, true) +
				`,"redirectURIs":null,"webOrigins":null}`,
		},
	})
}

// -----------------------------------------------------------------------------
// The list mappers, and the paginated wrappers
// -----------------------------------------------------------------------------

// TestWireJSON_ListMapperNilShapes pins what a nil slice becomes on the wire.
// mapping_test.go's TestListMappers_NilSliceBehaviorDiffersByType owns the same
// split at the Go level; this owns it as bytes, because null and [] are a
// difference a consumer has to write code for and neither spelling is recorded
// anywhere else.
func TestWireJSON_ListMapperNilShapes(t *testing.T) {
	runWireCases(t, []wireCase{
		{name: "ToGroupResponses", value: ToGroupResponses(nil, nil), literal: `[]`},
		{name: "ToClientResponses", value: ToClientResponses(nil), literal: `[]`},
		{name: "ToUserResponses", value: ToUserResponses(nil), literal: `null`},
		{name: "ToSessionOwnerResponses", value: ToSessionOwnerResponses(nil), literal: `null`},
		{name: "ToUserAttributeResponses", value: ToUserAttributeResponses(nil), literal: `null`},
		{name: "ToGroupAttributeResponses", value: ToGroupAttributeResponses(nil), literal: `null`},
		{name: "ToUserConsentResponses", value: ToUserConsentResponses(nil), literal: `null`},
		{name: "ToPermissionResponses", value: ToPermissionResponses(nil), literal: `null`},
		{name: "ToResourceResponses", value: ToResourceResponses(nil), literal: `null`},
	})
}

// The client sessions envelope, which is the only session list that spans users and so the
// only one that names who each session belongs to. Two things are pinned byte for byte.
//
// The users element's exact key set, which is decision 12 of #373: this endpoint is reached
// with the clients scopes alone -- admin-read, manage-clients or manage -- while every users
// route needs the users scopes, so the five fields here are what the documented scope split
// allows a clients-only caller to learn about a person. Widening the element back to
// UserResponse would hand it the subject, birth date, phone number, postal address, locale and
// otpEnabled of everyone holding a live session on a client it manages, and it would fail here
// rather than merely returning more.
//
// And the null that the producer must never emit: both arrays are required and neither is
// nullable, so the nil row below is the shape HandleAPIClientSessionsGet is written to avoid on
// an empty page. The integration tier reads the raw bytes of that page, because a decode into
// this struct cannot tell [] from null.
func TestWireJSON_ClientSessionsEnvelope(t *testing.T) {
	session := *ToUserSessionDetailResponse(&models.UserSession{
		Id: 21, SessionIdentifier: "b1c2d3", UserId: 7,
	}, "")
	sessionFields := `"id":21,"createdAt":null,"updatedAt":null,"sessionIdentifier":"b1c2d3",` +
		`"started":null,"lastAccessed":null,"authMethods":"","acrLevel":"","authTime":null,` +
		`"ipAddress":"","deviceName":"","deviceType":"","deviceOS":"","userAgent":"","userId":7,` +
		`"isCurrent":false,"clientIdentifiers":[]`

	runWireCases(t, []wireCase{
		{
			name: "GetClientSessionsResponse, populated",
			value: api.GetClientSessionsResponse{
				Sessions: []api.UserSessionDetailResponse{session},
				Users: ToSessionOwnerResponses([]models.User{{
					Id:           7,
					Email:        "jane@example.com",
					GivenName:    "Jane",
					MiddleName:   "Q",
					FamilyName:   "Doe",
					Subject:      "0f5a1f3e-6d8a-4f6b-9a1e-2c3d4e5f6a7b",
					Username:     "jdoe",
					PhoneNumber:  "555-0100",
					AddressLine1: "1 Somewhere Street",
					OTPEnabled:   true,
				}}),
			},
			literal: `{"sessions":[{` + sessionFields + `}],` +
				`"users":[{"id":7,"email":"jane@example.com","givenName":"Jane",` +
				`"middleName":"Q","familyName":"Doe"}]}`,
		},
		{
			// What an empty page must not look like. Both fields are required arrays in the
			// spec, and a nil slice reaches the wire as null, which is not [] to a generated
			// client: it is a value its type cannot hold.
			name:    "GetClientSessionsResponse, nil slices are null",
			value:   api.GetClientSessionsResponse{},
			literal: `{"sessions":null,"users":null}`,
		},
		{
			name: "GetClientSessionsResponse, an empty page",
			value: api.GetClientSessionsResponse{
				Sessions: []api.UserSessionDetailResponse{},
				Users:    []api.SessionOwnerResponse{},
			},
			literal: `{"sessions":[],"users":[]}`,
		},
	})
}

// TestWireJSON_AuditLogFamily is the only thing that sees decision 11 of #373:
// AuditLogResponse.CreatedAt was a string the handler filled by calling
// Format("2006-01-02T15:04:05Z07:00") on the model's instant, and is a time.Time
// now, so the console can localize a date instead of parsing one. That retype is
// invisible to every other test in the tree -- the handler still compiles, the
// integration test still decodes -- and it is invisible precisely because
// encoding/json marshals a time.Time as RFC3339, which is what the hand-rolled
// layout spelled out. The literal below is what says so, and what fails if the
// field is ever retyped again or given a custom marshaller.
//
// The one difference from the string era is deliberate: the hand-rolled layout
// had no fractional seconds and truncated them, where the marshaller emits
// whatever the instant carries. The second case is that, written down.
func TestWireJSON_AuditLogFamily(t *testing.T) {
	entry := api.AuditLogResponse{
		Id: 1, CreatedAt: wireCreated, AuditEvent: "user_login",
		Details: `{"email":"alice@example.com"}`, RequestId: "host/Ppg6bHPK5f-000012",
	}
	entryJSON := `{"id":1,"createdAt":"2026-09-16T10:00:00Z","auditEvent":"user_login",` +
		`"details":"{\"email\":\"alice@example.com\"}","requestId":"host/Ppg6bHPK5f-000012"}`

	runWireCases(t, []wireCase{
		{
			name:    "AuditLogResponse",
			value:   entry,
			literal: entryJSON,
		},
		{
			// createdAt is required and not nullable in the schema, which a non-pointer
			// time.Time satisfies: there is no shape of this response carrying a null date.
			// A sub-second instant keeps its precision, where the format it replaced dropped it.
			name: "AuditLogResponse, sub-second precision survives",
			value: api.AuditLogResponse{
				Id: 2, CreatedAt: wireCreated.Add(1500 * time.Millisecond), AuditEvent: "user_login",
			},
			literal: `{"id":2,"createdAt":"2026-09-16T10:00:01.5Z","auditEvent":"user_login",` +
				`"details":"","requestId":""}`,
		},
		{
			name: "GetAuditLogsResponse",
			value: api.GetAuditLogsResponse{
				AuditLogs: []api.AuditLogResponse{entry},
				Total:     73, Page: 4, Size: 20,
			},
			literal: `{"auditLogs":[` + entryJSON + `],"total":73,"page":4,"size":20}`,
		},
	})
}

// TestWireJSON_PaginatedWrappers covers the wrappers that carry a mapped family.
// The last three embed their member anonymously, so its keys flatten in beside
// the annotation rather than nesting under one -- a shape nothing else pins, and
// one that moves with every field the member type gains or loses.
//
// GetAuditLogsResponse is paginated too and is covered by the case above rather
// than here: it carries no mapped family, so what is worth pinning about it is
// its member's timestamp.
func TestWireJSON_PaginatedWrappers(t *testing.T) {
	bareUser := ToUserResponse(&models.User{Id: 7})
	bareUserFields := wireBareUserFields()

	group := wireGroupModel()

	runWireCases(t, []wireCase{
		{
			name: "SearchUsersResponse",
			value: api.SearchUsersResponse{
				Users: ToUserResponses([]models.User{{Id: 7}}),
				Total: 1, Page: 1, Size: 10, Query: "ali",
			},
			literal: `{"users":[{` + bareUserFields + `}],"total":1,"page":1,"size":10,"query":"ali"}`,
		},
		{
			name: "GetGroupMembersResponse",
			value: api.GetGroupMembersResponse{
				Members: ToUserResponses([]models.User{{Id: 7}}),
				Total:   1, Page: 1, Size: 10,
			},
			literal: `{"members":[{` + bareUserFields + `}],"total":1,"page":1,"size":10}`,
		},
		{
			name: "GetUsersByPermissionResponse",
			value: api.GetUsersByPermissionResponse{
				Users: ToUserResponses([]models.User{{Id: 7}}),
				Total: 1, Page: 1, Size: 10,
			},
			literal: `{"users":[{` + bareUserFields + `}],"total":1,"page":1,"size":10}`,
		},
		{
			name: "SearchUsersWithPermissionAnnotationResponse",
			value: api.SearchUsersWithPermissionAnnotationResponse{
				Users: []api.UserWithPermissionResponse{{UserResponse: *bareUser, HasPermission: true}},
				Total: 1, Page: 1, Size: 10, Query: "ali",
			},
			literal: `{"users":[{` + bareUserFields + `,"hasPermission":true}],` +
				`"total":1,"page":1,"size":10,"query":"ali"}`,
		},
		{
			name: "SearchUsersWithGroupAnnotationResponse",
			value: api.SearchUsersWithGroupAnnotationResponse{
				Users: []api.UserWithGroupMembershipResponse{{UserResponse: *bareUser, InGroup: false}},
				Total: 1, Page: 1, Size: 10, Query: "ali",
			},
			literal: `{"users":[{` + bareUserFields + `,"inGroup":false}],` +
				`"total":1,"page":1,"size":10,"query":"ali"}`,
		},
		{
			name: "SearchGroupsWithPermissionAnnotationResponse",
			value: api.SearchGroupsWithPermissionAnnotationResponse{
				Groups: []api.GroupWithPermissionResponse{
					{GroupResponse: *ToGroupResponse(&group, 3), HasPermission: true},
				},
				Total: 1, Page: 1, Size: 10,
			},
			literal: `{"groups":[{` + wireGroupResponseFields + `,"hasPermission":true}],` +
				`"total":1,"page":1,"size":10}`,
		},
	})
}
