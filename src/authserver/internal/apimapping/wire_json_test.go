package apimapping

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
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
// These literals record the bytes as they are today, capitalised nested keys
// and {"Time":...,"Valid":...} objects included. Several of those shapes are
// defects: models.Group, models.Permission, models.RedirectURI and
// models.WebOrigin carry no json tags, so they reach the wire in Go's
// declaration spelling inside a body whose every other key is lowerCamelCase,
// and a sql.NullTime that is NULL in the database arrives as a two-field object
// rather than as null. #350 replaces them with DTOs. Writing the defect down
// first is what makes that replacement a diff a reviewer reads, and what stops
// any other change moving a shape by accident (#350).
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
// The untagged nested models, named once
//
// Each of these four is a persistence model reaching the wire through a field
// of a response type, which is the whole of what #350 is about. Naming them
// here means the stage that replaces one edits one constant.
// -----------------------------------------------------------------------------

const (
	// wireNullTimeJSON is what a NULL sql.NullTime column becomes on the wire
	// through an untagged model field: an object, never null.
	wireNullTimeJSON = `{"Time":"0001-01-01T00:00:00Z","Valid":false}`

	wireCreatedJSON = `{"Time":"2026-09-16T10:00:00Z","Valid":true}`
	wireUpdatedJSON = `{"Time":"2026-09-16T11:00:00Z","Valid":true}`

	wireGroupModelJSON = `{"Id":2,"CreatedAt":` + wireCreatedJSON + `,"UpdatedAt":` + wireUpdatedJSON +
		`,"GroupIdentifier":"admins","Description":"administrators","Attributes":null,"Permissions":null,` +
		`"IncludeInIdToken":true,"IncludeInAccessToken":false,"MemberCount":3}`

	wireResourceModelJSON = `{"Id":9,"CreatedAt":` + wireCreatedJSON + `,"UpdatedAt":` + wireNullTimeJSON +
		`,"ResourceIdentifier":"backend-svc","Description":"the backend service"}`

	wirePermissionModelJSON = `{"Id":5,"CreatedAt":` + wireCreatedJSON + `,"UpdatedAt":` + wireUpdatedJSON +
		`,"PermissionIdentifier":"read-all","Description":"read everything","ResourceId":9,"Resource":` +
		wireResourceModelJSON + `}`

	wireRedirectURIModelJSON = `{"Id":1,"CreatedAt":` + wireCreatedJSON +
		`,"URI":"https://app.example/cb","ClientId":3}`

	wireWebOriginModelJSON = `{"Id":2,"CreatedAt":` + wireNullTimeJSON +
		`,"Origin":"https://app.example","ClientId":3}`
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
// permission and one attribute loaded. The three collection keys at the end are
// the ones #350 decision 11 removes; the nested objects inside the first two are
// the untagged models named above.
const wirePopulatedUserJSON = `{"id":7,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
	`"enabled":true,"subject":"3b9f1a2c-0000-4000-8000-000000000001","username":"alice","givenName":"Alice",` +
	`"middleName":"Q","familyName":"Smith","nickname":"al","website":"https://alice.example","gender":"female",` +
	`"email":"alice@example.com","emailVerified":true,"zoneInfoCountryName":"Brazil",` +
	`"zoneInfo":"America/Sao_Paulo","locale":"pt-BR","birthDate":"1990-01-02T00:00:00Z",` +
	`"phoneNumberCountryUniqueId":"BRA_55","phoneNumberCountryCallingCode":"55","phoneNumber":"11 99999-0000",` +
	`"phoneNumberVerified":true,"addressLine1":"Rua Um, 100","addressLine2":"apto 2",` +
	`"addressLocality":"Sao Paulo","addressRegion":"SP","addressPostalCode":"01000-000","addressCountry":"BRA",` +
	`"otpEnabled":true,"groups":[` + wireGroupModelJSON + `],"permissions":[` + wirePermissionModelJSON + `],` +
	`"attributes":[` + wireUserAttributeJSON + `]}`

// wireBareUserFields is ToUserResponse over a models.User carrying nothing but
// its id, with no braces and with the three collection keys left to the caller:
// those are the only part of the shape the empty-slice and nil-slice rows
// disagree about. Brace-free so the annotated wrappers further down can show
// how an embedded UserResponse flattens into its container.
func wireBareUserFields(groups, permissions, attributes string) string {
	return `"id":7,"createdAt":null,"updatedAt":null,"enabled":false,"subject":"","username":"",` +
		`"givenName":"","middleName":"","familyName":"","nickname":"","website":"","gender":"","email":"",` +
		`"emailVerified":false,"zoneInfoCountryName":"","zoneInfo":"","locale":"","birthDate":null,` +
		`"phoneNumberCountryUniqueId":"","phoneNumberCountryCallingCode":"","phoneNumber":"",` +
		`"phoneNumberVerified":false,"addressLine1":"","addressLine2":"","addressLocality":"",` +
		`"addressRegion":"","addressPostalCode":"","addressCountry":"","otpEnabled":false,` +
		`"groups":` + groups + `,"permissions":` + permissions + `,"attributes":` + attributes
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
			name:    "populated, with the untagged nested group and permission",
			value:   ToUserResponse(populated),
			literal: wirePopulatedUserJSON,
		},
		{
			// A user loaded without its collections, which is 20 of the 23
			// ToUserResponse call sites: every timestamp is NULL and every
			// collection is absent, so the three keys read null.
			name:    "nil collections and NULL timestamps",
			value:   ToUserResponse(&models.User{Id: 7}),
			literal: "{" + wireBareUserFields("null", "null", "null") + "}",
		},
		{
			name:    "empty collections marshal as [], not null",
			value:   ToUserResponse(empty),
			literal: "{" + wireBareUserFields("[]", "[]", "[]") + "}",
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

func TestWireJSON_UserSessionFamily(t *testing.T) {
	populated := &models.UserSession{
		Id:                21,
		CreatedAt:         wireNullTime(wireCreated),
		UpdatedAt:         wireNullTime(wireUpdated),
		SessionIdentifier: "b1c2d3",
		Started:           wireStarted,
		LastAccessed:      wireTouched,
		AuthMethods:       "pwd otp",
		AcrLevel:          string(enums.AcrLevel2Optional),
		AuthTime:          wireStarted,
		IpAddress:         "203.0.113.7",
		DeviceName:        "Firefox",
		DeviceType:        "Desktop",
		DeviceOS:          "Linux",
		UserAgent:         "Mozilla/5.0",
		UserId:            7,
	}

	// The enhanced form has no mapper: handler_api_users_sessions.go and its two
	// siblings build it inline from a UserSessionResponse plus the derived
	// display fields. So its row pins the declared struct, which is all of it
	// that could move.
	enhanced := api.EnhancedUserSessionResponse{
		Id:                        21,
		CreatedAt:                 &wireCreated,
		UpdatedAt:                 &wireUpdated,
		SessionIdentifier:         "b1c2d3",
		Started:                   &wireStarted,
		LastAccessed:              &wireTouched,
		AuthMethods:               "pwd otp",
		AcrLevel:                  string(enums.AcrLevel2Optional),
		AuthTime:                  &wireStarted,
		IpAddress:                 "203.0.113.7",
		DeviceName:                "Firefox",
		DeviceType:                "Desktop",
		DeviceOS:                  "Linux",
		UserAgent:                 "Mozilla/5.0",
		UserId:                    7,
		StartedAt:                 "16 Sep 2026 09:00",
		DurationSinceStarted:      "3 hours",
		LastAccessedAt:            "16 Sep 2026 09:30",
		DurationSinceLastAccessed: "2 hours",
		IsValid:                   true,
		IsCurrent:                 false,
		ClientIdentifiers:         []string{"admin-console-client"},
	}

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
			name:  "EnhancedUserSessionResponse, populated",
			value: enhanced,
			literal: `{"id":21,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				`"sessionIdentifier":"b1c2d3","started":"2026-09-16T09:00:00Z",` +
				`"lastAccessed":"2026-09-16T09:30:00Z","authMethods":"pwd otp",` +
				`"acrLevel":"urn:goiabada:level2_optional","authTime":"2026-09-16T09:00:00Z",` +
				`"ipAddress":"203.0.113.7","deviceName":"Firefox","deviceType":"Desktop","deviceOS":"Linux",` +
				`"userAgent":"Mozilla/5.0","userId":7,"startedAt":"16 Sep 2026 09:00",` +
				`"durationSinceStarted":"3 hours","lastAccessedAt":"16 Sep 2026 09:30",` +
				`"durationSinceLastAccessed":"2 hours","isValid":true,"isCurrent":false,` +
				`"clientIdentifiers":["admin-console-client"]}`,
		},
		{
			name:  "EnhancedUserSessionResponse, no client identifiers",
			value: api.EnhancedUserSessionResponse{Id: 21, UserId: 7},
			literal: `{"id":21,"createdAt":null,"updatedAt":null,"sessionIdentifier":"","started":null,` +
				`"lastAccessed":null,"authMethods":"","acrLevel":"","authTime":null,"ipAddress":"",` +
				`"deviceName":"","deviceType":"","deviceOS":"","userAgent":"","userId":7,"startedAt":"",` +
				`"durationSinceStarted":"","lastAccessedAt":"","durationSinceLastAccessed":"",` +
				`"isValid":false,"isCurrent":false,"clientIdentifiers":null}`,
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

	const resourceJSON = `{"id":9,"resourceIdentifier":"backend-svc","description":"the backend service"}`

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
			// The auth server's own resource. The admin console asks
			// models.Resource.IsSystemLevelResource() about this one today,
			// because the answer is on no response; #350 decision 10 puts it
			// on this shape, where the row below is what will show it.
			name: "ResourceResponse for the system-level resource",
			value: ToResourceResponse(&models.Resource{
				Id:                 1,
				ResourceIdentifier: constants.AuthServerResourceIdentifier,
				Description:        "Goiabada auth server",
			}),
			literal: `{"id":1,"resourceIdentifier":"authserver","description":"Goiabada auth server"}`,
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
		DefaultAcrLevel:                         enums.AcrLevel1,
		RedirectURIs: []models.RedirectURI{{
			Id:        1,
			CreatedAt: wireNullTime(wireCreated),
			URI:       "https://app.example/cb",
			ClientId:  3,
		}},
		// CreatedAt left NULL on purpose: it is the nested column that reaches
		// the wire as a two-field object rather than as null.
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
			name:  "populated, with the untagged redirect URIs and web origins",
			value: ToClientResponse(client),
			literal: `{"id":3,"createdAt":"2026-09-16T10:00:00Z","updatedAt":"2026-09-16T11:00:00Z",` +
				clientScalars("web-app", false) +
				`,"redirectURIs":[` + wireRedirectURIModelJSON + `],"webOrigins":[` +
				wireWebOriginModelJSON + `]}`,
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
		{name: "ToUserAttributeResponses", value: ToUserAttributeResponses(nil), literal: `null`},
		{name: "ToGroupAttributeResponses", value: ToGroupAttributeResponses(nil), literal: `null`},
		{name: "ToUserConsentResponses", value: ToUserConsentResponses(nil), literal: `null`},
		{name: "ToPermissionResponses", value: ToPermissionResponses(nil), literal: `null`},
		{name: "ToResourceResponses", value: ToResourceResponses(nil), literal: `null`},
	})
}

// TestWireJSON_PaginatedWrappers covers the wrappers that carry a mapped family.
// The last three embed their member anonymously, so its keys flatten in beside
// the annotation rather than nesting under one -- a shape nothing else pins, and
// one that moves with every field the member type gains or loses.
//
// GetAuditLogsResponse is paginated too and is deliberately absent: it carries
// no mapped family and no part of #350 touches it.
func TestWireJSON_PaginatedWrappers(t *testing.T) {
	bareUser := ToUserResponse(&models.User{Id: 7})
	bareUserFields := wireBareUserFields("null", "null", "null")

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
