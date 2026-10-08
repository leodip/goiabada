package userclaims

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/guard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// idTokenMapper is the shape /userinfo and the ID token share: the ID token's include flag and a
// base URL the assertions can name. The updated_at gate is per test, since that is one of the
// three things the two callers disagree about.
func idTokenMapper(db Database) Mapper {
	return Mapper{Database: db, BaseURL: "http://localhost:8081", Inclusion: InclusionIdToken}
}

// TestAddOpenIDConnectClaims is the table that came with the code from
// issuance/token_issuer_test.go, where it drove the private addOpenIdConnectClaimsFromUser. Its
// three non-profile rows carried updated_at until the gate became the profile scope: that was
// issuance's "anything beyond a lone openid" rule, and it put a profile claim in a response that
// had not been granted the profile scope.
func TestAddOpenIDConnectClaims(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	mapper := idTokenMapper(mockDB)
	now := time.Now().UTC()

	// Set up mock for profile picture check - it will be called for tests with profile scope
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything).Return(false, nil).Maybe()

	testCases := []struct {
		name     string
		user     *record.User
		scopes   []string
		expected jwt.MapClaims
	}{
		{
			name: "Full scope",
			user: &record.User{
				Email:               "test@example.com",
				EmailVerified:       true,
				Username:            "testuser",
				GivenName:           "Test",
				MiddleName:          "Middle",
				FamilyName:          "User",
				Nickname:            "Testy",
				Website:             "https://test.com",
				Gender:              "male",
				BirthDate:           sql.NullTime{Time: time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true},
				ZoneInfo:            "Europe/London",
				Locale:              "en-GB",
				PhoneNumber:         "+1234567890",
				PhoneNumberVerified: true,
				AddressLine1:        "123 Test St",
				AddressLine2:        "Apt 4",
				AddressLocality:     "Testville",
				AddressRegion:       "Testshire",
				AddressPostalCode:   "TE1 2ST",
				AddressCountry:      "Testland",
				UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
			},
			scopes: []string{"openid", "profile", "email", "address", "phone"},
			expected: jwt.MapClaims{
				"name":                  "Test Middle User",
				"given_name":            "Test",
				"middle_name":           "Middle",
				"family_name":           "User",
				"nickname":              "Testy",
				"preferred_username":    "testuser",
				"profile":               "http://localhost:8081/account/profile",
				"website":               "https://test.com",
				"gender":                "male",
				"birthdate":             "1990-01-01",
				"zoneinfo":              "Europe/London",
				"locale":                "en-GB",
				"email":                 "test@example.com",
				"email_verified":        true,
				"phone_number":          "+1234567890",
				"phone_number_verified": true,
				"updated_at":            now.Add(-1 * time.Hour).Unix(),
			},
		},
		{
			name: "Minimal scope",
			user: &record.User{
				Email:     "minimal@example.com",
				UpdatedAt: sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
			},
			scopes:   []string{"openid"},
			expected: jwt.MapClaims{},
		},
		{
			name: "Profile scope only",
			user: &record.User{
				Username:   "profileuser",
				GivenName:  "Profile",
				FamilyName: "User",
				UpdatedAt:  sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
			},
			scopes: []string{"openid", "profile"},
			expected: jwt.MapClaims{
				"name":               "Profile User",
				"given_name":         "Profile",
				"family_name":        "User",
				"preferred_username": "profileuser",
				"profile":            "http://localhost:8081/account/profile",
				"updated_at":         now.Add(-1 * time.Hour).Unix(),
			},
		},
		{
			name: "Email scope only",
			user: &record.User{
				Email:         "email@example.com",
				EmailVerified: true,
				UpdatedAt:     sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
			},
			scopes: []string{"openid", "email"},
			expected: jwt.MapClaims{
				"email":          "email@example.com",
				"email_verified": true,
			},
		},
		{
			name: "Address scope only",
			user: &record.User{
				AddressLine1:      "456 Address St",
				AddressLocality:   "Addressville",
				AddressRegion:     "Addressshire",
				AddressPostalCode: "AD1 3SS",
				AddressCountry:    "Addressland",
				UpdatedAt:         sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
			},
			scopes:   []string{"openid", "address"},
			expected: jwt.MapClaims{},
		},
		{
			name: "Phone scope only",
			user: &record.User{
				PhoneNumber:         "+9876543210",
				PhoneNumberVerified: false,
				UpdatedAt:           sql.NullTime{Time: now.Add(-1 * time.Hour), Valid: true},
			},
			scopes: []string{"openid", "phone"},
			expected: jwt.MapClaims{
				"phone_number":          "+9876543210",
				"phone_number_verified": false,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			claims := make(jwt.MapClaims)

			mapper.AddOpenIDConnectClaims(context.Background(), nil, claims, tc.user, tc.scopes)

			for key, expectedValue := range tc.expected {
				assert.Equal(t, expectedValue, claims[key], "Mismatch for claim: %s", key)
			}

			if slices.Contains(tc.scopes, "profile") {
				assert.NotZero(t, claims["updated_at"], "updated_at rides with the profile scope")
			}

			// Check for address claim separately
			if slices.Contains(tc.scopes, "address") {
				address, ok := claims["address"].(map[string]string)
				assert.True(t, ok, "Address claim should be of type map[string]string")
				if ok {
					assert.Equal(t, tc.user.AddressLine1+"\r\n"+tc.user.AddressLine2, address["street_address"])
					assert.Equal(t, tc.user.AddressLocality, address["locality"])
					assert.Equal(t, tc.user.AddressRegion, address["region"])
					assert.Equal(t, tc.user.AddressPostalCode, address["postal_code"])
					assert.Equal(t, tc.user.AddressCountry, address["country"])
					expectedFormatted := strings.TrimSpace(tc.user.AddressLine1 + "\r\n" + tc.user.AddressLine2 + "\r\n" +
						tc.user.AddressLocality + "\r\n" + tc.user.AddressRegion + "\r\n" +
						tc.user.AddressPostalCode + "\r\n" + tc.user.AddressCountry)
					assert.Equal(t, expectedFormatted, address["formatted"])
				}
			}

			for key := range claims {
				if key != "address" {
					_, expected := tc.expected[key]
					assert.True(t, expected, "Unexpected claim: %s", key)
				}
			}
		})
	}
}

// TestAddOpenIDConnectClaims_UpdatedAtRidesWithTheProfileScope is the one rule, where there were
// two gates. updated_at is a profile-scope claim: OIDC Core 5.4 lists it with name, family_name,
// birthdate and the rest, and this repository's own documentation has always assigned it there
// (site/src/content/docs/concepts/scopes.mdx, reference/endpoints/userinfo.mdx). /userinfo
// already gated on profile; issuance emitted it for any scope but a lone openid, so "openid email"
// carried it with no profile scope granted.
//
// The empty-element row is the scope claim a token can be missing entirely, which strings.Split
// turns into []string{""}. It used to open issuance's gate, since one element that is not "openid"
// satisfied it.
func TestAddOpenIDConnectClaims_UpdatedAtRidesWithTheProfileScope(t *testing.T) {
	updatedAt := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		scopes  []string
		carries bool
	}{
		{"openid alone", []string{"openid"}, false},
		{"openid email", []string{"openid", "email"}, false},
		{"openid address", []string{"openid", "address"}, false},
		{"openid phone", []string{"openid", "phone"}, false},
		{"openid profile", []string{"openid", "profile"}, true},
		{"profile alone", []string{"profile"}, true},
		{"no scope at all", []string{}, false},
		{"the empty element a missing scope claim splits into", []string{""}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user := &record.User{Id: 7, Email: "a@example.com",
				UpdatedAt: sql.NullTime{Time: updatedAt, Valid: true}}
			mockDB := datamocks.NewDatabase(t)
			if slices.Contains(test.scopes, "profile") {
				mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, int64(7)).
					Return(false, nil).Once()
			}

			claims := jwt.MapClaims{}
			idTokenMapper(mockDB).AddOpenIDConnectClaims(context.Background(), nil, claims, user, test.scopes)

			if test.carries {
				assert.Equal(t, updatedAt.Unix(), claims["updated_at"])
			} else {
				assert.NotContains(t, claims, "updated_at")
			}
		})
	}
}

// TestAddOpenIDConnectClaims_UpdatedAtDoesNotDependOnTheTokenType is the divergence's other half,
// refused at the mapper: the access token's mapper and the ID token's differ in which include flag
// filters groups and attributes, and in nothing else. A gate that reads the token type, or a scope
// slice one caller has extended and the other has not, would show up here.
func TestAddOpenIDConnectClaims_UpdatedAtDoesNotDependOnTheTokenType(t *testing.T) {
	updatedAt := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	user := &record.User{Id: 7, Email: "a@example.com", UpdatedAt: sql.NullTime{Time: updatedAt, Valid: true}}

	for _, inclusion := range []Inclusion{InclusionIdToken, InclusionAccessToken} {
		mapper := Mapper{Database: datamocks.NewDatabase(t), BaseURL: "http://localhost:8081",
			Inclusion: inclusion}

		claims := jwt.MapClaims{}
		mapper.AddOpenIDConnectClaims(context.Background(), nil, claims, user, []string{"openid", "email"})
		assert.NotContains(t, claims, "updated_at",
			"no profile scope, so neither token type carries the claim")
	}
}

// TestAddOpenIDConnectClaims_CarriesTheCallersContext is #386 seam 4 at the package the read
// moved into: the picture lookup is the one database call claim construction makes, and it runs
// under the context the caller handed in, not a fresh one.
func TestAddOpenIDConnectClaims_CarriesTheCallersContext(t *testing.T) {
	type marker struct{}
	ctx := context.WithValue(context.Background(), marker{}, "the caller's own")
	callersContext := mock.MatchedBy(func(got context.Context) bool {
		return got.Value(marker{}) == "the caller's own"
	})

	user := &record.User{Id: 42, Subject: "sub-42", GivenName: "Ada", FamilyName: "Lovelace"}

	t.Run("the profile scope reads the picture flag under the caller's context", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("UserHasProfilePicture", callersContext, mock.Anything, int64(42)).Return(true, nil).Once()

		claims := jwt.MapClaims{}
		idTokenMapper(mockDB).
			AddOpenIDConnectClaims(ctx, nil, claims, user, []string{"openid", "profile"})

		assert.Equal(t, "http://localhost:8081/userinfo/picture/sub-42", claims["picture"])
		mockDB.AssertExpectations(t)
	})

	t.Run("without the profile scope the port is not reached", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)

		claims := jwt.MapClaims{}
		idTokenMapper(mockDB).
			AddOpenIDConnectClaims(ctx, nil, claims, user, []string{"openid", "email"})

		assert.NotContains(t, claims, "picture")
		mockDB.AssertNotCalled(t, "UserHasProfilePicture", mock.Anything, mock.Anything, mock.Anything)
	})
}

// TestAddOpenIDConnectClaims_ReadsThePictureOnTheTransactionItIsHanded is #437's: an issuance that
// holds a transaction hands it here, and the picture lookup is made on it. The lookup's failure is
// swallowed, so a read made on nil while the caller holds sqlitedb's one connection waits for that
// connection until the context expires and the picture claim is dropped without an error; only the
// claim's absence would show it. The expectations name the transaction, so the read on nil matches
// nothing and the case fails, and the nil case is the other half: /userinfo runs in no transaction
// and reads on none.
func TestAddOpenIDConnectClaims_ReadsThePictureOnTheTransactionItIsHanded(t *testing.T) {
	user := &record.User{Id: 42, Subject: "sub-42", GivenName: "Ada"}

	t.Run("the transaction it is handed", func(t *testing.T) {
		tx := &sql.Tx{}
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("UserHasProfilePicture", mock.Anything, tx, int64(42)).Return(true, nil).Once()

		claims := jwt.MapClaims{}
		idTokenMapper(mockDB).AddOpenIDConnectClaims(context.Background(), tx, claims, user, []string{"openid", "profile"})

		assert.Equal(t, "http://localhost:8081/userinfo/picture/sub-42", claims["picture"])
		mockDB.AssertExpectations(t)
	})

	t.Run("no transaction, when it is handed none", func(t *testing.T) {
		mockDB := datamocks.NewDatabase(t)
		mockDB.On("UserHasProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(42)).Return(true, nil).Once()

		claims := jwt.MapClaims{}
		idTokenMapper(mockDB).AddOpenIDConnectClaims(context.Background(), nil, claims, user, []string{"openid", "profile"})

		assert.Equal(t, "http://localhost:8081/userinfo/picture/sub-42", claims["picture"])
		mockDB.AssertExpectations(t)
	})
}

// TestAddOpenIDConnectClaims_PictureFailureLeavesTheRestStanding pins the arm both callers wrote
// before this package and neither logged: a failed lookup omits the claim and nothing else.
func TestAddOpenIDConnectClaims_PictureFailureLeavesTheRestStanding(t *testing.T) {
	mockDB := datamocks.NewDatabase(t)
	mockDB.On("UserHasProfilePicture", mock.Anything, mock.Anything, int64(9)).
		Return(false, assert.AnError).Once()

	user := &record.User{Id: 9, Subject: "sub-9", GivenName: "Ada"}
	claims := jwt.MapClaims{}
	idTokenMapper(mockDB).
		AddOpenIDConnectClaims(context.Background(), nil, claims, user, []string{"openid", "profile"})

	assert.NotContains(t, claims, "picture")
	assert.Equal(t, "Ada", claims["given_name"])
	assert.Equal(t, "http://localhost:8081/account/profile", claims["profile"])
}

// groupsAndAttributesUser is one user whose group, user attribute and group attribute each carry
// one include flag and not the other, so a mapper reading the wrong flag cannot pass.
func groupsAndAttributesUser() *record.User {
	return &record.User{
		Id: 1,
		Groups: []record.Group{
			{
				GroupIdentifier:  "id-token-group",
				IncludeInIdToken: true, IncludeInAccessToken: false,
				Attributes: []record.GroupAttribute{
					{Key: "group-id-attr", Value: "id", IncludeInIdToken: true, IncludeInAccessToken: false},
					{Key: "group-access-attr", Value: "access", IncludeInIdToken: false, IncludeInAccessToken: true},
				},
			},
			{
				GroupIdentifier:  "access-token-group",
				IncludeInIdToken: false, IncludeInAccessToken: true,
			},
		},
		Attributes: []record.UserAttribute{
			{Key: "user-id-attr", Value: "id", IncludeInIdToken: true, IncludeInAccessToken: false},
			{Key: "user-access-attr", Value: "access", IncludeInIdToken: false, IncludeInAccessToken: true},
		},
	}
}

// TestGroupAndAttributeClaimsFollowTheInclusion holds the third divergence: the same user and the
// same scopes produce different group and attribute claims per token type, which is why Inclusion
// is an input. /userinfo and the ID token read the same flag; only the access token differs.
func TestGroupAndAttributeClaimsFollowTheInclusion(t *testing.T) {
	scopes := []string{"openid", "groups", "attributes"}
	user := groupsAndAttributesUser()

	t.Run("the ID token's flag", func(t *testing.T) {
		claims := jwt.MapClaims{}
		mapper := Mapper{Inclusion: InclusionIdToken}
		mapper.AddGroupClaims(claims, user, scopes)
		mapper.AddAttributeClaims(claims, user, scopes)

		assert.Equal(t, []string{"id-token-group"}, claims["groups"])
		assert.Equal(t, map[string]string{"user-id-attr": "id", "group-id-attr": "id"}, claims["attributes"])
	})

	t.Run("the access token's flag", func(t *testing.T) {
		claims := jwt.MapClaims{}
		mapper := Mapper{Inclusion: InclusionAccessToken}
		mapper.AddGroupClaims(claims, user, scopes)
		mapper.AddAttributeClaims(claims, user, scopes)

		assert.Equal(t, []string{"access-token-group"}, claims["groups"])
		assert.Equal(t, map[string]string{"user-access-attr": "access", "group-access-attr": "access"}, claims["attributes"])
	})

	t.Run("the zero value is the ID token's flag", func(t *testing.T) {
		claims := jwt.MapClaims{}
		var mapper Mapper
		mapper.AddGroupClaims(claims, user, scopes)
		mapper.AddAttributeClaims(claims, user, scopes)

		assert.Equal(t, []string{"id-token-group"}, claims["groups"])
		assert.Equal(t, map[string]string{"user-id-attr": "id", "group-id-attr": "id"}, claims["attributes"])
	})
}

// TestGroupAndAttributeClaimsWithoutTheirScopes: the two blocks are gated on their own scopes, and
// a scope whose filter matches nothing writes no claim at all rather than an empty array or map.
// Both callers relied on that before the move.
func TestGroupAndAttributeClaimsWithoutTheirScopes(t *testing.T) {
	user := groupsAndAttributesUser()

	t.Run("no groups or attributes scope", func(t *testing.T) {
		claims := jwt.MapClaims{}
		mapper := Mapper{Inclusion: InclusionIdToken}
		mapper.AddGroupClaims(claims, user, []string{"openid", "profile"})
		mapper.AddAttributeClaims(claims, user, []string{"openid", "profile"})

		assert.NotContains(t, claims, "groups")
		assert.NotContains(t, claims, "attributes")
	})

	t.Run("scoped but nothing carries the flag", func(t *testing.T) {
		none := &record.User{
			Id:         2,
			Groups:     []record.Group{{GroupIdentifier: "hidden", IncludeInIdToken: false}},
			Attributes: []record.UserAttribute{{Key: "hidden", Value: "x", IncludeInIdToken: false}},
		}

		claims := jwt.MapClaims{}
		mapper := Mapper{Inclusion: InclusionIdToken}
		mapper.AddGroupClaims(claims, none, []string{"groups", "attributes"})
		mapper.AddAttributeClaims(claims, none, []string{"groups", "attributes"})

		assert.NotContains(t, claims, "groups")
		assert.NotContains(t, claims, "attributes")
	})
}

// TestAttributeClaims_GroupPassWinsACollision pins the order both callers wrote: a group
// attribute sharing a key with a user attribute overwrites it, because the group pass runs
// second.
func TestAttributeClaims_GroupPassWinsACollision(t *testing.T) {
	user := &record.User{
		Id:         3,
		Attributes: []record.UserAttribute{{Key: "shared", Value: "from the user", IncludeInIdToken: true}},
		Groups: []record.Group{{
			GroupIdentifier: "g",
			Attributes:      []record.GroupAttribute{{Key: "shared", Value: "from the group", IncludeInIdToken: true}},
		}},
	}

	claims := jwt.MapClaims{}
	Mapper{Inclusion: InclusionIdToken}.AddAttributeClaims(claims, user, []string{"attributes"})

	assert.Equal(t, map[string]string{"shared": "from the group"}, claims["attributes"])
}

// TestAddClaimIfNotEmpty came with the helper from issuance/token_issuer_test.go, where it drove
// TokenIssuer.addClaimIfNotEmpty (#387).
func TestAddClaimIfNotEmpty(t *testing.T) {
	testCases := []struct {
		name           string
		claims         jwt.MapClaims
		claimName      string
		claimValue     string
		expectedClaims jwt.MapClaims
	}{
		{
			name:           "Non-empty claim",
			claims:         jwt.MapClaims{},
			claimName:      "test_claim",
			claimValue:     "test_value",
			expectedClaims: jwt.MapClaims{"test_claim": "test_value"},
		},
		{
			name:           "Empty claim",
			claims:         jwt.MapClaims{},
			claimName:      "empty_claim",
			claimValue:     "",
			expectedClaims: jwt.MapClaims{},
		},
		{
			name:           "Whitespace-only claim",
			claims:         jwt.MapClaims{},
			claimName:      "whitespace_claim",
			claimValue:     "   ",
			expectedClaims: jwt.MapClaims{},
		},
		{
			name:           "Claim with leading/trailing whitespace",
			claims:         jwt.MapClaims{},
			claimName:      "trimmed_claim",
			claimValue:     "  trimmed_value  ",
			expectedClaims: jwt.MapClaims{"trimmed_claim": "  trimmed_value  "},
		},
		{
			name:           "Adding to existing claims",
			claims:         jwt.MapClaims{"existing_claim": "existing_value"},
			claimName:      "new_claim",
			claimValue:     "new_value",
			expectedClaims: jwt.MapClaims{"existing_claim": "existing_value", "new_claim": "new_value"},
		},
		{
			name:           "Overwriting existing claim",
			claims:         jwt.MapClaims{"overwrite_claim": "old_value"},
			claimName:      "overwrite_claim",
			claimValue:     "new_value",
			expectedClaims: jwt.MapClaims{"overwrite_claim": "new_value"},
		},
		{
			name:           "Unicode claim value",
			claims:         jwt.MapClaims{},
			claimName:      "unicode_claim",
			claimValue:     "こんにちは",
			expectedClaims: jwt.MapClaims{"unicode_claim": "こんにちは"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addClaimIfNotEmpty(tc.claims, tc.claimName, tc.claimValue)

			assert.Equal(t, tc.expectedClaims, tc.claims, "Claims do not match expected values")

			if len(strings.TrimSpace(tc.claimValue)) > 0 {
				assert.Contains(t, tc.claims, tc.claimName, "Claim should be added")
				assert.Equal(t, tc.claimValue, tc.claims[tc.claimName], "Claim value should match")
			} else {
				assert.NotContains(t, tc.claims, tc.claimName, "Claim should not be added")
			}
		})
	}
}

// TestHasAddress came with the predicate from record/user_test.go (#387).
func TestHasAddress(t *testing.T) {
	tests := []struct {
		name     string
		user     record.User
		expected bool
	}{
		{"Empty address", record.User{}, false},
		{"Only AddressLine1", record.User{AddressLine1: "123 Main St"}, true},
		{"Only AddressLine2", record.User{AddressLine2: "Apt 4B"}, true},
		{"Only AddressLocality", record.User{AddressLocality: "Springfield"}, true},
		{"Only AddressRegion", record.User{AddressRegion: "IL"}, true},
		{"Only AddressPostalCode", record.User{AddressPostalCode: "12345"}, true},
		{"Only AddressCountry", record.User{AddressCountry: "USA"}, true},
		{"Full address", record.User{
			AddressLine1:      "123 Main St",
			AddressLine2:      "Apt 4B",
			AddressLocality:   "Springfield",
			AddressRegion:     "IL",
			AddressPostalCode: "12345",
			AddressCountry:    "USA",
		}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.user
			assert.Equal(t, tt.expected, hasAddress(&user))
		})
	}
}

// TestAddressClaim came with the builder from record/user_test.go, where it was
// TestUser_GetAddressClaim (#387).
func TestAddressClaim(t *testing.T) {
	tests := []struct {
		name     string
		user     record.User
		expected map[string]string
	}{
		{"Empty address", record.User{}, map[string]string{}},
		{"Full address", record.User{
			AddressLine1:      "123 Main St",
			AddressLine2:      "Apt 4B",
			AddressLocality:   "Springfield",
			AddressRegion:     "IL",
			AddressPostalCode: "12345",
			AddressCountry:    "USA",
		}, map[string]string{
			"street_address": "123 Main St\r\nApt 4B",
			"locality":       "Springfield",
			"region":         "IL",
			"postal_code":    "12345",
			"country":        "USA",
			"formatted":      "123 Main St\r\nApt 4B\r\nSpringfield\r\nIL\r\n12345\r\nUSA",
		}},
		{"Partial address", record.User{
			AddressLine1:    "123 Main St",
			AddressLocality: "Springfield",
			AddressCountry:  "USA",
		}, map[string]string{
			"street_address": "123 Main St\r\n",
			"locality":       "Springfield",
			"country":        "USA",
			"formatted":      "123 Main St\r\n\r\nSpringfield\r\nUSA",
		}},
		{"No country, so no formatted rendering", record.User{
			AddressLine1:    "123 Main St",
			AddressLocality: "Springfield",
		}, map[string]string{
			"street_address": "123 Main St\r\n",
			"locality":       "Springfield",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := tt.user
			result := addressClaim(&user)
			assert.Equal(t, tt.expected, result)

			// Additional check for the "formatted" field
			if formatted, ok := result["formatted"]; ok {
				assert.Equal(t, tt.expected["formatted"], formatted, "Formatted address mismatch")
			}
		})
	}
}

// TestAddOpenIDConnectClaims_AddressScopeWithoutAnAddress: the address claim is gated on the
// predicate as well as the scope, so a user with no address columns set carries no address member
// rather than an empty object.
func TestAddOpenIDConnectClaims_AddressScopeWithoutAnAddress(t *testing.T) {
	claims := jwt.MapClaims{}
	idTokenMapper(datamocks.NewDatabase(t)).
		AddOpenIDConnectClaims(context.Background(), nil, claims, &record.User{Id: 4}, []string{"openid", "address"})

	assert.NotContains(t, claims, "address")
}

// The profile claim is the auth server's base URL and /account/profile, a path the auth server
// serves no page at, and Scopes says so rather than calling it the user's account page (#522).
func TestAddOpenIDConnectClaims_TheScopesPageSaysWhereProfilePoints(t *testing.T) {
	db := datamocks.NewDatabase(t)
	db.On("UserHasProfilePicture", mock.Anything, (*sql.Tx)(nil), int64(1)).Return(false, nil)
	claims := jwt.MapClaims{}
	Mapper{Database: db, BaseURL: "https://auth.example.com"}.
		AddOpenIDConnectClaims(context.Background(), nil, claims, &record.User{Id: 1}, []string{"openid", "profile"})
	assert.Equal(t, "https://auth.example.com/account/profile", claims["profile"])

	const page = "site/src/content/docs/concepts/scopes.mdx"
	body, err := os.ReadFile(filepath.Join(filepath.Dir(guard.SourceRoot(t)), page))
	require.NoError(t, err)
	assert.Containsf(t, string(body),
		"`profile` is the auth server's base URL followed by `/account/profile`, where the auth server has no page",
		"%s says where the profile claim points", page)
}
