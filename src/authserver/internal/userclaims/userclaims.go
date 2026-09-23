// Package userclaims owns the one conversion from a stored user row to the OIDC claims a client
// reads: the profile, email, address and phone block, and the group and attribute blocks.
//
// It exists because that conversion was written twice -- once in
// authserver/internal/handlers/handler_userinfo.go and once in
// authserver/internal/issuance/token_issuer.go -- and the two copies had drifted in three places
// that no test and no document named. Building the address claim sat on models.User besides,
// which is a persistence record with no business constructing an OIDC claim (#387 decision 5).
//
// Two of the three divergences are inputs here, not merges. Each is observable on the wire, so
// collapsing one changes what a client receives, which #387 was not permitted to do; #387
// decision 6 pinned all three with tests before this package existed:
//
//   - the base URL the profile and picture claims are built from. /userinfo reads the global
//     configuration, issuance the one injected into TokenIssuer. That is Mapper.BaseURL.
//   - which of a group's or an attribute's two include flags decides. /userinfo reads
//     IncludeInIdToken at all three of its filter sites; issuance reads IncludeInAccessToken in
//     the access token and IncludeInIdToken in the ID token. That is Mapper.Inclusion.
//
// The third was the gate on updated_at, and it is no longer an input: both sites now write the
// claim inside the profile arm. It was a defect rather than a difference two callers wanted.
// /userinfo already gated on profile, which is the scope OIDC Core 5.4 lists updated_at under and
// the scope this repository's own documentation has always assigned it to; issuance wrote it for
// any scope but a lone openid, so a grant of "openid email" carried a profile claim nobody asked
// for. In an access token issuance wrote it always, including for a lone openid, because
// generateAccessTokenCore appends authserver:userinfo to the scope slice for the audience before
// the claim block reads it -- so the same grant produced an access token carrying updated_at and
// an ID token without it, which nothing chose. Emitting it under the profile scope alone is one
// rule for all three sites, and it is the rule the wire documentation already stated.
//
// Staying with the caller: every gate above these ones -- the openid requirement and the
// per-client IncludeOpenIDConnectClaimsInAccessToken / InIdToken settings issuance applies, and
// /userinfo's decision to answer at all -- together with iss, aud, exp, nonce and everything else
// a token carries that is not read off the user row.
//
// Staying on models.User: GetFullName, which also names the user in the emails the auth server
// sends. The birthdate claim's YYYY-MM-DD format has no reader but the claim, so it is written
// here, as the claim construction it is (#424).
//
// Nothing here takes an http.ResponseWriter, a *http.Request, template data or a status code, and
// nothing here imports a handler package.
package userclaims

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/models"
)

// Database is what claim construction needs: the one row behind the picture claim.
//
// Declared here rather than taken whole, following #386: the consumer names the method it calls.
// Both callers already hold a port carrying this method and hand it on unchanged, so neither
// changes which database it reads.
type Database interface {
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)
}

// Inclusion names which of the two include flags a group or an attribute is filtered by. The zero
// value is the ID token's flag, which is what /userinfo and the ID token both read; only the
// access token sets the other.
type Inclusion int

const (
	// InclusionIdToken filters on include_in_id_token.
	InclusionIdToken Inclusion = iota
	// InclusionAccessToken filters on include_in_access_token.
	InclusionAccessToken
)

func (i Inclusion) includesGroup(group models.Group) bool {
	if i == InclusionAccessToken {
		return group.IncludeInAccessToken
	}
	return group.IncludeInIdToken
}

func (i Inclusion) includesUserAttribute(attribute models.UserAttribute) bool {
	if i == InclusionAccessToken {
		return attribute.IncludeInAccessToken
	}
	return attribute.IncludeInIdToken
}

func (i Inclusion) includesGroupAttribute(attribute models.GroupAttribute) bool {
	if i == InclusionAccessToken {
		return attribute.IncludeInAccessToken
	}
	return attribute.IncludeInIdToken
}

// Mapper writes OIDC claims from a stored user row. Its four fields are the port and the three
// divergences, so a call site reads as a statement of which of the two conversions it wants.
type Mapper struct {
	// Database backs the picture claim and is only reached under the profile scope.
	Database Database
	// BaseURL is the public URL the profile and picture claims are built from.
	BaseURL string
	// Inclusion filters groups and attributes. The zero value is the ID token's flag.
	Inclusion Inclusion
}

// AddOpenIdConnectClaims writes the profile, email, address and phone claims the given scopes ask
// for. updated_at rides inside the profile arm with the rest of the claims OIDC Core 5.4 lists
// under that scope, which is also what this repository's own documentation has always said
// (site/src/content/docs/concepts/openid-connect.mdx and integration/endpoints.mdx).
//
// A failed picture lookup is not an error here and never has been: the claim is omitted and the
// rest of the response stands, because a user who cannot be told whether they have a picture still
// has a name and an email.
func (m Mapper) AddOpenIdConnectClaims(ctx context.Context, claims jwt.MapClaims, user *models.User, scopes []string) {

	if slices.Contains(scopes, "profile") {
		claims["updated_at"] = user.UpdatedAt.Time.UTC().Unix()
		addClaimIfNotEmpty(claims, "name", user.GetFullName())
		addClaimIfNotEmpty(claims, "given_name", user.GivenName)
		addClaimIfNotEmpty(claims, "middle_name", user.MiddleName)
		addClaimIfNotEmpty(claims, "family_name", user.FamilyName)
		addClaimIfNotEmpty(claims, "nickname", user.Nickname)
		addClaimIfNotEmpty(claims, "preferred_username", user.Username)
		claims["profile"] = fmt.Sprintf("%v/account/profile", m.BaseURL)
		addClaimIfNotEmpty(claims, "website", user.Website)
		addClaimIfNotEmpty(claims, "gender", user.Gender)
		if user.BirthDate.Valid {
			claims["birthdate"] = user.BirthDate.Time.Format("2006-01-02")
		}
		addClaimIfNotEmpty(claims, "zoneinfo", user.ZoneInfo)
		addClaimIfNotEmpty(claims, "locale", user.Locale)

		hasPicture, err := m.Database.UserHasProfilePicture(ctx, nil, user.Id)
		if err == nil && hasPicture {
			claims["picture"] = fmt.Sprintf("%v/userinfo/picture/%v", m.BaseURL, user.Subject)
		}
	}

	if slices.Contains(scopes, "email") {
		addClaimIfNotEmpty(claims, "email", user.Email)
		claims["email_verified"] = user.EmailVerified
	}

	if slices.Contains(scopes, "address") && hasAddress(user) {
		claims["address"] = addressClaim(user)
	}

	if slices.Contains(scopes, "phone") {
		addClaimIfNotEmpty(claims, "phone_number", user.PhoneNumber)
		claims["phone_number_verified"] = user.PhoneNumberVerified
	}
}

// AddGroupClaims writes the groups claim when the scopes ask for it and at least one of the user's
// groups carries this mapper's include flag. An empty result writes no claim rather than an empty
// array, which is what both callers did before this package.
func (m Mapper) AddGroupClaims(claims jwt.MapClaims, user *models.User, scopes []string) {
	if !slices.Contains(scopes, "groups") {
		return
	}

	groups := []string{}
	for _, group := range user.Groups {
		if m.Inclusion.includesGroup(group) {
			groups = append(groups, group.GroupIdentifier)
		}
	}
	if len(groups) > 0 {
		claims["groups"] = groups
	}
}

// AddAttributeClaims writes the attributes claim from the user's own attributes and then from the
// attributes of every group the user belongs to, each filtered by this mapper's include flag. The
// group pass runs second and therefore wins a key collision, as it did at both sites before.
func (m Mapper) AddAttributeClaims(claims jwt.MapClaims, user *models.User, scopes []string) {
	if !slices.Contains(scopes, "attributes") {
		return
	}

	attributes := map[string]string{}
	for _, attribute := range user.Attributes {
		if m.Inclusion.includesUserAttribute(attribute) {
			attributes[attribute.Key] = attribute.Value
		}
	}

	for _, group := range user.Groups {
		for _, attribute := range group.Attributes {
			if m.Inclusion.includesGroupAttribute(attribute) {
				attributes[attribute.Key] = attribute.Value
			}
		}
	}
	if len(attributes) > 0 {
		claims["attributes"] = attributes
	}
}

// addClaimIfNotEmpty writes a claim only when its value is more than whitespace, so an unset
// column is absent from the response rather than present and empty. The value is written as it is
// read, not trimmed: trimming is the test for emptiness, never an edit of what is stored.
func addClaimIfNotEmpty(claims jwt.MapClaims, claimName string, claimValue string) {
	if len(strings.TrimSpace(claimValue)) > 0 {
		claims[claimName] = claimValue
	}
}

// hasAddress reports whether any of the six address columns holds more than whitespace. It was
// models.User.HasAddress until #387: it exists to gate the address claim and has no other caller.
func hasAddress(user *models.User) bool {
	return len(strings.TrimSpace(user.AddressLine1)) > 0 ||
		len(strings.TrimSpace(user.AddressLine2)) > 0 ||
		len(strings.TrimSpace(user.AddressLocality)) > 0 ||
		len(strings.TrimSpace(user.AddressRegion)) > 0 ||
		len(strings.TrimSpace(user.AddressPostalCode)) > 0 ||
		len(strings.TrimSpace(user.AddressCountry)) > 0
}

// addressClaim builds the OIDC address claim, a JSON object of the members OIDC Core 1.0 5.1.1
// defines. It was models.User.GetAddressClaim until #387.
//
// Two shapes are kept verbatim rather than tidied, because both are observable by a client that
// stores what it is given. street_address joins the two address lines with CRLF whether or not the
// second one is set, so a user with one line has a trailing CRLF in that member; and formatted is
// written only when the country is set, so an address without one carries the members but no
// formatted rendering of them.
func addressClaim(user *models.User) map[string]string {
	claim := make(map[string]string)

	formatted := ""
	streetAddress := fmt.Sprintf("%v\r\n%v", user.AddressLine1, user.AddressLine2)
	if len(strings.TrimSpace(streetAddress)) > 0 {
		claim["street_address"] = streetAddress
		formatted += streetAddress + "\r\n"
	}

	if len(strings.TrimSpace(user.AddressLocality)) > 0 {
		claim["locality"] = user.AddressLocality
		formatted += user.AddressLocality + "\r\n"
	}

	if len(strings.TrimSpace(user.AddressRegion)) > 0 {
		claim["region"] = user.AddressRegion
		formatted += user.AddressRegion + "\r\n"
	}

	if len(strings.TrimSpace(user.AddressPostalCode)) > 0 {
		claim["postal_code"] = user.AddressPostalCode
		formatted += user.AddressPostalCode + "\r\n"
	}

	if len(strings.TrimSpace(user.AddressCountry)) > 0 {
		claim["country"] = user.AddressCountry
		formatted += user.AddressCountry + "\r\n"
	}

	if len(strings.TrimSpace(user.AddressCountry)) > 0 {
		claim["formatted"] = strings.TrimSpace(formatted)
	}

	return claim
}
