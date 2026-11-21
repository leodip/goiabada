package adminclienthandlers

import (
	"time"

	"github.com/leodip/goiabada/core/i18n"
)

// clientErrorFields maps the refusals of the new client and client settings forms to the field
// each is about. The admin API answers a client's refusals by their catalog key, which names the
// field (#617); the blank identifier the console refuses itself.
var clientErrorFields = map[string]string{
	i18n.ErrCodeClientIdentifierRequired:             "clientIdentifier",
	i18n.ErrCodeIdentifierTooLong:                    "clientIdentifier",
	i18n.ErrCodeIdentifierTooShort:                   "clientIdentifier",
	i18n.ErrCodeIdentifierInvalidFormat:              "clientIdentifier",
	i18n.ErrCodeClientIdentifierInUse:                "clientIdentifier",
	i18n.ErrCodeClientIdentifierNamesResource:        "clientIdentifier",
	i18n.ErrCodeClientSystemLevelIdentifierFixed:     "clientIdentifier",
	i18n.ErrCodeClientSelfRegisteredIdentifierFixed:  "clientIdentifier",
	i18n.ErrCodeClientDescriptionTooLong:             "description",
	i18n.ErrCodeDescriptionAngleBrackets:             "description",
	i18n.ErrCodeClientDisplayNameTooLong:             "displayName",
	i18n.ErrCodeDisplayNameAngleBrackets:             "displayName",
	i18n.ErrCodeClientWebsiteURLTooLong:              "websiteUrl",
	i18n.ErrCodeClientWebsiteURLInvalid:              "websiteUrl",
	i18n.ErrCodeClientWebsiteURLSchemeInvalid:        "websiteUrl",
	i18n.ErrCodeClientPrivacyPolicyURLTooLong:        "privacyPolicyUrl",
	i18n.ErrCodeClientPrivacyPolicyURLInvalid:        "privacyPolicyUrl",
	i18n.ErrCodeClientPrivacyPolicyURLSchemeInvalid:  "privacyPolicyUrl",
	i18n.ErrCodeClientTermsOfServiceURLTooLong:       "termsOfServiceUrl",
	i18n.ErrCodeClientTermsOfServiceURLInvalid:       "termsOfServiceUrl",
	i18n.ErrCodeClientTermsOfServiceURLSchemeInvalid: "termsOfServiceUrl",
	i18n.ErrCodeClientDefaultACRNotApplicable:        "defaultAcrLevel",
	i18n.ErrCodeClientDefaultACRInvalid:              "defaultAcrLevel",
}

// clientTokensErrorFields maps the token tab's refusals to the duration each is about.
var clientTokensErrorFields = map[string]string{
	i18n.ErrCodeClientTokensTokenExpirationOutOfRange:          "tokenExpirationInSeconds",
	i18n.ErrCodeClientTokensOfflineIdleTimeoutOutOfRange:       "refreshTokenOfflineIdleTimeoutInSeconds",
	i18n.ErrCodeClientTokensOfflineIdleTimeoutAboveMaxLifetime: "refreshTokenOfflineIdleTimeoutInSeconds",
	i18n.ErrCodeClientTokensOfflineMaxLifetimeOutOfRange:       "refreshTokenOfflineMaxLifetimeInSeconds",
}

// clientAuthenticationErrorFields maps the authentication tab's refusals to the field each is about.
var clientAuthenticationErrorFields = map[string]string{
	i18n.ErrCodeClientSecretInvalid: "clientSecret",
}

// grantedPermission is a permission a client holds, as its permissions tab lists it: the
// permission's id, which the save sends, and its scope, resource:permission, which the row shows.
type grantedPermission struct {
	ID    int64
	Scope string
}

type PermissionsPostInput struct {
	ClientID               int64   `json:"clientId"`
	AssignedPermissionsIDs []int64 `json:"assignedPermissionsIds"`
	// ExpectedPermissionIDs is the set as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedPermissionIDs []int64 `json:"expectedPermissionIds"`
}

// listedResource is a resource on a client's introspection list, as its Introspection tab lists
// it: the resource's id, which the save sends, and its identifier, which the row shows.
type listedResource struct {
	ID         int64
	Identifier string
}

// IntrospectionPostInput is the Introspection tab's save: the list wanted, and the list as the page
// loaded it, passed through unchanged so the auth server can refuse a save from an outdated page
// (#428). The client is the route's.
type IntrospectionPostInput struct {
	ResourceIDs         []int64 `json:"resourceIds"`
	ExpectedResourceIDs []int64 `json:"expectedResourceIds"`
}

type RedirectURIsPostInput struct {
	ClientID     int64    `json:"clientId"`
	RedirectURIs []string `json:"redirectURIs"`
	// ExpectedRedirectURIs is the list as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedRedirectURIs []string `json:"expectedRedirectURIs"`
}

// SignOutRedirectURIsPostInput is the Sign-out redirect URIs tab's save: the list wanted, and the
// list as the page loaded it, passed through unchanged so the auth server can refuse a save from an
// outdated page (#428).
type SignOutRedirectURIsPostInput struct {
	ClientID                    int64    `json:"clientId"`
	SignOutRedirectURIs         []string `json:"signOutRedirectURIs"`
	ExpectedSignOutRedirectURIs []string `json:"expectedSignOutRedirectURIs"`
}

type WebOriginsPostInput struct {
	ClientID   int64    `json:"clientId"`
	WebOrigins []string `json:"webOrigins"`
	// ExpectedWebOrigins is the list as the page loaded it, passed through unchanged so the auth
	// server can refuse a save from an outdated page (#428).
	ExpectedWebOrigins []string `json:"expectedWebOrigins"`
}

type SessionInfo struct {
	UserSessionID int64
	UserID        int64
	UserEmail     string
	UserFullName  string
	IsCurrent     bool
	// Started and LastAccessed are the instants themselves rather than pre-rendered text: the
	// page formats them with the DateTime and Since template functions, which read the layout
	// and the relative phrase from the viewer's catalog. Formatting them here produced an
	// English RFC1123 date beside a Go duration string under every locale, because Go's
	// time.Format has no locale and Duration.String() is not anybody's language (#373).
	Started      *time.Time
	LastAccessed *time.Time
	IPAddress    string
	DeviceName   string
	DeviceType   string
	DeviceOS     string
	// UserAgent is the raw header, shown as the Device cell's tooltip so two sessions
	// whose labels read alike can still be told apart (#281).
	UserAgent string
	Clients   []string
}
