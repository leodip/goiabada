package apihandlers

import (
	"net/url"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/core/i18n"
)

// A client holds two lists of URIs a browser is sent to: its redirect URIs, where an authorization
// response goes, and its sign-out redirect URIs, where a sign-out may return. The admin API saves
// both under one set of rules, so an administrator learns them once, and each list refuses with
// its own messages, so a refusal says which list it is about (#147 decision 4). The rules live
// here, and each save passes its list's catalog keys.

// uriListRefusals is the catalog keys one list's save refuses with, one per rule.
type uriListRefusals struct {
	tooMany      string // Args: {"max": int, "count": int}
	empty        string
	tooLong      string // Args: {"length": int, "max": int, "prefix": string}
	invalid      string // Args: {"uri": string}
	notAbsolute  string // Args: {"uri": string}
	insecureHTTP string // Args: {"uri": string}
	duplicate    string
}

// redirectURIRefusals is the redirect URI save's.
var redirectURIRefusals = uriListRefusals{
	tooMany:      i18n.ErrCodeClientRedirectURIsTooMany,
	empty:        i18n.ErrCodeClientRedirectURIEmpty,
	tooLong:      i18n.ErrCodeClientRedirectURITooLong,
	invalid:      i18n.ErrCodeClientRedirectURIInvalid,
	notAbsolute:  i18n.ErrCodeClientRedirectURINotAbsolute,
	insecureHTTP: i18n.ErrCodeClientRedirectURIInsecureHTTP,
	duplicate:    i18n.ErrCodeClientRedirectURIsDuplicate,
}

// postLogoutRedirectURIRefusals is the sign-out redirect URI save's (#147 decision 5).
var postLogoutRedirectURIRefusals = uriListRefusals{
	tooMany:      i18n.ErrCodeClientPostLogoutRedirectURIsTooMany,
	empty:        i18n.ErrCodeClientPostLogoutRedirectURIEmpty,
	tooLong:      i18n.ErrCodeClientPostLogoutRedirectURITooLong,
	invalid:      i18n.ErrCodeClientPostLogoutRedirectURIInvalid,
	notAbsolute:  i18n.ErrCodeClientPostLogoutRedirectURINotAbsolute,
	insecureHTTP: i18n.ErrCodeClientPostLogoutRedirectURIInsecureHTTP,
	duplicate:    i18n.ErrCodeClientPostLogoutRedirectURIsDuplicate,
}

// loadedURIList reads a save's expected list, the list as the caller loaded it: each value trimmed,
// in order, and the same values as a set, which the plain-http rule below reads.
func loadedURIList(raw []string) (expected []string, loaded map[string]struct{}) {
	expected = make([]string, 0, len(raw))
	loaded = make(map[string]struct{}, len(raw))
	for _, value := range raw {
		uri := strings.TrimSpace(value)
		expected = append(expected, uri)
		loaded[uri] = struct{}{}
	}
	return expected, loaded
}

// normalizeURIList checks a whole list a save is about to store and answers it trimmed, in order, or
// the first refusal, in the list's own words. Nothing is read or written: every refusal is decided
// before the save opens its transaction.
func normalizeURIList(wanted []string, loaded map[string]struct{}, refusals uriListRefusals) ([]string, *i18n.LocalizedError) {
	// The bounds are the model's, the same at dynamic client registration: at most
	// RedirectURIsMaxPerClient per list, each at most RedirectURIMaxBytes, which the columns hold
	// on every engine. A save replaces the whole set, so a client already over either bound cannot
	// be saved until the administrator trims it in the same save, which is #122's precedent for a
	// legacy row below (#428).
	if len(wanted) > record.RedirectURIsMaxPerClient {
		return nil, i18n.NewLocalizedError(refusals.tooMany, map[string]any{"max": record.RedirectURIsMaxPerClient, "count": len(wanted)})
	}

	seen := make(map[string]struct{})
	normalized := make([]string, 0, len(wanted))
	for _, raw := range wanted {
		uri := strings.TrimSpace(raw)
		if uri == "" {
			return nil, i18n.NewLocalizedError(refusals.empty, nil)
		}
		// Before the parse, so an overlong value is never parsed. The message names the value by
		// its beginning rather than echoing up to the whole body back.
		if len(uri) > record.RedirectURIMaxBytes {
			return nil, i18n.NewLocalizedError(refusals.tooLong, map[string]any{"length": len(uri), "max": record.RedirectURIMaxBytes, "prefix": strings.ToValidUTF8(uri[:80], "")})
		}
		if _, parseErr := url.ParseRequestURI(uri); parseErr != nil {
			return nil, i18n.NewLocalizedError(refusals.invalid, map[string]any{"uri": uri})
		}
		// url.ParseRequestURI above accepts "//evil.example/cb", "/relative/cb",
		// "http://host/cb#frag" and "https:///evil.example/cb", every one of which is later
		// emitted verbatim into a Location header. RFC 6749 section 3.1.2 is what refuses them,
		// through the same predicate dynamic registration and the authorization endpoint use.
		// Ordered after the parse and before the duplicate check, mirroring the dynamic
		// registration gate.
		//
		// Only the absolute-URI rule crosses over from dynamic registration, not that endpoint's
		// scheme denylist or excluded-character set. The absolute-URI rule is a protocol
		// requirement and binds an administrator exactly as it binds an anonymous registrant; the
		// other two exist because that caller is anonymous, and an administrator has legitimate
		// reasons to register a custom scheme (#122), for a sign-out as for a sign-in, which
		// RP-Initiated Logout 1.0 section 2 permits (#147).
		//
		// Accepted cost: a save replaces the whole set, so a deployment still holding a legacy
		// non-absolute row cannot save the list until the administrator removes that URI from it.
		// The message names the offending value, and taking that remediation also deletes the row.
		if !urlmatch.IsAbsoluteRedirectURI(uri) {
			return nil, i18n.NewLocalizedError(refusals.notAbsolute, map[string]any{"uri": uri})
		}
		// RFC 9700 section 2.6: an authorization response MUST NOT travel over an unencrypted
		// connection, so a redirect URI may use http only on the loopback interface (RFC 8252
		// section 7.3). Dynamic registration already refuses this shape; the admin API did not,
		// and a saved http URI then received the code in the clear. The MUST binds an
		// administrator as it binds a registrant, exactly as the absolute-URI rule above does
		// (#122). A sign-out redirect URI is held to the same rule, as the #702 decision on #147
		// records.
		//
		// Refused when saving only, not re-checked where the URI is used: a stored http URI
		// belongs to an integration that works today, and a use-time gate would stop it at
		// upgrade with no warning. The worst case is the admin console's own client, whose URIs
		// bootstrap seeds from GOIABADA_ADMINCONSOLE_BASEURL: an installation serving the console
		// over http on a non-loopback host would lock its administrators out (#590).
		//
		// For the same reason, a URI the caller loaded passes when the save carries it back. A
		// legacy non-absolute row above does not, but that row is already refused where it is
		// used; this one still works, and refusing it would block every other change to the
		// list, removing a compromised entry included. Adding an http URI is what is refused, and
		// the caller's word for what it loaded is checked: the save's transaction answers 409
		// when the stored rows differ from it, so naming a new http URI there writes nothing
		// (#575).
		if _, wasLoaded := loaded[uri]; !wasLoaded && urlmatch.IsInsecureHTTPRedirectURI(uri) {
			return nil, i18n.NewLocalizedError(refusals.insecureHTTP, map[string]any{"uri": uri})
		}
		if _, exists := seen[uri]; exists {
			return nil, i18n.NewLocalizedError(refusals.duplicate, nil)
		}
		seen[uri] = struct{}{}
		normalized = append(normalized, uri)
	}
	return normalized, nil
}
