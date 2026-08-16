package handlers

import (
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

// responseParam is one parameter this server writes into a client's redirect URI: an
// authorization response field such as "code", "state", "error" or "access_token".
type responseParam struct{ name, value string }

// encodeResponseParams renders params as an "application/x-www-form-urlencoded" field
// list, in the order given, and returns "" for an empty slice.
//
// The order is the caller's declaration order and not url.Values.Encode's alphabetical
// sort, so an emitter decides what its response looks like on the wire. Names are
// compile-time literals from this package, so escaping them is identity today; it is done
// anyway to stay symmetric with the decoded-name filter in writeResponseParams, which
// compares decoded names and would otherwise be matching against something this function
// never guarantees.
func encodeResponseParams(params []responseParam) string {
	fields := make([]string, 0, len(params))
	for _, param := range params {
		fields = append(fields, url.QueryEscape(param.name)+"="+url.QueryEscape(param.value))
	}
	return strings.Join(fields, "&")
}

// writeResponseParams returns redirectURI with params written into its query component:
// every field the client registered is preserved byte for byte and in order, except those
// params replaces, and the params are appended escaped.
//
// This is the one construction in this package that writes response parameters into a
// client's redirect URI. Every emitter goes through it, which is the point: #146 exists
// because #109 fixed this in one place and left the other copies alone, so a second
// implementation is the condition that produced the issue rather than duplication beside
// it.
//
// Two defects it exists to prevent, both of which the obvious code has:
//
//   - Exactly one of each written parameter reaches the client. Every registered field
//     whose decoded name is one being written is dropped and the new one appended, so a
//     client that registered "?state=fixed" reads back the state it actually sent rather
//     than the registered one, and never both with the choice left to its parser. Adding
//     without filtering emitted two, and Go's own url.Values.Get returns the first of
//     them, which is the registered value the client never generated (#146). RFC 6749
//     section 3.1 is explicit: "Request and response parameters MUST NOT be included more
//     than once."
//
//   - The registered query survives. RFC 6749 section 3.1.2 says a redirection endpoint
//     "MAY include an "application/x-www-form-urlencoded" formatted query component, which
//     MUST be retained when adding additional query parameters". Decoding it into
//     url.Values and re-encoding it does not round-trip: url.Query discards the error from
//     url.ParseQuery, so a field separated by a literal semicolon ("?lang=en;mode=dark")
//     is deleted outright and the caller never learns; Encode sorts by key, so a query
//     whose order the client signs over comes back reordered; a valueless field ("?flag")
//     gains an "="; percent-escapes are normalised ("%7E" to "~"); and an empty field is
//     collapsed ("?a=1&&b=2"). The registered URI was just matched byte for byte by
//     ValidateClientAndRedirectURI, so altering its query sends the client somewhere it
//     did not register. None of those shapes is rejected at registration:
//     validateRedirectURI's excluded-character set is "<>\"{}|\\^` " and admits a
//     semicolon (#109, #146).
//
// Copying registered bytes into a Location header is safe here because url.Parse rejects
// CR, LF and NUL outright ("net/url: invalid control character in URL"), so a registered
// URI that reaches this point cannot carry a header-splitting byte. Param values are
// caller- or client-supplied and are escaped, never copied.
//
// url.Parse rather than url.ParseRequestURI, matching the logout emitter: a fragment is
// not part of an HTTP request URI, so ParseRequestURI keeps a literal "#" in the path and
// the result comes back as ".../out%23frag?state=abc". url.Parse still rejects the
// genuinely malformed, so the looser parse gives up nothing. Nothing reachable turns on
// it either way, because checkRedirectURIEmittable refuses a relative, scheme-relative or
// fragment-bearing URI above every caller (#122).
//
// Deciding whether a parameter belongs in params at all is the caller's job, not this
// function's: it writes exactly what it is given. An empty params returns the URI with its
// query rejoined unchanged, which is byte-identical to the input because
// strings.Join(strings.Split(q, "&"), "&") == q and url.URL.ForceQuery keeps a registered
// bare "?".
func writeResponseParams(redirectURI string, params []responseParam) (string, error) {
	redirUrl, err := url.Parse(redirectURI)
	if err != nil {
		return "", errors.Wrap(err, "unable to parse redirect URI")
	}

	fields := make([]string, 0, 4+len(params))
	// An empty RawQuery is the only field the loop must not see. strings.Split("", "&")
	// yields one empty string rather than nothing, so iterating unconditionally would
	// append a leading "&" to a URI that had no query at all. Guarding here rather than
	// skipping empty fields inside the loop is what keeps the empty fields a registered
	// query really did carry: "?a=1&&b=2" stays that way instead of collapsing to
	// "?a=1&b=2", which is a different target from the one that was registered and just
	// matched exactly (#109).
	if redirUrl.RawQuery != "" {
		for _, field := range strings.Split(redirUrl.RawQuery, "&") {
			name := field
			if i := strings.IndexByte(field, '='); i >= 0 {
				name = field[:i]
			}
			// The comparison is on the decoded name, so a registered "%73tate=fixed" is
			// replaced too: it is the same parameter to a client's parser, and leaving it
			// would put the duplicate back through the door percent-encoding opens. An
			// unescapable name cannot decode to any parameter this server writes, and is
			// kept as it stands rather than dropped, since the point is to preserve what
			// was registered.
			if decoded, err := url.QueryUnescape(name); err == nil && isResponseParamName(decoded, params) {
				continue
			}
			fields = append(fields, field)
		}
	}

	if len(params) > 0 {
		fields = append(fields, encodeResponseParams(params))
	}

	redirUrl.RawQuery = strings.Join(fields, "&")
	return redirUrl.String(), nil
}

// isResponseParamName reports whether name is one of the parameters being written, and so
// whether a registered field carrying it is being replaced.
func isResponseParamName(name string, params []responseParam) bool {
	for _, param := range params {
		if param.name == name {
			return true
		}
	}
	return false
}
