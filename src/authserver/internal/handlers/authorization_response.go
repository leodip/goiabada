package handlers

import (
	"bytes"
	"context"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/render"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/web"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// responseParam is one parameter this server writes into a client's redirect URI: an
// authorization response field such as "code", "state", "error" or "access_token".
type responseParam struct{ name, value string }

// authorizationResponseParamNames are the names an authorization response owns in the query
// component of a client's redirect URI. A registered field carrying one of them is dropped
// by writeResponseParams whether or not the selected response emits it.
//
// Filtering only what a response actually emits is not enough. A client registering
// "?error=stale" would read "?error=stale&code=fresh&state=...", success and failure at once,
// and an RP that checks for "error" before reading "code" (the usual order) reads it as a
// refusal. One registering "?state=fixed" and sending no state of its own would be handed a
// state on the code redirect that it never sent and cannot have bound to its user agent (#146).
//
// iss is among them because every authorization response writes it (RFC 9207 section 2), so a
// registered "iss" is always replaced and reserving it changes nothing a client sees; it is listed
// so that the set names what this server emits (#576).
//
// The set is these five and not six: RFC 6749 section 4.1.2.1 also defines "error_uri",
// but this server never emits it, so reserving it would only delete a registered field no
// response of ours can collide with. Adding a name here is therefore a decision about what
// this server emits, not a tidy-up, and it takes a field away from every client that
// registered it.
//
// Nothing in RFC 6749 forces this. Section 3.1.2 says the registered query "MUST be
// retained when adding additional query parameters", which argues the other way; section
// 4.1.2 says only that "The client MUST ignore unrecognized response parameters", and these
// are recognized ones. It is a judgement call (#146): the two shapes above are
// worth more than a registered fixed value, which a client can keep by choosing a name this
// server does not emit.
//
// The end_session_endpoint deliberately reserves nothing, so buildPostLogoutRedirect passes
// nil and a registered post-logout "?state=fixed" survives. See its comment: the two
// endpoints differ because their specifications do.
var authorizationResponseParamNames = []string{"code", "state", "error", "error_description", "iss"}

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
// params replaces or reservedNames claims, and the params are appended escaped.
//
// reservedNames are names the response owns whether or not it emits them, and it is the one
// difference between the two endpoints that call this. The authorization emitters pass
// authorizationResponseParamNames, whose comment carries why; buildPostLogoutRedirect passes
// nil, so a registered field survives there unless the response actually replaces it.
//
// This is the one construction in this package that writes response parameters into a
// client's redirect URI, and every emitter goes through it, so the rule lives in one place
// (#109, #146).
//
// Two defects it exists to prevent, both of which the obvious code has:
//
//   - Exactly one of each written parameter reaches the client. Every registered field
//     whose decoded name is one being written is dropped and the new one appended, so a
//     client that registered "?state=fixed" reads back the state it actually sent rather
//     than the registered one, and never both with the choice left to its parser. Adding
//     without filtering would emit two, and Go's own url.Values.Get returns the first of
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
// bare "?". An empty params with a non-empty reservedNames still filters, so the reserved
// names are gone from the query whichever response mode or path selected them; no
// authorization emitter reaches that combination, because every response it can build
// carries at least one parameter. Filtering can leave a single empty field as the whole
// query, and the "?" that then carries it is restored explicitly, for the reason given
// at the end of the body.
func writeResponseParams(redirectURI string, params []responseParam, reservedNames []string) (string, error) {
	redirUrl, err := url.Parse(redirectURI)
	if err != nil {
		return "", errs.Wrap(err, "unable to parse redirect URI")
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
			if decoded, err := url.QueryUnescape(name); err == nil &&
				(isResponseParamName(decoded, params) || slices.Contains(reservedNames, decoded)) {
				continue
			}
			fields = append(fields, field)
		}
	}

	if len(params) > 0 {
		fields = append(fields, encodeResponseParams(params))
	}

	redirUrl.RawQuery = strings.Join(fields, "&")
	// A surviving field list that joins to "" is exactly one empty field, and then the
	// "?" is the only byte left carrying it. url.URL.String writes that delimiter only
	// when RawQuery is non-empty or ForceQuery is set, so without this a registered
	// "?state=fixed&" filtered down to its trailing empty field comes back as no query
	// at all, which is a different target from the one that was registered and just
	// matched exactly. Zero surviving fields is the opposite case and deliberately
	// loses the "?": there is nothing left for it to delimit (#146).
	if len(fields) > 0 && redirUrl.RawQuery == "" {
		redirUrl.ForceQuery = true
	}
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

// writeAuthorizationResponse answers the client at redirectURI with params, in responseMode:
// "fragment", "form_post", or the query for anything else. The authorization code, the implicit
// tokens and the error emitter all answer through it, so the three encodings are written once each
// (#437).
//
// It appends iss after the caller's params, which end with state when there is one, in the order of
// RFC 9207 section 2.1's example. iss is the issuer setting as read for this request, the value
// discovery's issuer and every token's iss carry, so the three a client compares under RFC 9207
// section 2.4 are one. Appending it here, the one place every encoding and every outcome passes,
// is what makes "every authorization response carries iss" hold, as discovery advertises it does.
// A request without its settings has no issuer to send: it is an error, and nothing is written,
// since a response without iss is one section 2.4 has the client reject (#576, decision 2).
//
// Deciding whether a response may be emitted at all is the caller's: each runs
// checkRedirectURIEmittable, and the error emitter RedirectWillBeEmitted's provenance and
// registration gates, above this call.
func writeAuthorizationResponse(w http.ResponseWriter, r *http.Request, formPostFS fs.FS,
	responseMode string, redirectURI string, params []responseParam) error {

	settings, ok := reqctx.SettingsFrom(r.Context())
	if !ok {
		return errs.Wrap(reqctx.ErrNoSettings, "unable to read the issuer for the authorization response")
	}
	params = append(slices.Clip(params), responseParam{"iss", settings.Issuer})

	switch responseMode {
	case "fragment":
		writeFragmentRedirect(w, r, redirectURI, params)
		return nil
	case "form_post":
		page, err := newFormPostPage(r.Context(), settings)
		if err != nil {
			return err
		}
		return writeFormPost(w, formPostFS, page, redirectURI, params)
	default:
		return writeQueryRedirect(w, r, redirectURI, params)
	}
}

// noStoreAuthorizationResponse writes the Cache-Control/Pragma pair RFC 6749 section 5.1 requires of
// any response carrying tokens, credentials or other sensitive information. A successful
// authorization response carries an authorization code or an access token; an error carries
// neither, and is marked all the same, so every authorization response follows one rule whatever
// its mode and outcome. All three encodings call it: the two redirect writers below, so a cache never
// stores and replays a Location carrying the credential (#573), and writeFormPost.
func noStoreAuthorizationResponse(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// implicitResponseMode is the mode an implicit response is delivered in, its tokens or its error:
// the form_post the client asked for, and the fragment for anything else.
//
// Never the query. OAuth 2.0 Multiple Response Type Encoding Practices section 3 says of id_token
// that "the query encoding MUST NOT be used", section 5 says the same of id_token token, and
// RFC 6749 4.2.2 puts the implicit grant's token response in the fragment; section 7 gives the
// reason, that "Access Tokens and ID Tokens MUST NOT be encoded in the query string", since the
// Referer header carries a query to third parties. ValidateRequest refuses a request that names the query for such a response type, and that
// refusal is itself answered through here, in the fragment, because it answers a request whose mode
// it cannot honour. The empty string is the fragment, the default for these response types.
//
// One rule for the success path and the error path, so an explicit "query" never reaches the query
// component of either (#231, #437).
func implicitResponseMode(requested string) string {
	if requested == "form_post" {
		return "form_post"
	}
	return "fragment"
}

// writeFragmentRedirect redirects to redirectURI with params as its fragment, with redirectStatus's
// code: 303 for the declined consent, which answers a POST, and 302 at /auth/issue and
// /auth/authorize.
//
// Appended rather than written through writeResponseParams: the redirect URI cannot carry a
// fragment of its own (RFC 6749 3.1.2 forbids it and checkRedirectURIEmittable refuses one above
// every caller), so there is no registered field list here to preserve or replace. Its query, if it
// registered one, is left exactly as it stands.
func writeFragmentRedirect(w http.ResponseWriter, r *http.Request, redirectURI string, params []responseParam) {
	noStoreAuthorizationResponse(w)
	http.Redirect(w, r, redirectURI+"#"+encodeResponseParams(params), redirectStatus(r))
}

// writeQueryRedirect redirects to redirectURI with params in its query component, with
// redirectStatus's code, as writeFragmentRedirect does.
//
// writeResponseParams, not Query() then Encode(): seeding url.Values from the registered query and
// adding on top would emit two state parameters to a client that registered "?state=fixed", and
// url.Values.Get answers with the registered one, defeating the RP's RFC 9700 2.1 CSRF check;
// re-encoding would also rewrite the registered query, against RFC 6749 3.1.2's "MUST be retained".
// The shared helper's comment carries the detail (#146).
//
// authorizationResponseParamNames, so a registered "code" is dropped from an error response and a
// registered "error" from a success response, and no response says success and failure at once. It
// also drops a registered "?state=fixed"
// when the request carried no state of its own, so the client is never handed a state it did not
// send (#146).
func writeQueryRedirect(w http.ResponseWriter, r *http.Request, redirectURI string, params []responseParam) error {
	location, err := writeResponseParams(redirectURI, params, authorizationResponseParamNames)
	if err != nil {
		return errs.Wrap(err, "unable to build the authorization response redirect")
	}

	noStoreAuthorizationResponse(w)
	http.Redirect(w, r, location, redirectStatus(r))
	return nil
}

// formPostPage is what the form_post page shows around the response it carries: its language, the
// theme, the text in the reader's language, and the stylesheet and script by their fingerprints. The
// page is parsed alone, with no layout and none of the renderer's template functions, so every value
// it shows arrives here (#617).
type formPostPage struct {
	Lang       string
	Theme      string
	AppName    string
	Title      string
	Message    string
	Button     string
	Stylesheet string
	Script     string
}

// formPostAssetURL names the page's stylesheet and script by the fingerprints of the built-in static
// files, the ones the built-in page is written against.
var formPostAssetURL = render.NewAssetURLs(web.StaticFS())

// newFormPostPage is the form_post page's presentation for a request in ctx under settings. The
// theme is written only for light and dark, as the layouts write it, so any other value follows the
// device.
func newFormPostPage(ctx context.Context, settings *record.Settings) (formPostPage, error) {
	stylesheet, err := formPostAssetURL("/static/main.css")
	if err != nil {
		return formPostPage{}, err
	}
	script, err := formPostAssetURL("/static/form-post.js")
	if err != nil {
		return formPostPage{}, err
	}
	page := formPostPage{
		Lang:       i18n.CatalogTag(ctx),
		AppName:    settings.AppName,
		Title:      i18n.T(ctx, "form_post.title"),
		Message:    i18n.T(ctx, "form_post.message"),
		Button:     i18n.T(ctx, "form_post.button"),
		Stylesheet: stylesheet,
		Script:     script,
	}
	if settings.UITheme == "light" || settings.UITheme == "dark" {
		page.Theme = settings.UITheme
	}
	return page, nil
}

// writeFormPost answers with form_post.html, a form posting params to redirectURI, which its script
// submits at once and its button submits without JavaScript.
//
// formPostFS is the built-in template set in every server (NewClientErrorResponder), never
// GOIABADA_AUTHSERVER_TEMPLATEDIR: the page is how an authorization response is encoded on the wire,
// as the query string is for the query encoding, and a copy taken from an older release would drop
// a parameter, iss among them, that discovery says every response carries (#576, decision 5).
//
// The bind map holds redirectURI, page, and exactly the parameters in params, so a parameter the
// caller left out, an empty state above all, is absent rather than present and empty. {{.state}} and
// {{if .state}} cannot tell the two apart, but a template that enumerates the map can: range yields
// the key only when it is present, and len counts it. TestFormPostBindMapOmitsAnAbsentState pins it
// through both emitters (#146).
func writeFormPost(w http.ResponseWriter, formPostFS fs.FS, page formPostPage, redirectURI string, params []responseParam) error {
	m := make(map[string]interface{}, 2+len(params))
	m["redirectURI"] = redirectURI
	m["page"] = page
	for _, param := range params {
		m[param.name] = param.value
	}

	t, err := template.ParseFS(formPostFS, "form_post.html")
	if err != nil {
		return errs.Wrap(err, "unable to parse template")
	}

	// Render into a buffer, not straight to w. Execute writes as it walks the template, so a
	// template that parses and then fails part way through would leave a partial body and an
	// implicit 200 already on the wire. Every caller answers an error from here with
	// pageRenderer.InternalServerError as its last resort, and a WriteHeader after the response is
	// committed changes nothing, so the client would be told 200 for a page that was never
	// finished: on the success path, a form carrying an authorization code with no submit to
	// deliver it. Buffering keeps the response uncommitted until there is a whole page to send
	// (#141, #146 decision 10).
	var rendered bytes.Buffer
	err = t.Execute(&rendered, m)
	if err != nil {
		return errs.Wrap(err, "unable to execute template")
	}

	// OAuth 2.0 Form Post Response Mode section 2: "Because the Authorization Response is intended to
	// be used only once, the Authorization Server MUST instruct the User Agent (and any
	// intermediaries) not to store or reuse the content of the response." The page holds the
	// client's state, and on the success path an authorization code, so a cached or reused copy is a
	// replayable response sitting in an intermediary. This pair is what the rest of this codebase
	// writes for a no-store response (#146), and what the two redirect writers write (#573).
	//
	// Set here rather than before Execute deliberately: a render that fails must leave the response
	// completely untouched, so that the caller's last-resort InternalServerError owns every header
	// as well as the status (#141).
	noStoreAuthorizationResponse(w)

	_, err = w.Write(rendered.Bytes())
	if err != nil {
		// The connection itself failed. Nothing can be recovered from here, including the
		// caller's 500, but the error is still worth reporting rather than swallowing.
		return errs.Wrap(err, "unable to write the form_post response")
	}
	return nil
}
