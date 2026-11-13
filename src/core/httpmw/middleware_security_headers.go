package httpmw

import "net/http"

// strictTransportSecurityValue is the Strict-Transport-Security value: a one-year
// max-age (the commonly recommended value) plus includeSubDomains. No `preload`
// directive is emitted, since preload is a long-lived commitment that is hard to
// reverse.
const strictTransportSecurityValue = "max-age=31536000; includeSubDomains"

// The Content-Security-Policy's parts: the script-src directive's sources, the three directives that
// say where styles, images and fonts come from, and the directives after them. What each directive
// does, and why it is not more or less, is on SecurityHeaders.
const (
	scriptSrcSelf        = "script-src 'self'"
	styleSrcSelf         = "; style-src 'self'"
	imgSrcSelf           = "; img-src 'self' data:"
	fontSrcSelf          = "; font-src 'self'"
	policyAfterAssetSrcs = "; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)

// SetContentSecurityPolicy sets h's Content-Security-Policy to the one SecurityHeaders sends, with
// assetOrigins admitted beside 'self' to style-src, img-src and font-src, and scriptOrigins
// admitted beside 'self' to script-src. SecurityHeaders sets it with its own asset origins and no
// script origin. A handler calls it, before it writes the response, to widen script-src for that
// one response, passing the asset origins its server's SecurityHeaders was given: an origin in
// script-src runs with the page's authority, over its forms and what the user types, so it belongs
// only on the pages its scripts run on. The auth server admits Cloudflare's on the forms carrying
// the Turnstile challenge, while it is on (#642 decision 9). Each origin is a constant or the
// configuration of the caller's, never a value a request carries.
func SetContentSecurityPolicy(h http.Header, assetOrigins []string, scriptOrigins ...string) {
	assets := ""
	for _, origin := range assetOrigins {
		assets += " " + origin
	}
	scriptSrc := scriptSrcSelf
	for _, origin := range scriptOrigins {
		scriptSrc += " " + origin
	}
	h.Set("Content-Security-Policy", scriptSrc+
		styleSrcSelf+assets+
		imgSrcSelf+assets+
		fontSrcSelf+assets+
		policyAfterAssetSrcs)
}

// SecurityHeaders sets baseline security response headers on every
// response. It is installed early in the chain (before Recoverer) so that even
// panic (500) responses carry the headers.
//
// Headers set:
//
//   - X-Frame-Options: DENY blocks clickjacking (the login/consent/OTP pages are
//     never meant to be framed).
//
//   - Content-Security-Policy: script-src 'self'; style-src 'self';
//     img-src 'self' data:; font-src 'self'; object-src 'none';
//     base-uri 'none'; frame-ancestors 'none' (#518, #816). A browser runs only
//     the script files this origin serves, and refuses every inline <script>, on…
//     attribute, javascript: URL and eval, so markup that reaches a page through
//     a missed sink or an operator's template cannot run code. Every built-in
//     page keeps its scripts in static files and hands them data in JSON data
//     blocks, which a browser never runs (core/guard.AssertWellFormedTemplates
//     holds the templates to that), so the policy needs no nonce or hash and
//     stays one constant. A page that loads a script from elsewhere admits
//     that origin on its own responses (SetContentSecurityPolicy).
//
//     style-src, img-src and font-src load stylesheets, images and fonts only
//     from this origin, and images from data: URLs too. A brand's custom CSS
//     reaches the pages, and CSS that could load from anywhere could read a
//     value on the page and send it away in a URL; the three directives leave
//     it no other site to send it to. style-src 'self' also refuses every <style>
//     element and style attribute; every built-in page keeps its styles in
//     static files. data: images carry their bytes in the URL and send nothing
//     anywhere: the built-in stylesheet's icons, the console's authenticator
//     QR code and the picture being cropped are such images. assetOrigins are
//     admitted beside 'self' to the three: the console passes the auth
//     server's origin, which serves the brand's stylesheets, pictures and font,
//     the client logos and the user pictures its pages draw (#816 decision 5).
//
//     object-src 'none' refuses <object> and <embed>, which nothing else
//     restricts with no default-src sent; base-uri 'none' refuses a <base> that
//     would move every relative form action to another origin; frame-ancestors
//     'none' refuses framing, as X-Frame-Options does. None of the seven
//     governs form submission, fetches or frames, so the form_post page and
//     every other form submit as before, and the Turnstile widget's frame
//     loads.
//
//   - X-Content-Type-Options: nosniff stops MIME sniffing (this also protects
//     the image-serving endpoints).
//
//   - Referrer-Policy: same-origin keeps sensitive auth URLs (codes, state) out
//     of Referer headers sent to other origins, which is the case that matters:
//     an authorization code or state value must never travel to a third party.
//     Within our own origin the full URL is still sent, which is harmless.
//
//     It must NOT be no-referrer, even though that looks stricter. Under
//     no-referrer a browser sends "Origin: null" on form POSTs as well as
//     omitting Referer, and an opaque origin has no host for the CSRF origin
//     check to compare against Host. It once broke every cookie-authenticated
//     POST outright: login, OTP, consent and every admin console form.
//
//     The blast radius is narrower now that the check is
//     net/http.CrossOriginProtection (#155). It consults Sec-Fetch-Site first
//     and allows a same-origin POST whatever the Origin header says, so a
//     browser new enough to send fetch metadata (2023 onwards) is unaffected by
//     an opaque origin. Only a browser predating it falls through to the Origin
//     comparison, where "null" still matches no host and is still rejected.
//     Same conclusion, smaller set of victims, and not worth courting for a
//     policy that buys nothing over same-origin. Verified in a browser across
//     four policies; same-origin, strict-origin-when-cross-origin and omitting
//     the header all send a usable Origin, and only no-referrer does not.
//
//   - Strict-Transport-Security is emitted only when secure is true (i.e. the
//     deployment serves over HTTPS); it is meaningless over plain HTTP.
func SecurityHeaders(secure bool, assetOrigins ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Frame-Options", "DENY")
			SetContentSecurityPolicy(h, assetOrigins)
			h.Set("X-Content-Type-Options", "nosniff")
			// same-origin, not no-referrer. See the note above: no-referrer makes
			// browsers send "Origin: null" on form POSTs, which fails the CSRF
			// origin check on any browser that sends no Sec-Fetch-Site header.
			h.Set("Referrer-Policy", "same-origin")
			if secure {
				h.Set("Strict-Transport-Security", strictTransportSecurityValue)
			}
			next.ServeHTTP(w, r)
		})
	}
}
