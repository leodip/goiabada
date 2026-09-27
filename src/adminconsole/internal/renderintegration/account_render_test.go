package renderintegration

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/countries"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/timezones"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRender_AccountPhone(t *testing.T) {
	bind := map[string]interface{}{
		"selectedPhoneCountryUniqueId": "",
		"phoneNumber":                  "",
		"phoneCountries": []api.PhoneCountryResponse{
			{UniqueId: "BRA_0", Alpha2: "BR", Emoji: "🇧🇷", CallingCode: "+55", Name: "🇧🇷 - Brazil (+55)"},
			{UniqueId: "ITA_0", Alpha2: "IT", Emoji: "🇮🇹", CallingCode: "+39", Name: "🇮🇹 - Italy (+39)"},
		},
		"savedSuccessfully": false,
	}
	out := render(t, "/account_phone.html", bind)
	// html/template escapes "+" to "&#43;", so assert on the emoji + localized
	// country name (the part the phone-500 bug and the CLDR work affect).
	assert.Contains(t, out, "🇧🇷 - Brasil") // RefPhoneCountry: CLDR-localized name
	assert.Contains(t, out, "🇮🇹 - Itália") // RefPhoneCountry: CLDR-localized name
}

func TestRender_AccountAddress(t *testing.T) {
	bind := map[string]interface{}{
		"user": &api.UserResponse{},
		"address": map[string]interface{}{
			"AddressLine": "", "AddressLocality": "", "AddressRegion": "",
			"AddressPostalCode": "", "AddressCountry": "BR",
		},
		"countries":         countries.All(),
		"savedSuccessfully": false,
	}
	out := render(t, "/account_address.html", bind)
	assert.Contains(t, out, "Itália") // RefCountry: CLDR-localized name
	assert.Contains(t, out, "México")
}

func TestRender_AccountProfile(t *testing.T) {
	bind := map[string]interface{}{
		"user":              &api.UserResponse{},
		"timezones":         timezones.Get(),
		"locales":           locales.Get(),
		"savedSuccessfully": false,
	}
	out := render(t, "/account_profile.html", bind)
	assert.Contains(t, out, "português (Brasil) (Portuguese (Brazil))") // LocaleLabel
	assert.Contains(t, out, "Estados Unidos")                           // RefTimezone country portion localized
}

// The enrolment form shows the QR code and the seed, and carries neither back as a hidden input.
//
// Both halves need HTML to see, which is why they are here rather than in the handler's own tests:
// a mocked RenderTemplate is handed a bind map, and a bind map cannot tell you whether a value was
// drawn for the user to scan or planted in a form for the browser to post back.
//
// The hidden inputs are what #247 removed. They put the TOTP shared secret and an image encoding it
// into the submitted body of every enrolment attempt, on a page that then let the server enrol
// whatever came back. The visible <img> and <pre> stay: those are what the user scans and types.
func TestRender_AccountOtp_Enrollment(t *testing.T) {
	const secretKey = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	out := render(t, "/account_otp.html", map[string]interface{}{
		"otpEnabled":  false,
		"base64Image": "aW1hZ2UtYnl0ZXM=",
		"secretKey":   secretKey,
		"error":       "OTP code is required.",
	})

	assert.Contains(t, out, "data:image/png;base64,aW1hZ2UtYnl0ZXM=", "the QR code must be shown")
	assert.Contains(t, out, secretKey, "and the seed, for a user who cannot scan it")
	assert.Contains(t, out, `name="otp"`)
	assert.Contains(t, out, `name="password"`)

	assert.NotContains(t, out, `type="hidden"`,
		"the enrolment form must post nothing the user did not type")
	assert.NotContains(t, out, `name="secretKey"`)
	assert.NotContains(t, out, `name="base64Image"`)
}

// The enabled state carries neither, whatever the bind map happens to hold: a user with an
// authenticator is not enrolling, and the page is a disable form.
func TestRender_AccountOtp_Enabled(t *testing.T) {
	out := render(t, "/account_otp.html", map[string]interface{}{
		"otpEnabled": true,
		"error":      "Authentication failed. Check your password and try again.",
	})

	assert.NotContains(t, out, "data:image/png;base64,")
	assert.NotContains(t, out, `name="otp"`)
	assert.Contains(t, out, `name="password"`)
}

// The Device cell's tooltip, on all three session pages at once.
//
// The raw User-Agent is attacker-chosen: it is a request header copied into the row verbatim, so
// the one thing that needs proving about showing it is that it stays an attribute value. A header
// carrying a quote and an angle bracket is what would break out of title="..." if the cell were
// ever built by concatenation or marked safe, and only rendered HTML can see that (#281 decision 6).
//
// The three pages are one case because they carry one edit between them: the same <td>, in three
// files, and a tooltip added to two of the three is the shape this guards against.
func TestRender_SessionPagesTooltipTheRawUserAgent(t *testing.T) {
	const header = `Mozilla/5.0 "odd" <build>`
	const escaped = `Mozilla/5.0 &#34;odd&#34; &lt;build&gt;`

	for _, tc := range []struct {
		name string
		page string
		bind map[string]interface{}
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []accounthandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: header,
				}},
			},
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"sessions": []adminuserhandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: header,
				}},
				"page":  "1",
				"query": "",
			},
		},
		{
			name: "admin client",
			page: "/admin_clients_usersessions.html",
			bind: map[string]interface{}{
				"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
				"sessions": []adminclienthandlers.SessionInfo{{
					UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
					DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: header,
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			// The tooltip is on the Device cell, which is also what carries the labels.
			assert.Containsf(t, out, `<td title="`+escaped+`">Chrome 120 Desktop Linux`,
				"%s: the Device cell carries no User-Agent tooltip", tc.page)

			// And the header never reaches the page as markup. Counting the escaped form is
			// what says so: one occurrence, and no unescaped one anywhere.
			assert.Equal(t, 1, strings.Count(out, escaped),
				"the header belongs in the tooltip and nowhere else")
			assert.NotContains(t, out, header,
				"the raw header must never reach the page unescaped")
		})
	}
}

// The two timestamp cells of the three session pages, in pt-BR, byte for byte.
//
// Decision 3 of #373 chose a catalog-held numeric layout over Go's RFC1123, which carries English
// month and weekday names under every locale, and a whole translated phrase over a Go duration
// string with a translated suffix glued to it ("72h30m0s atrás"). Both regressions render
// something that merely looks wrong rather than breaking, so the cell is asserted exactly: the
// layout literal below is the pin, and the RFC1123 form of the same instant is asserted absent.
func TestRender_SessionPagesLocalizeTheTimestampCells(t *testing.T) {
	// Relative to now, because the second line of each cell is how long ago the instant was. Both
	// offsets sit half an hour and half a minute clear of their unit boundary, so neither phrase
	// can change while the case runs.
	now := time.Now().UTC()
	started := now.Add(-72*time.Hour - 30*time.Minute)
	lastAccessed := now.Add(-5*time.Minute - 30*time.Second)

	// pt-BR's layout, written out here rather than read from the catalog: this literal is what a
	// layout regressing to RFC1123, or to en's 01/02/2006 3:04 PM, is held against.
	const layout = "02/01/2006 15:04"
	startedCell := "<td>" + started.Format(layout) + "<br />há 3 dias</td>"
	lastAccessedCell := "<td>" + lastAccessed.Format(layout) + "<br />há 5 minutos</td>"

	for _, tc := range []struct {
		name string
		page string
		bind map[string]interface{}
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []accounthandlers.SessionInfo{{
					UserSessionId: 1, Started: &started, LastAccessed: &lastAccessed,
				}},
			},
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"sessions": []adminuserhandlers.SessionInfo{{
					UserSessionId: 1, Started: &started, LastAccessed: &lastAccessed,
				}},
				"page":  "1",
				"query": "",
			},
		},
		{
			name: "admin client",
			page: "/admin_clients_usersessions.html",
			bind: map[string]interface{}{
				"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
				"sessions": []adminclienthandlers.SessionInfo{{
					UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
					Started: &started, LastAccessed: &lastAccessed,
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			assert.Containsf(t, out, startedCell, "%s: the Started cell is not localized", tc.page)
			assert.Containsf(t, out, lastAccessedCell,
				"%s: the Last accessed cell is not localized", tc.page)

			assert.NotContains(t, out, started.Format(time.RFC1123),
				"RFC1123 names the month and weekday in English under every locale")
			assert.NotContains(t, out, "atrás",
				"the relative phrase is one translated string now, not a number with a suffix after it")
		})
	}
}

// A session whose instants are absent renders two empty cells rather than year 1 or a 2026-year
// relative phrase. The client-sessions page is the one that can meet this: its rows come from a
// list endpoint, and a row decoded from a payload written before those columns existed carries nil
// (#373).
func TestRender_SessionPagesRenderAMissingInstantAsBlank(t *testing.T) {
	out := render(t, "/admin_clients_usersessions.html", map[string]interface{}{
		"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
		"sessions": []adminclienthandlers.SessionInfo{{
			UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
		}},
	})

	assert.Contains(t, out, "<td><br /></td>", "a nil instant must render an empty cell")
	assert.NotContains(t, out, "0001", "year 1 is what a zero instant renders as")
}

// The Device label reaches a second sink the tooltip above does not, and this is the case that
// says it arrives there as text.
//
// A label is derived from Sec-CH-UA and Sec-CH-UA-Platform, whose values UA-CH requires a
// server to accept arbitrarily (authserver/internal/useragent pins that premise), so any user
// can put markup in their own session's label by completing a login with hand-written headers.
// On these two pages the End Session button hands that label to endSessionClick, which builds a
// message showModalDialog assigns to innerHTML. html/template escapes the label for the JavaScript
// string literal in the onclick attribute and stops there, so the concatenation is where the
// escaping has to happen, and only rendered HTML can see whether it does (#281).
//
// The third session page passes the user's email rather than the device label to its modal, so
// it is asserted here as the negative: no device concatenation to escape.
func TestRender_SessionPagesEscapeTheDeviceLabelIntoTheModal(t *testing.T) {
	const markup = `<script>alert(1)</script>`

	// The unescaped concatenation, in any spacing. This is the shape that shipped and the shape
	// a later edit would reintroduce; matching on it rather than on the fixed text is what makes
	// the guard survive reformatting.
	unescaped := regexp.MustCompile(`\+\s*device\s*\+`)

	for _, tc := range []struct {
		name       string
		page       string
		bind       map[string]interface{}
		modalTakes bool
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []accounthandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: markup, DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0",
				}},
			},
			modalTakes: true,
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"sessions": []adminuserhandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: markup, DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0",
				}},
				"page":  "1",
				"query": "",
			},
			modalTakes: true,
		},
		{
			name: "admin client",
			page: "/admin_clients_usersessions.html",
			bind: map[string]interface{}{
				"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
				"sessions": []adminclienthandlers.SessionInfo{{
					UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
					DeviceName: markup, DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0",
				}},
			},
			modalTakes: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			// Neither the cell nor the onclick attribute carries the label as markup: the cell
			// is HTML text and the attribute is a JavaScript string literal, and html/template
			// escapes each for its own context.
			assert.NotContains(t, out, markup,
				"the device label must never reach the page as markup")
			assert.Contains(t, out, "&lt;script&gt;alert(1)&lt;/script&gt;",
				"the label belongs in the Device cell, as text")

			if !tc.modalTakes {
				assert.NotContains(t, out, "escapeHtml(device)")
				assert.NotRegexp(t, unescaped, out,
					"this page's modal takes the email, so no device label reaches it")
				return
			}

			// And the script that reads it back out of the attribute escapes it before the
			// innerHTML sink. Dropping the call leaves every other assertion here passing.
			assert.Contains(t, out, "escapeHtml(device)",
				"the device label must be escaped before showModalDialog assigns it to innerHTML")
			assert.NotRegexp(t, unescaped, out,
				"the device label must not be concatenated into the modal message unescaped")
		})
	}
}

// The End Session button's arguments against endSessionClick's parameters, on all three session
// pages.
//
// Folded in with #281: the admin-client page declared six parameters -- it kept a `device` the
// body never reads, unlike the two pages whose modal names the device -- and its button passed
// five, so `IsCurrent` landed in `device` and `isCurrent` was always undefined. The "you are
// ending your own session" warning could therefore never appear on that page, although its
// handler sets the flag. JavaScript pads a short call with undefined rather than failing, so
// nothing anywhere reported it: not the renderer, not the browser, not a handler test that
// only sees the bind.
//
// Counting rather than pinning the argument lists is what makes this a guard for the next edit
// as well as this one: a parameter added to one page's function and not to its button, in
// either direction, is the same defect and fails here too. The fixture values carry no comma,
// which is what lets the count be commas plus one.
func TestRender_SessionPagesPassEveryArgumentEndSessionClickDeclares(t *testing.T) {
	declRe := regexp.MustCompile(`function endSessionClick\(([^)]*)\)`)
	callRe := regexp.MustCompile(`onclick="endSessionClick\(([^)]*)\)`)

	for _, tc := range []struct {
		name string
		page string
		bind map[string]interface{}
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []accounthandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true,
				}},
			},
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"sessions": []adminuserhandlers.SessionInfo{{
					UserSessionId: 1, DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true,
				}},
				"page":  "1",
				"query": "",
			},
		},
		{
			name: "admin client",
			page: "/admin_clients_usersessions.html",
			bind: map[string]interface{}{
				"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
				"sessions": []adminclienthandlers.SessionInfo{{
					UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
					DeviceName: "Chrome 120", DeviceType: "Desktop",
					DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true,
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			decl := declRe.FindStringSubmatch(out)
			require.NotNilf(t, decl, "%s: no endSessionClick declaration", tc.page)
			call := callRe.FindStringSubmatch(out)
			require.NotNilf(t, call, "%s: no End Session button", tc.page)

			assert.Equal(t, strings.Count(decl[1], ",")+1, strings.Count(call[1], ",")+1,
				"%s: endSessionClick(%s) is called with (%s)", tc.page, decl[1], call[1])

			// The flag is the argument the mismatch swallowed, and it is the last one on every
			// page, so pinning it is what says the count above lines up where it matters.
			assert.True(t, strings.HasSuffix(strings.TrimSpace(decl[1]), "isCurrent"),
				"%s: isCurrent is expected last, got (%s)", tc.page, decl[1])
			assert.True(t, strings.HasSuffix(strings.TrimSpace(call[1]), "true"),
				"%s: the current session must pass true last, got (%s)", tc.page, call[1])
		})
	}
}

// The two consent pages, which are two of decision 8's seven other dates (#373). Each rendered
// GrantedAt as an English RFC1123 string its handler had already formatted -- "Wed, 16 Sep 2026
// 12:00:00 UTC" beside Portuguese column headings -- and each now binds the instant and lets the
// page format it. They are one case because they are one edit made twice, in two packages, and a
// fix applied to the account page alone is the shape this guards against.
func TestRender_ConsentPagesLocalizeTheGrantedAtCell(t *testing.T) {
	granted := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		page string
		bind map[string]interface{}
	}{
		{
			name: "account",
			page: "/account_manage_consents.html",
			bind: map[string]interface{}{
				"consents": []accounthandlers.ConsentInfo{{
					ConsentId: 1, Client: "web-app", ClientDescription: "The web app",
					GrantedAt: &granted, Scope: "openid profile",
				}},
			},
		},
		{
			name: "admin user",
			page: "/admin_users_consents.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"consents": []adminuserhandlers.ConsentInfo{{
					ConsentId: 1, Client: "web-app", ClientDescription: "The web app",
					GrantedAt: &granted, Scope: "openid profile",
				}},
				"page":              "1",
				"query":             "",
				"savedSuccessfully": false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			assert.Containsf(t, out, "<td>16/09/2026 12:00</td>",
				"%s: the granted-at cell is not localized", tc.page)
			assert.NotContainsf(t, out, granted.Format(time.RFC1123),
				"%s: RFC1123 names the month and weekday in English under every locale", tc.page)
		})
	}
}

// A consent whose grantedAt is absent renders an empty cell rather than year 1. The column is NOT
// NULL in the database, so this is the shape of a response the console cannot date rather than of
// an ungranted consent (#350), and the guard that used to stand in front of the Format call is now
// the formatter's own nil answer (#373).
func TestRender_ConsentPageRendersAMissingGrantedAtAsBlank(t *testing.T) {
	out := render(t, "/account_manage_consents.html", map[string]interface{}{
		"consents": []accounthandlers.ConsentInfo{{
			ConsentId: 1, Client: "web-app", Scope: "openid",
		}},
	})

	assert.Contains(t, out, "<td></td>", "a nil instant must render an empty cell")
	assert.NotContains(t, out, "0001", "year 1 is what a zero instant renders as")
}

// Decision 8's exclusion, kept deliberately (#373). The dateOfBirth input is not a date the page
// shows a reader: it is a form value the server parses back with a "2006-01-02" layout, so
// localizing it would break the round trip on the next save -- silently, for pt-BR, since
// "02/01/2026" parses as neither. The two inputs look like an oversight to anyone sweeping the
// console for unlocalized dates, and this case is what stops that sweep "finishing the job".
func TestRender_ProfilePagesKeepTheDateOfBirthMachineFormat(t *testing.T) {
	born := time.Date(1990, 1, 2, 0, 0, 0, 0, time.UTC)
	user := &api.UserResponse{Id: 7, Email: "someone@example.com", BirthDate: &born}

	for _, tc := range []struct {
		name string
		page string
		bind map[string]interface{}
	}{
		{
			name: "account",
			page: "/account_profile.html",
			bind: map[string]interface{}{
				"user":              user,
				"timezones":         timezones.Get(),
				"locales":           locales.Get(),
				"savedSuccessfully": false,
			},
		},
		{
			name: "admin user",
			page: "/admin_users_profile.html",
			bind: map[string]interface{}{
				"user":              user,
				"timezones":         timezones.Get(),
				"locales":           locales.Get(),
				"page":              "1",
				"query":             "",
				"savedSuccessfully": false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := render(t, tc.page, tc.bind)

			assert.Containsf(t, out, `value="1990-01-02"`,
				"%s: the dateOfBirth input must stay the machine format the server parses back", tc.page)
			assert.NotContainsf(t, out, `value="02/01/1990"`,
				"%s: the catalog layout here would break the form's round trip", tc.page)
		})
	}
}

// Seam 4 for the logout form binding (#350 decision 2). The only seam that reads the real template
// through the real layout, and so the only one that can see the page a browser would receive.
//
// What it asserts is what the browser would submit and where: one POST form, an action equal to the
// endpoint the API named with nothing appended to it, a hidden input per parameter, and the hook
// that submits it. The action matters most. Building the same parameters into a query string here
// would leave every other case in this package green while restoring exactly the leak this mode
// closes, because the id_token_hint would be back in a top-level navigation's URL.
//
// Where it stops: no browser executes here, so that the submission actually fires is the code gate's
// to confirm. This case sees the hook declared, not run.
func TestRender_AccountLogoutFormPost(t *testing.T) {
	// The host deliberately does not start "auth.": rawKeyRe in helpers_test.go reads
	// "auth.example.com" as a leaked catalog key, which is a property of the fixture and not of the
	// page.
	const endpoint = "https://op.example.com/auth/logout"
	params := map[string]string{
		"id_token_hint":            "eyJhbGciOiJSUzI1NiJ9.e30.sig",
		"post_logout_redirect_uri": "https://console.example.com/",
		"state":                    "a-state",
	}

	out := renderWithLayout(t, "/layouts/no_menu_layout.html", "/account_logout_form_post.html",
		map[string]interface{}{"endpoint": endpoint, "params": params})

	assert.Equal(t, 1, strings.Count(out, "<form "), "exactly one form, so document.forms is unambiguous")
	assert.Contains(t, out, `method="post"`, "the whole point of this page is the POST binding")
	assert.Contains(t, out, `action="`+endpoint+`"`,
		"the action is the endpoint the API named, with nothing appended")

	for name, value := range params {
		assert.Containsf(t, out, `name="`+name+`" value="`+value+`"`,
			"%s must reach the form as a hidden input", name)
	}

	// The hint reaches the page exactly once, in the field it belongs in. A second occurrence would
	// be it in a URL: an action, a link or a script, which is the leak this mode exists to close.
	assert.Equal(t, 1, strings.Count(out, params["id_token_hint"]),
		"the id_token_hint appears only as a form field, never in a URL")
	assert.NotContains(t, out, endpoint+"?", "nothing may turn the endpoint back into a query string")

	assert.Contains(t, out, `document.getElementById("logoutForm").submit()`,
		"the form submits itself; without the hook the visitor sits on a blank page")
	assert.Contains(t, out, "<noscript>", "a browser without JavaScript still needs a way through")
}
