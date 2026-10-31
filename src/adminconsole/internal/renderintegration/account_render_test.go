package renderintegration

import (
	"context"
	"html"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminclienthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/countries"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/leodip/goiabada/core/timezones"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRender_AccountPhone(t *testing.T) {
	bind := map[string]interface{}{
		"selectedPhoneCountryUniqueId": "",
		"phoneNumber":                  "",
		"phoneCountries": []phonecountries.PhoneCountry{
			{UniqueId: "BRA_0", Alpha2: "BR", Emoji: "🇧🇷", CallingCode: "+55", Name: "🇧🇷 - Brazil (+55)"},
			{UniqueId: "ITA_0", Alpha2: "IT", Emoji: "🇮🇹", CallingCode: "+39", Name: "🇮🇹 - Italy (+39)"},
		},
		"savedSuccessfully": false,
	}
	out := renderMenuPage(t, "/account_phone.html", bind)
	// html/template escapes "+" to "&#43;", so assert on the emoji + localized
	// country name (the part the phone-500 bug and the CLDR work affect).
	assert.Contains(t, out, "🇧🇷 - Brasil") // RefPhoneCountry: CLDR-localized name
	assert.Contains(t, out, "🇮🇹 - Itália") // RefPhoneCountry: CLDR-localized name
}

// numberFieldHintRe captures what a phone page renders between its number input and the next
// form control, which is where the hint under the number field belongs.
var numberFieldHintRe = regexp.MustCompile(`(?s)<input[^>]*\sname="phoneNumber"[^>]*>(.*?)<(?:input|button|select)\b`)

// Both phone pages tell the user, under the number field, to type the number as it is dialled from
// another country, after the country code: phone_number is the calling code followed by what was
// typed, so a habitual trunk 0 (the UK's 07700 900123) would become a claim no one can dial (#563
// decision 6).
func TestRender_PhonePagesHintHowToTypeTheNumber(t *testing.T) {
	hints := map[string]string{
		"en":    "Enter the number as it's dialled from another country, after the country code.",
		"pt-BR": "Digite o número como é discado de outro país, depois do código do país.",
	}
	for _, page := range []string{"/account_phone.html", "/admin_users_phone.html"} {
		for locale, hint := range hints {
			t.Run(page+" "+locale, func(t *testing.T) {
				out := renderMenuPageIn(t, page, map[string]interface{}{
					"user":                         &api.UserResponse{Id: 7, Email: "someone@example.com"},
					"selectedPhoneCountryUniqueId": "PRT_0",
					"phoneNumber":                  "912 345 678",
					"phoneNumberVerified":          false,
					"phoneCountries":               phonecountries.All(),
					"page":                         "1",
					"query":                        "",
					"savedSuccessfully":            false,
				}, locale, true)

				m := numberFieldHintRe.FindStringSubmatch(out)
				require.NotNil(t, m, "no form control follows the number field")
				assert.Contains(t, html.UnescapeString(m[1]), hint, "the hint is not under the number field")
			})
		}
	}
}

// The account menu marks Phone as the page the user is on at /account/phone, and at no other path.
func TestRender_AccountMenuMarksThePhonePage(t *testing.T) {
	phoneLinkRe := regexp.MustCompile(`<a class="nav-link" href="/account/phone"([^>]*)>`)
	bind := map[string]interface{}{
		"selectedPhoneCountryUniqueId": "",
		"phoneNumber":                  "",
		"phoneCountries":               phonecountries.All(),
		"savedSuccessfully":            false,
	}

	for _, tc := range []struct {
		path   string
		marked bool
	}{
		{"/account/phone", true},
		{"/account/address", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			m := phoneLinkRe.FindStringSubmatch(renderMenuPageAt(t, tc.path, "/account_phone.html", bind))
			require.NotNil(t, m, "the account menu has no Phone link")
			assert.Equal(t, tc.marked, strings.Contains(m[1], `aria-current="page"`), "the link marked as the current page")
		})
	}
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
	out := renderMenuPage(t, "/account_address.html", bind)
	assert.Contains(t, out, "Itália") // RefCountry: CLDR-localized name
	assert.Contains(t, out, "México")
}

func TestRender_AccountProfile(t *testing.T) {
	bind := map[string]interface{}{
		"user":              &api.UserResponse{},
		"timezones":         timezones.All(),
		"locales":           locales.All(),
		"savedSuccessfully": false,
	}
	out := renderMenuPage(t, "/account_profile.html", bind)
	assert.Contains(t, out, "português (Brasil) (Portuguese (Brazil))") // LocaleLabel
	assert.Contains(t, out, "Estados Unidos")                           // RefTimezone country portion localized
}

// Both profile pages label each locale from locales.Locale.Name, so a template left on a removed
// field fails here on either page rather than on the one TestRender_AccountProfile reads (#432).
func TestRender_ProfilePagesLabelLocalesByName(t *testing.T) {
	for _, page := range []string{"/account_profile.html", "/admin_users_profile.html"} {
		t.Run(page, func(t *testing.T) {
			out := renderMenuPage(t, page, map[string]interface{}{
				"user":              &api.UserResponse{Id: 7},
				"timezones":         timezones.All(),
				"locales":           locales.All(),
				"page":              "1",
				"query":             "",
				"savedSuccessfully": false,
			})

			assert.Contains(t, out, "português (Brasil) (Portuguese (Brazil))")
		})
	}
}

// zoneOptionRe matches a zone picker option, capturing its value and whether it is selected. The
// blank option carries no "___", so it is not one.
var zoneOptionRe = regexp.MustCompile(`<option value="([^"]*___[^"]*)"\s*(selected)?>`)

// A profile stores its zone as the (country name, zone) pair the picker posts, and one zone ID is
// listed under several countries. So the page must select the row the stored pair names, and not
// the first row carrying the zone: a user stored as Sweden/Europe/Berlin reopens on Sweden, though
// Denmark and Germany list the same zone ahead of it, on both profile pages (#432).
func TestRender_ProfilePagesSelectTheStoredZoneRow(t *testing.T) {
	user := &api.UserResponse{Id: 7, ZoneInfoCountryName: "Sweden", ZoneInfo: "Europe/Berlin"}

	for _, page := range []string{"/account_profile.html", "/admin_users_profile.html"} {
		t.Run(page, func(t *testing.T) {
			out := renderMenuPage(t, page, map[string]interface{}{
				"user":              user,
				"timezones":         timezones.All(),
				"locales":           locales.All(),
				"page":              "1",
				"query":             "",
				"savedSuccessfully": false,
			})

			var values, selected []string
			for _, m := range zoneOptionRe.FindAllStringSubmatch(out, -1) {
				value := html.UnescapeString(m[1])
				values = append(values, value)
				if m[2] != "" {
					selected = append(selected, value)
				}
			}
			require.Len(t, values, len(timezones.All()), "one option per zone row")
			assert.Contains(t, values, "Germany___Europe/Berlin", "the row sharing the zone is offered")
			assert.Equal(t, []string{"Sweden___Europe/Berlin"}, selected)
		})
	}
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

	out := renderMenuPage(t, "/account_otp.html", map[string]interface{}{
		"otpEnabled":  false,
		"base64Image": "aW1hZ2UtYnl0ZXM=",
		"secretKey":   secretKey,
		"error":       "OTP code is required.",
	})

	assert.Contains(t, out, "data:image/png;base64,aW1hZ2UtYnl0ZXM=", "the QR code must be shown")
	assert.Contains(t, out, secretKey, "and the seed, for a user who cannot scan it")
	assert.Contains(t, out, `name="otp"`)
	assert.Contains(t, out, `name="password"`)
	assert.Contains(t, out, `name="otpAction" value="enable"`,
		"the form says it enables, so a stale one cannot be read as a disable (#562 decision 8)")
	assert.NotContains(t, out, `value="disable"`)

	assert.NotContains(t, out, `type="hidden"`,
		"the enrolment form must post nothing the user did not type")
	assert.NotContains(t, out, `name="secretKey"`)
	assert.NotContains(t, out, `name="base64Image"`)
}

// The enabled state carries neither, whatever the bind map happens to hold: a user with an
// authenticator is not enrolling, and the page is a disable form.
func TestRender_AccountOtp_Enabled(t *testing.T) {
	out := renderMenuPage(t, "/account_otp.html", map[string]interface{}{
		"otpEnabled": true,
		"error":      "Authentication failed. Check your password and try again.",
	})

	assert.NotContains(t, out, "data:image/png;base64,")
	assert.NotContains(t, out, `name="otp"`)
	assert.Contains(t, out, `name="password"`)
	assert.Contains(t, out, `name="otpAction" value="disable"`,
		"the form says it disables, so a stale one cannot be read as an enrolment (#562 decision 8)")
	assert.NotContains(t, out, `value="enable"`)
}

// Right after two-factor authentication is turned on, the page shows the set of recovery codes,
// each on its own line, with the instruction to save them and the Copy button that copies the list
// (#257 decision 8). The codes are text only: none of them is in a form, so nothing posts them back.
func TestRender_AccountOtp_TheNewSetOfRecoveryCodes(t *testing.T) {
	codes := []string{"7kq2-m9xh-4trw-b3np-j6vd-egac", "0123-4567-89ab-cdef-ghjk-mnpq"}

	out := renderMenuPageIn(t, "/account_otp.html", map[string]interface{}{
		"otpEnabled":    true,
		"recoveryCodes": codes,
	}, "en", true)

	assert.Contains(t, out, "Save your recovery codes")
	assert.Contains(t, out, "They are not shown again.")
	assert.Contains(t, out, `<li>7kq2-m9xh-4trw-b3np-j6vd-egac</li>`)
	assert.Contains(t, out, `<li>0123-4567-89ab-cdef-ghjk-mnpq</li>`)
	assert.Contains(t, out, `data-copy-target="recovery-codes"`, "the Copy button copies the list")
	assert.Contains(t, out, `id="recovery-codes"`)
	assert.Contains(t, out, `name="otpAction" value="disable"`, "the page is still the account's own")
	assert.NotContains(t, out, `value="7kq2`, "no code is a form value")

	without := renderMenuPageIn(t, "/account_otp.html", map[string]interface{}{"otpEnabled": true}, "en", true)
	assert.NotContains(t, without, "Save your recovery codes", "drawn afresh, the page shows no set")
	assert.NotContains(t, without, `id="recovery-codes"`)
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
				"sessions": []render.SessionInfo{{
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
				"sessions": []render.SessionInfo{{
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
			out := renderMenuPage(t, tc.page, tc.bind)

			// The tooltip is on the Device cell, which is also what carries the labels.
			assert.Regexpf(t, `<td(?: [a-z-]+="[^"]*")* title="`+regexp.QuoteMeta(escaped)+`">\s*Chrome 120 Desktop Linux`, out,
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
	// Each page's cells are a list's, labelled for the stacked cards, the phrase beneath the
	// instant.
	startedCell := `">` + started.Format(layout) + `<span class="cell-secondary">há 3 dias</span></td>`
	lastAccessedCell := `">` + lastAccessed.Format(layout) + `<span class="cell-secondary">há 5 minutos</span></td>`

	for _, tc := range []struct {
		name string
		page string
		bind map[string]interface{}
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []render.SessionInfo{{
					UserSessionId: 1, Started: &started, LastAccessed: &lastAccessed,
				}},
			},
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"sessions": []render.SessionInfo{{
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
			out := renderMenuPage(t, tc.page, tc.bind)

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
	out := renderMenuPage(t, "/admin_clients_usersessions.html", map[string]interface{}{
		"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
		"sessions": []adminclienthandlers.SessionInfo{{
			UserSessionId: 1, UserId: 7, UserEmail: "someone@example.com",
		}},
	})

	assert.Regexp(t, `<td(?: [a-z:-]+="[^"]*")*><span class="cell-secondary"></span></td>`, out,
		"a nil instant must render an empty cell")
	assert.NotContains(t, out, "0001", "year 1 is what a zero instant renders as")
}

// The End session buttons of the three sessions pages, the account's, a user's and a client's, which
// carry what their dialog says rather than handing it to a function: data-dialog names the dialog, the one for the
// device in use whose button says it signs out, and data-confirm the sentence, the device label in it
// escaped for the attribute. The script, which ends the session through the route the page's status
// region names, shows that sentence as the dialog's plain message, which is drawn as text (#120,
// #281).
func TestRender_SessionListsAskWithTheirOwnSentence(t *testing.T) {
	const markup = `<script>alert(1)</script>`
	for _, tc := range []struct {
		name   string
		page   string
		bind   map[string]interface{}
		endURL string
	}{
		{
			name: "account",
			page: "/account_user_sessions.html",
			bind: map[string]interface{}{
				"sessions": []render.SessionInfo{
					{UserSessionId: 1, DeviceName: markup, DeviceType: "Desktop", DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true},
					{UserSessionId: 2, DeviceName: "Firefox 128", DeviceType: "Desktop", DeviceOS: "Windows", UserAgent: "curl/8.5.0"},
				},
			},
			endURL: "/account/sessions",
		},
		{
			name: "admin user",
			page: "/admin_users_sessions.html",
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "admin@example.com"},
				"sessions": []render.SessionInfo{
					{UserSessionId: 1, DeviceName: markup, DeviceType: "Desktop", DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true},
					{UserSessionId: 2, DeviceName: "Firefox 128", DeviceType: "Desktop", DeviceOS: "Windows", UserAgent: "curl/8.5.0"},
				},
				"page":  "1",
				"query": "",
			},
			endURL: "/admin/users/7/sessions",
		},
		{
			name: "admin client",
			page: "/admin_clients_usersessions.html",
			bind: map[string]interface{}{
				"client": &api.ClientResponse{Id: 3, ClientIdentifier: "web-app"},
				"sessions": []adminclienthandlers.SessionInfo{
					{UserSessionId: 1, UserId: 7, UserEmail: "admin@example.com", DeviceName: markup, DeviceType: "Desktop", DeviceOS: "Linux", UserAgent: "curl/8.5.0", IsCurrent: true},
					{UserSessionId: 2, UserId: 8, UserEmail: "someone@example.com", DeviceName: "Firefox 128", DeviceType: "Desktop", DeviceOS: "Windows", UserAgent: "curl/8.5.0"},
				},
			},
			endURL: "/admin/clients/3/user-sessions/delete",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderMenuPage(t, tc.page, tc.bind)

			assert.NotContains(t, out, markup, "the device label must never reach the page as markup")
			assert.Regexp(t, `data-end-session="1" data-dialog="endCurrentSession" data-confirm="[^"]*&lt;script&gt;alert\(1\)&lt;/script&gt;`, out,
				"the device in use asks in its own dialog, its label escaped in the sentence")
			assert.Regexp(t, `data-end-session="2" data-dialog="endSession" data-confirm="[^"]*Firefox 128 Desktop Windows`, out)
			assert.Contains(t, out, `id="endSession_modalDialog"`)
			assert.Contains(t, out, `id="endCurrentSession_modalDialog"`)
			assert.Regexp(t, `id="endCurrentSession_btnModal2" class="button button-danger">Encerrar sessão e sair</button>`, out,
				"ending the session in use says it signs out")
			assert.Contains(t, out, `id="sessions-status" role="status" data-end-url="`+tc.endURL+`"`,
				"the status region names the route the session is ended through")
		})
	}

	script, err := fs.ReadFile(web.StaticFS(), "pages/user-sessions.js")
	require.NoError(t, err)
	assert.Contains(t, string(script), `showModalDialog(button.dataset.dialog, sessionsStatus.dataset.confirmTitle, button.dataset.confirm,`,
		"the sentence reaches the dialog as its plain message, which is drawn as text")
	assert.Contains(t, string(script), `url: status.dataset.endUrl,`,
		"the session is ended through the route the page names")
}

// The consent pages' Revoke buttons, held as the sessions pages' are: the sentence, the client's
// name in it escaped, rides in data-confirm, and row-actions.js shows it as the dialog's plain
// message, then posts the body the button names to the route it names.
func TestRender_ConsentPagesAskWithTheirOwnSentence(t *testing.T) {
	const markup = `<b>web-app</b>`
	for _, tc := range []struct {
		name   string
		page   string
		bind   map[string]interface{}
		action string
	}{
		{
			name: "account",
			page: "/account_manage_consents.html",
			bind: map[string]interface{}{
				"consents": []render.ConsentInfo{{ConsentId: 4, Client: "web-app", ClientName: markup, Scope: "openid"}},
			},
			action: `data-action-url="/account/manage-consents" data-action-body="{&#34;consentId&#34;:4}"`,
		},
		{
			name: "admin user",
			page: "/admin_users_consents.html",
			bind: map[string]interface{}{
				"user":     &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"consents": []render.ConsentInfo{{ConsentId: 4, Client: markup, Scope: "openid"}},
				"page":     "1",
				"query":    "",
			},
			action: `data-action-url="/admin/users/7/consents" data-action-body="{&#34;consentId&#34;:4}"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderMenuPage(t, tc.page, tc.bind)

			assert.NotContains(t, out, markup, "the client's name must never reach the page as markup")
			assert.Contains(t, out, tc.action, "the button names the route and the consent it revokes")
			assert.Regexp(t, `data-dialog="revokeConsent"[^>]*data-confirm="[^"]*&lt;b&gt;web-app&lt;/b&gt;`, out)
			assert.Contains(t, out, `id="revokeConsent_modalDialog"`)
			assert.Contains(t, out, `id="row-actions-status" role="status"`)
		})
	}

	script, err := fs.ReadFile(web.StaticFS(), "pages/row-actions.js")
	require.NoError(t, err)
	assert.Contains(t, string(script), `showModalDialog(button.dataset.dialog, title, button.dataset.confirm, null,`,
		"the sentence reaches the dialog as its plain message, which is drawn as text")
	assert.Contains(t, string(script), `bodyData: button.dataset.actionBody || null,`)
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
		cell string
	}{
		{
			name: "account",
			page: "/account_manage_consents.html",
			cell: `<td class="sm:whitespace-nowrap" data-label="Concedido em">16/09/2026 12:00</td>`,
			bind: map[string]interface{}{
				"consents": []render.ConsentInfo{{
					ConsentId: 1, Client: "web-app", ClientDescription: "The web app",
					GrantedAt: &granted, Scope: "openid profile",
				}},
			},
		},
		{
			name: "admin user",
			page: "/admin_users_consents.html",
			cell: `<td class="sm:whitespace-nowrap" data-label="Dado em">16/09/2026 12:00</td>`,
			bind: map[string]interface{}{
				"user": &api.UserResponse{Id: 7, Email: "someone@example.com"},
				"consents": []render.ConsentInfo{{
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
			out := renderMenuPage(t, tc.page, tc.bind)

			assert.Containsf(t, out, tc.cell, "%s: the granted-at cell is not localized", tc.page)
			assert.NotContainsf(t, out, granted.Format(time.RFC1123),
				"%s: RFC1123 names the month and weekday in English under every locale", tc.page)
		})
	}
}

// The account pages name each application as the consent screen did, by its name rather than its
// identifier, and mark a name the application gave itself, as that screen does (#108). The admin
// pages keep the identifier, which is what an administrator knows a client by.
func TestRender_AccountPagesNameApplicationsAsTheConsentScreenDid(t *testing.T) {
	consents := renderMenuPage(t, "/account_manage_consents.html", map[string]interface{}{
		"consents": []render.ConsentInfo{
			{ConsentId: 1, Client: "portal", ClientName: "Customer portal", ClientDescription: "Orders and invoices", Scope: "openid"},
			{ConsentId: 2, Client: "dcr_a3f9", ClientName: "Payroll Portal", ClientNameUnverified: true, Scope: "openid"},
		},
	})
	assert.Contains(t, consents, `<span class="font-semibold">Customer portal</span>`)
	assert.Contains(t, consents, `<span class="cell-secondary">Orders and invoices</span>`)
	assert.Contains(t, consents, `<span class="font-semibold">Payroll Portal</span>`+"\n"+
		`          <span class="tag tag-caution ml-1">Não verificado</span>`)
	assert.Contains(t, consents, `<span class="cell-secondary">Este aplicativo se registrou sozinho e não foi verificado.</span>`)
	assert.NotContains(t, consents, "dcr_a3f9")
	assert.Equal(t, 1, strings.Count(consents, "Não verificado"), "only the unverified name is marked")

	sessions := renderMenuPage(t, "/account_user_sessions.html", map[string]interface{}{
		"sessions": []render.SessionInfo{{
			UserSessionId: 1, DeviceName: "Firefox", DeviceType: "Desktop", DeviceOS: "Linux",
			Clients:     []string{"portal", "dcr_a3f9"},
			ClientNames: []render.ClientName{{Name: "Customer portal"}, {Name: "Payroll Portal", Unverified: true}},
		}},
	})
	assert.Contains(t, sessions, `<li>Customer portal</li><li>Payroll Portal<span class="tag tag-caution ml-1">Não verificado</span></li>`)
	assert.NotContains(t, sessions, "dcr_a3f9")
}

// A consent whose grantedAt is absent renders an empty cell rather than year 1. The column is NOT
// NULL in the database, so this is the shape of a response the console cannot date rather than of
// an ungranted consent (#350), and the guard that used to stand in front of the Format call is now
// the formatter's own nil answer (#373).
func TestRender_ConsentPageRendersAMissingGrantedAtAsBlank(t *testing.T) {
	out := renderMenuPage(t, "/account_manage_consents.html", map[string]interface{}{
		"consents": []render.ConsentInfo{{
			ConsentId: 1, Client: "web-app", Scope: "openid",
		}},
	})

	assert.Contains(t, out, `<td class="sm:whitespace-nowrap" data-label="Concedido em"></td>`, "a nil instant must render an empty cell")
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
				"timezones":         timezones.All(),
				"locales":           locales.All(),
				"savedSuccessfully": false,
			},
		},
		{
			name: "admin user",
			page: "/admin_users_profile.html",
			bind: map[string]interface{}{
				"user":              user,
				"timezones":         timezones.All(),
				"locales":           locales.All(),
				"page":              "1",
				"query":             "",
				"savedSuccessfully": false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := renderMenuPage(t, tc.page, tc.bind)

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

	// form-post.js submits every form marked data-auto-submit as soon as the page is parsed.
	assert.Contains(t, out, `data-auto-submit>`, "the form submits itself; without the hook the visitor waits on the page")
	assert.Contains(t, out, `<script src="/static/form-post.js?v=`, "the page loads the script that submits it")
	script, err := fs.ReadFile(web.StaticFS(), "form-post.js")
	require.NoError(t, err)
	assert.Contains(t, string(script), `document.querySelectorAll("form[data-auto-submit]")`)
	assert.Contains(t, string(script), `form.submit();`)
	assert.Regexp(t, `(?s)<button class="[^"]*" type="submit">[^<]+</button>\s*</form>`, out,
		"a browser without JavaScript still needs a way through: the form's own button")
}

// The sign-out confirmation (#411), through the real template and layout: the GET renders this
// page and changes nothing, so its form is what signs out, and only as a POST, which the origin
// check guards. A form that sent GET would land on this page again and nobody could sign out.
// The layout loads its own scripts, so this asserts what the page's own markup offers, which needs
// none of them: a plain submit and a plain link.
func TestRender_AccountLogoutConfirm(t *testing.T) {
	for _, locale := range []string{"en", "pt-BR"} {
		t.Run(locale, func(t *testing.T) {
			out := renderPage(t, "/layouts/no_menu_layout.html", "/account_logout_confirm.html", nil, nil, locale, true)
			ctx := i18n.WithLocale(context.Background(), true, locale)

			assert.Equal(t, 1, strings.Count(out, "<form "), "exactly one form")
			assert.Contains(t, out, `<form method="post" action="/auth/logout" `,
				"the sign-out is the POST the origin check guards")
			assert.Regexp(t, `(?s)<form method="post" action="/auth/logout"[^>]*>.*<button class="[^"]*" type="submit">`+
				regexp.QuoteMeta(html.EscapeString(i18n.T(ctx, "adminconsole.menu.logout")))+`</button>\s*</div>\s*</form>`, out,
				"a plain submit inside the form, which needs no JavaScript")
			assert.Regexp(t, `<a class="button" href="/">`+regexp.QuoteMeta(html.EscapeString(i18n.T(ctx, "adminconsole.logout_confirm.cancel")))+`</a>`, out,
				"staying signed in goes home and changes nothing")
			assert.Contains(t, out, html.EscapeString(i18n.T(ctx, "adminconsole.logout_confirm.heading")))
			assert.Contains(t, out, html.EscapeString(i18n.T(ctx, "adminconsole.logout_confirm.message")))
		})
	}
}
