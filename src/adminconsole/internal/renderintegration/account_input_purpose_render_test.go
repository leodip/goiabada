package renderintegration

import (
	"html"
	"regexp"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/countries"
	"github.com/leodip/goiabada/core/locales"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/leodip/goiabada/core/timezones"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// purposeAttrRe reads a control's autocomplete attribute; it must follow whitespace, so a
// data-autocomplete is not read as one.
var purposeAttrRe = regexp.MustCompile(`\sautocomplete="([^"]*)"`)

// controlTag returns the opening tag of the input or select with that id, which may span lines.
func controlTag(t *testing.T, page, id string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<(?:input|select)\b[^>]*\sid="` + regexp.QuoteMeta(id) + `"[^>]*>`).FindString(page)
	require.NotEmpty(t, m, "the page has no control with id %q", id)
	return m
}

// purposeOf is a control's autocomplete token, "" when it declares none.
func purposeOf(t *testing.T, page, id string) string {
	t.Helper()
	if m := purposeAttrRe.FindStringSubmatch(controlTag(t, page, id)); m != nil {
		return m[1]
	}
	return ""
}

// phoneOptionRe matches a phone country option, capturing its value and the rest of its tag.
var phoneOptionRe = regexp.MustCompile(`<option value="([A-Z]{3}_\d+)"([^>]*)>`)

// callingCodeAttrRe reads an option's data-calling-code.
var callingCodeAttrRe = regexp.MustCompile(`\sdata-calling-code="([^"]*)"`)

func profileBind() map[string]interface{} {
	return map[string]interface{}{
		"user":              &api.UserResponse{Id: 7},
		"timezones":         timezones.All(),
		"locales":           locales.All(),
		"page":              "1",
		"query":             "",
		"savedSuccessfully": false,
	}
}

func addressBind() map[string]interface{} {
	return map[string]interface{}{
		"user":              &api.UserResponse{Id: 7},
		"address":           map[string]interface{}{"AddressCountry": "BR"},
		"countries":         countries.All(),
		"page":              "1",
		"query":             "",
		"savedSuccessfully": false,
	}
}

func phoneBind() map[string]interface{} {
	return map[string]interface{}{
		"user":                         &api.UserResponse{Id: 7},
		"selectedPhoneCountryUniqueId": "PRT_0",
		"phoneNumber":                  "912 345 678",
		"phoneCountries":               phonecountries.All(),
		"page":                         "1",
		"query":                        "",
		"savedSuccessfully":            false,
	}
}

// The person's own profile, address and phone pages say what their fields hold (WCAG 2.2 SC 1.3.5
// Identify Input Purpose), so a browser can fill them: the username, the language, the country and
// the phone's country code. The searchable lists' field takes the select's token, so the select
// declares it; the time zone has none and its field stays off (#722 decisions 2, 3 and 6).
func TestRender_AccountPagesDeclareTheirInputPurposes(t *testing.T) {
	profile := renderMenuPage(t, "/account_profile.html", profileBind())
	assert.Equal(t, "username", purposeOf(t, profile, "username"), "the profile's username")
	assert.Equal(t, "language", purposeOf(t, profile, "locale"), "the profile's language and region")
	assert.Empty(t, purposeOf(t, profile, "zoneInfo"), "the profile's time zone")

	address := renderMenuPage(t, "/account_address.html", addressBind())
	assert.Equal(t, "country", purposeOf(t, address, "addressCountry"), "the address's country")

	phone := renderMenuPage(t, "/account_phone.html", phoneBind())
	assert.Equal(t, "tel-country-code", purposeOf(t, phone, "phoneCountryUniqueId"), "the phone's country")
	assert.Equal(t, "tel-national", purposeOf(t, phone, "phoneNumber"), "the phone's number")
}

// Each option of the person's phone country list carries its calling code in the canonical form of
// tel-country-code, "+" and digits, which a fill is matched against exactly: the value is an
// internal identifier and the text is translated (#722 decision 6).
func TestRender_AccountPhoneOptionsCarryTheirCallingCode(t *testing.T) {
	phone := renderMenuPage(t, "/account_phone.html", phoneBind())
	want := map[string]string{"PRT_0": "+351", "GBR_0": "+44", "JEY_0": "+44", "USA_0": "+1", "BRA_0": "+55"}

	options := phoneOptionRe.FindAllStringSubmatch(phone, -1)
	require.Len(t, options, len(phonecountries.All()), "the phone page's options")
	seen := map[string]bool{}
	var without []string
	for _, option := range options {
		code := callingCodeAttrRe.FindStringSubmatch(option[2])
		if code == nil {
			without = append(without, option[1])
			continue
		}
		assert.Regexp(t, `^\+\d+$`, html.UnescapeString(code[1]), "option %s's calling code", option[1])
		if expected, ok := want[option[1]]; ok {
			seen[option[1]] = true
			assert.Equal(t, expected, html.UnescapeString(code[1]), "option %s's calling code", option[1])
		}
	}
	assert.Empty(t, without, "the options that carry no calling code")
	assert.Len(t, seen, len(want), "the options pinned by value")
}

// The administrator's pages about another user declare none of these purposes, since they collect
// data about someone else, which SC 1.3.5 does not cover and autofill would fill with the
// administrator's own (#722, assumed).
func TestRender_AdminUserPagesDeclareNoInputPurposes(t *testing.T) {
	profile := renderMenuPage(t, "/admin_users_profile.html", profileBind())
	assert.Equal(t, "off", purposeOf(t, profile, "username"), "the user's username")
	assert.Empty(t, purposeOf(t, profile, "locale"), "the user's language and region")
	assert.Empty(t, purposeOf(t, profile, "zoneInfo"), "the user's time zone")

	address := renderMenuPage(t, "/admin_users_address.html", addressBind())
	assert.Empty(t, purposeOf(t, address, "addressCountry"), "the user's country")

	phone := renderMenuPage(t, "/admin_users_phone.html", phoneBind())
	assert.Empty(t, purposeOf(t, phone, "phoneCountryUniqueId"), "the user's phone country")
	assert.NotRegexp(t, `\sdata-calling-code=`, phone, "the user's phone country options")
}
