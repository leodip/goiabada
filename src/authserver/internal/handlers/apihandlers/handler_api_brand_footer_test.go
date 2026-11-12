package apihandlers

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A brand's footer links and support contact in the admin API (#814 decisions 1, 5, 9 and 10), one
// rule per case, through the create and update handlers with the generated database mock: each
// refusal's code and the member error_field points at, each bound at its limit, what is stored and
// answered, and the two audit events.

// footerLink is a footer link as a request body names it.
func footerLink(url, label string, labels map[string]any) map[string]any {
	link := map[string]any{"url": url, "label": label}
	if labels != nil {
		link["labels"] = labels
	}
	return link
}

// withFooterLinks is a valid brand body whose footer links are links.
func withFooterLinks(links ...any) map[string]any {
	body := validBrandBody()
	body["footerLinks"] = links
	return body
}

// withContact is a valid brand body with one contact member set.
func withContact(member, value string) map[string]any {
	body := validBrandBody()
	body[member] = value
	return body
}

var (
	privacyLink = footerLink("https://acme.example/privacy", "Privacy", nil)
	statusLink  = footerLink("https://status.acme.example", "Status", nil)
)

// 256 characters: "https://acme.example/" is 21.
var url256 = "https://acme.example/" + strings.Repeat("a", 235)

// emailOf is an address of n characters, 74 or more, of the account address shape: 64 before the
// @, the longest part RFC 5321 delivers to, and the rest a domain of labels of at most 63.
func emailOf(n int) string {
	domain := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", n-64-1-63-1-63-1-4) + ".com"
	return strings.Repeat("a", 64) + "@" + domain
}

var email254 = emailOf(254)

// brandFooterRefusals are the refusals of the footer links and the contact, each decided on the
// request alone. field is the JSON Pointer error_field holds, and empty where the answer has none.
var brandFooterRefusals = []struct {
	name  string
	body  map[string]any
	code  string
	field string
}{
	// A fourth link is refused, never dropped (decision 5).
	{"a fourth link", withFooterLinks(privacyLink, statusLink, privacyLink, statusLink),
		"handler.brand.footer_links_too_many", "/footerLinks/3"},

	{"a link with no label", withFooterLinks(privacyLink, map[string]any{"url": "https://acme.example/terms"}),
		"handler.brand.footer_link_label_required", "/footerLinks/1/label"},
	{"a label of spaces", withFooterLinks(footerLink("https://acme.example/terms", "  \t ", nil)),
		"handler.brand.footer_link_label_required", "/footerLinks/0/label"},
	{"a label of 41 characters", withFooterLinks(statusLink, privacyLink, footerLink("https://acme.example/terms", strings.Repeat("é", 41), nil)),
		"handler.brand.footer_link_label_too_long", "/footerLinks/2/label"},
	{"a label with an opening angle bracket", withFooterLinks(footerLink("https://acme.example/terms", "Terms <b", nil)),
		"handler.brand.footer_link_label_angle_brackets", "/footerLinks/0/label"},
	{"a label with a closing angle bracket", withFooterLinks(footerLink("https://acme.example/terms", "Terms>", nil)),
		"handler.brand.footer_link_label_angle_brackets", "/footerLinks/0/label"},

	{"a language tag in lower case", withFooterLinks(privacyLink, footerLink("https://acme.example/terms", "Terms", map[string]any{"pt-br": "Termos"})),
		"handler.brand.footer_link_language_invalid", "/footerLinks/1/labels/pt-br"},
	{"a language that is not built in", withFooterLinks(footerLink("https://acme.example/terms", "Terms", map[string]any{"nl": "Voorwaarden"})),
		"handler.brand.footer_link_language_invalid", "/footerLinks/0/labels/nl"},
	// RFC 6901 section 3: "~" is written "~0" and "/" is written "~1" in a reference token.
	{"a language tag holding a slash and a tilde", withFooterLinks(footerLink("https://acme.example/terms", "Terms", map[string]any{"en/~x": "Terms"})),
		"handler.brand.footer_link_language_invalid", "/footerLinks/0/labels/en~1~0x"},
	{"a language label of 41 characters", withFooterLinks(footerLink("https://acme.example/terms", "Terms", map[string]any{"de": strings.Repeat("ß", 41)})),
		"handler.brand.footer_link_language_label_too_long", "/footerLinks/0/labels/de"},
	{"a language label with an angle bracket", withFooterLinks(statusLink, footerLink("https://acme.example/terms", "Terms", map[string]any{"pt-BR": "<Termos"})),
		"handler.brand.footer_link_language_label_angle_brackets", "/footerLinks/1/labels/pt-BR"},

	{"a link with no URL", withFooterLinks(map[string]any{"label": "Terms"}),
		"handler.brand.footer_link_url_required", "/footerLinks/0/url"},
	{"a URL of spaces", withFooterLinks(privacyLink, footerLink("   ", "Terms", nil)),
		"handler.brand.footer_link_url_required", "/footerLinks/1/url"},
	{"a URL of 257 characters", withFooterLinks(footerLink(url256+"a", "Terms", nil)),
		"handler.brand.footer_link_url_too_long", "/footerLinks/0/url"},
	{"an http: URL", withFooterLinks(footerLink("http://acme.example/terms", "Terms", nil)),
		"handler.brand.footer_link_url_invalid", "/footerLinks/0/url"},
	{"a URL showing one site and opening another", withFooterLinks(footerLink("https://acme.com@other.example", "Terms", nil)),
		"handler.brand.footer_link_url_invalid", "/footerLinks/0/url"},
	{"a URL with a user name and password", withFooterLinks(footerLink("https://user:secret@acme.example/terms", "Terms", nil)),
		"handler.brand.footer_link_url_invalid", "/footerLinks/0/url"},
	{"a URL with no host", withFooterLinks(footerLink("https:///terms", "Terms", nil)),
		"handler.brand.footer_link_url_invalid", "/footerLinks/0/url"},
	{"a URL with a port and no host", withFooterLinks(footerLink("https://:443/terms", "Terms", nil)),
		"handler.brand.footer_link_url_invalid", "/footerLinks/0/url"},
	{"a URL with no slashes after the scheme", withFooterLinks(footerLink("https:acme.example", "Terms", nil)),
		"handler.brand.footer_link_url_invalid", "/footerLinks/0/url"},
	{"a relative URL", withFooterLinks(footerLink("/terms", "Terms", nil)),
		"handler.brand.footer_link_url_invalid", "/footerLinks/0/url"},
	{"a javascript: URL", withFooterLinks(footerLink("javascript:alert(1)", "Terms", nil)),
		"handler.brand.footer_link_url_invalid", "/footerLinks/0/url"},

	// The contact's refusals are one code per field, as every other brand field's, and set no
	// error_field (decision 10).
	{"an email address with no @", withContact("supportEmail", "support.acme.example"), "handler.brand.support_email_invalid", ""},
	{"an email address with two dots in a row", withContact("supportEmail", "help..desk@acme.example"), "handler.brand.support_email_invalid", ""},
	{"an email address of 255 characters", withContact("supportEmail", emailOf(255)), "handler.brand.support_email_too_long", ""},
	{"an http: support page", withContact("supportUrl", "http://help.acme.example"), "handler.brand.support_url_invalid", ""},
	{"a support page with a user name", withContact("supportUrl", "https://acme.com@help.example"), "handler.brand.support_url_invalid", ""},
	{"a relative support page", withContact("supportUrl", "/help"), "handler.brand.support_url_invalid", ""},
	{"a support page of 257 characters", withContact("supportUrl", url256+"a"), "handler.brand.support_url_too_long", ""},
	{"a phone number with no plus", withContact("supportPhone", "555 0100"), "handler.brand.support_phone_invalid", ""},
	{"a phone number whose first digit is zero", withContact("supportPhone", "+044 20 7946 0958"), "handler.brand.support_phone_invalid", ""},
	{"a phone number of 16 digits", withContact("supportPhone", "+1234567890123456"), "handler.brand.support_phone_invalid", ""},
	{"a phone number with a letter", withContact("supportPhone", "+1 555 CALL"), "handler.brand.support_phone_invalid", ""},
	{"a phone number with a plus inside it", withContact("supportPhone", "+1 555+0100"), "handler.brand.support_phone_invalid", ""},
	{"a phone number with a slash", withContact("supportPhone", "+1 555/0100"), "handler.brand.support_phone_invalid", ""},
	{"a plus alone", withContact("supportPhone", "+"), "handler.brand.support_phone_invalid", ""},
	{"separators alone", withContact("supportPhone", "+ ( ) - ."), "handler.brand.support_phone_invalid", ""},
}

func TestBrandFooter_CreateRefusals(t *testing.T) {
	for _, c := range brandFooterRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)

			status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPost, c.body))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			assertErrorField(t, c.field, answer)
			database.AssertNotCalled(t, "CreateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

func TestBrandFooter_UpdateRefusals(t *testing.T) {
	for _, c := range brandFooterRefusals {
		t.Run(c.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(3)).
				Return(storedBrand(3, "Acme", record.BrandAppearanceDark, "plum"), nil).Once()

			status, answer := serveBrand(HandleBrandUpdatePut(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPut, c.body, "id", "3"))

			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, errorCode(answer))
			assertErrorField(t, c.field, answer)
			database.AssertNotCalled(t, "UpdateBrand", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}

// assertErrorField checks the answer's error_field: the pointer, or no member at all.
func assertErrorField(t *testing.T, want string, answer map[string]any) {
	t.Helper()
	got, present := answer["error_field"]
	if want == "" {
		assert.False(t, present, "error_field is %v", got)
		return
	}
	assert.Equal(t, want, got)
}

// A refusal of a member with a code of its own, such as the name, sets no error_field beside a
// footer link (decision 10).
func TestBrandFooter_TheNamesRefusalSetsNoErrorField(t *testing.T) {
	database := datamocks.NewDatabase(t)
	body := withFooterLinks(privacyLink)
	body["name"] = ""

	status, answer := serveBrand(HandleBrandCreatePost(database, handlersmocks.NewAuditLogger(t), brandBaseURL),
		brandRequest(t, http.MethodPost, body))

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.brand.name_required", errorCode(answer))
	assertErrorField(t, "", answer)
}

// The sentences name the link by its number counted from 1, for a person (decision 10).
func TestBrandFooter_TheSentenceNamesTheLinkByItsNumber(t *testing.T) {
	cases := []struct {
		body map[string]any
		want string
	}{
		{withFooterLinks(privacyLink, statusLink, privacyLink, statusLink), "A brand has at most 3 footer links."},
		{withFooterLinks(privacyLink, map[string]any{"url": "https://acme.example/terms"}), "Link 2 needs a label."},
		{withFooterLinks(footerLink("https://acme.example/terms", strings.Repeat("a", 41), nil)), "The label of link 1 cannot exceed 40 characters."},
		{withFooterLinks(statusLink, footerLink("https://acme.example/terms", "Terms", map[string]any{"nl": "Voorwaarden"})),
			"Link 2 has a label for nl, which is not a built-in language."},
		{withFooterLinks(privacyLink, statusLink, footerLink("https://acme.example/terms", "Terms", map[string]any{"fr": strings.Repeat("a", 41)})),
			"The fr label of link 3 cannot exceed 40 characters."},
		{withFooterLinks(footerLink("http://acme.example/terms", "Terms", nil)),
			"The URL of link 1 must start with https:// and name a site, with no user name or password."},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			_, answer := serveBrand(HandleBrandCreatePost(datamocks.NewDatabase(t), handlersmocks.NewAuditLogger(t), brandBaseURL),
				brandRequest(t, http.MethodPost, c.body))

			assert.Equal(t, c.want, answer["error_description"])
		})
	}
}

// expectCreate records the brand a create writes, stamping it as the data layer does.
func expectCreate(database *datamocks.Database, stored *record.Brand) {
	database.On("CreateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		brand := args.Get(2).(*record.Brand)
		*stored = *brand
		brand.Id = 7
		brand.CreatedAt = sql.NullTime{Time: brandTime, Valid: true}
		brand.UpdatedAt = sql.NullTime{Time: brandTime, Valid: true}
	}).Return(nil).Once()
}

// Each bound is taken at its limit: three links, a 40-character label and language label, a
// 256-character URL and support page, a 254-character address, and 15 digits.
func TestBrandFooter_EachBoundIsTakenAtItsLimit(t *testing.T) {
	label40 := strings.Repeat("é", 40)
	body := withFooterLinks(
		footerLink(url256, label40, map[string]any{"de": strings.Repeat("ß", 40)}),
		statusLink,
		privacyLink,
	)
	body["supportEmail"] = email254
	body["supportUrl"] = url256
	body["supportPhone"] = "+123456789012345"
	database := datamocks.NewDatabase(t)
	var stored record.Brand
	expectCreate(database, &stored)
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()

	status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL), brandRequest(t, http.MethodPost, body))

	require.Equal(t, http.StatusCreated, status, "%v", answer)
	require.Len(t, stored.FooterLinks, 3)
	assert.Equal(t, record.BrandFooterLink{URL: url256, Label: label40, Labels: map[string]string{"de": strings.Repeat("ß", 40)}},
		stored.FooterLinks[0])
	assert.Equal(t, email254, stored.SupportEmail)
	assert.Equal(t, url256, stored.SupportURL)
	assert.Equal(t, "+123456789012345", stored.SupportPhone)
}

// A create stores the links in the order sent and the contact, each value trimmed, a blank language
// label dropped and the phone number without its separators, answers the four members, and audits
// the contact and each link's URL in order (decisions 1, 5 and 9).
func TestBrandFooter_CreateStoresAnswersAndAudits(t *testing.T) {
	body := withFooterLinks(
		footerLink(" https://acme.example/privacy ", " Privacy ", map[string]any{
			"pt-BR": " Privacidade ", "de": "Datenschutz", "fr": "  ", "es": ""}),
		footerLink("https://status.acme.example", "Status", map[string]any{}),
		map[string]any{"url": "https://acme.example", "label": "Acme", "labels": nil},
	)
	body["supportEmail"] = "  help@acme.example "
	body["supportUrl"] = " https://help.acme.example/contact "
	body["supportPhone"] = " +1 (555) 010-0199 "
	database := datamocks.NewDatabase(t)
	var stored record.Brand
	expectCreate(database, &stored)
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, map[string]interface{}{
		"brand_id": int64(7), "brand_name": "Acme",
		"support_email": "help@acme.example", "support_url": "https://help.acme.example/contact", "support_phone": "+15550100199",
		"footer_link_urls": []string{"https://acme.example/privacy", "https://status.acme.example", "https://acme.example"},
		"logged_in_user":   brandCaller,
	}).Once()

	status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL), brandRequest(t, http.MethodPost, body))

	require.Equal(t, http.StatusCreated, status, "%v", answer)
	assert.Equal(t, record.BrandFooterLinks{
		{URL: "https://acme.example/privacy", Label: "Privacy", Labels: map[string]string{"pt-BR": "Privacidade", "de": "Datenschutz"}},
		{URL: "https://status.acme.example", Label: "Status"},
		{URL: "https://acme.example", Label: "Acme"},
	}, stored.FooterLinks)
	assert.Equal(t, "help@acme.example", stored.SupportEmail)
	assert.Equal(t, "https://help.acme.example/contact", stored.SupportURL)
	assert.Equal(t, "+15550100199", stored.SupportPhone)

	assert.Equal(t, []any{
		map[string]any{"url": "https://acme.example/privacy", "label": "Privacy",
			"labels": map[string]any{"pt-BR": "Privacidade", "de": "Datenschutz"}},
		map[string]any{"url": "https://status.acme.example", "label": "Status", "labels": map[string]any{}},
		map[string]any{"url": "https://acme.example", "label": "Acme", "labels": map[string]any{}},
	}, brandAt(answer, "brand", "footerLinks"))
	assert.Equal(t, "help@acme.example", brandAt(answer, "brand", "supportEmail"))
	assert.Equal(t, "https://help.acme.example/contact", brandAt(answer, "brand", "supportUrl"))
	assert.Equal(t, "+15550100199", brandAt(answer, "brand", "supportPhone"))
}

// The phone number is taken as typed, with spaces, hyphens, dots and parentheses, and stored
// without them (decision 11).
func TestBrandFooter_ThePhoneNumberIsStoredWithoutSeparators(t *testing.T) {
	cases := map[string]string{
		"+44 20 7946 0958":   "+442079460958",
		"+49-30-901820":      "+4930901820",
		"+33.1.42.68.53.00":  "+33142685300",
		"+1 (212) 555-0123":  "+12125550123",
		"(+351) 21 000 0000": "+351210000000",
		"+15550100199":       "+15550100199",
		"+1":                 "+1",
	}
	for typed, want := range cases {
		t.Run(typed, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			var stored record.Brand
			expectCreate(database, &stored)
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()

			status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
				brandRequest(t, http.MethodPost, withContact("supportPhone", typed)))

			require.Equal(t, http.StatusCreated, status, "%v", answer)
			assert.Equal(t, want, stored.SupportPhone)
			assert.Equal(t, want, brandAt(answer, "brand", "supportPhone"))
		})
	}
}

// Footer links and every contact member left out, null, [] or "" mean no links and an unset
// contact, and are answered as [] and "" (decision 9). Nothing of the footer is audited.
func TestBrandFooter_LeftOutNullAndEmptyMeanNone(t *testing.T) {
	cases := map[string]func(body map[string]any){
		"left out": func(map[string]any) {},
		"null": func(b map[string]any) {
			b["footerLinks"], b["supportEmail"], b["supportUrl"], b["supportPhone"] = nil, nil, nil, nil
		},
		"empty": func(b map[string]any) {
			b["footerLinks"], b["supportEmail"], b["supportUrl"], b["supportPhone"] = []any{}, "", "", ""
		},
		"spaces": func(b map[string]any) {
			b["footerLinks"], b["supportEmail"], b["supportUrl"], b["supportPhone"] = []any{}, "  ", " ", "\t"
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			body := validBrandBody()
			edit(body)
			database := datamocks.NewDatabase(t)
			var stored record.Brand
			expectCreate(database, &stored)
			auditLogger := handlersmocks.NewAuditLogger(t)
			auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, map[string]interface{}{
				"brand_id": int64(7), "brand_name": "Acme", "logged_in_user": brandCaller,
			}).Once()

			status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL), brandRequest(t, http.MethodPost, body))

			require.Equal(t, http.StatusCreated, status, "%v", answer)
			assert.Nil(t, stored.FooterLinks)
			assert.Equal(t, []string{"", "", ""}, []string{stored.SupportEmail, stored.SupportURL, stored.SupportPhone})
			assert.Equal(t, []any{}, brandAt(answer, "brand", "footerLinks"))
			assert.Empty(t, brandAt(answer, "brand", "supportEmail"))
			assert.Empty(t, brandAt(answer, "brand", "supportUrl"))
			assert.Empty(t, brandAt(answer, "brand", "supportPhone"))
		})
	}
}

// A link's labels left out, null, {} or holding only blanks are no labels, stored as none.
func TestBrandFooter_LabelsLeftOutNullOrBlankAreNone(t *testing.T) {
	links := []any{
		map[string]any{"url": "https://acme.example/a", "label": "A"},
		map[string]any{"url": "https://acme.example/b", "label": "B", "labels": nil},
		map[string]any{"url": "https://acme.example/c", "label": "C", "labels": map[string]any{}},
	}
	for _, link := range links {
		database := datamocks.NewDatabase(t)
		var stored record.Brand
		expectCreate(database, &stored)
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()

		status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPost, withFooterLinks(link)))

		require.Equal(t, http.StatusCreated, status, "%v", answer)
		require.Len(t, stored.FooterLinks, 1)
		assert.Nil(t, stored.FooterLinks[0].Labels, "%v", link)
		assert.Equal(t, map[string]any{}, brandAt(answer, "brand", "footerLinks").([]any)[0].(map[string]any)["labels"])
	}

	t.Run("blank labels only", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		var stored record.Brand
		expectCreate(database, &stored)
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()

		status, _ := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPost, withFooterLinks(footerLink("https://acme.example", "Acme",
				map[string]any{"en": " ", "it": ""}))))

		require.Equal(t, http.StatusCreated, status)
		require.Len(t, stored.FooterLinks, 1)
		assert.Nil(t, stored.FooterLinks[0].Labels)
	})

	t.Run("every built-in language", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		var stored record.Brand
		expectCreate(database, &stored)
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventCreatedBrand, mock.Anything).Once()
		labels := map[string]any{"en": "Help", "de": "Hilfe", "es": "Ayuda", "fr": "Aide", "it": "Aiuto", "pt-BR": "Ajuda"}

		status, answer := serveBrand(HandleBrandCreatePost(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPost, withFooterLinks(footerLink("https://help.acme.example", "Help", labels))))

		require.Equal(t, http.StatusCreated, status, "%v", answer)
		assert.Equal(t, map[string]string{"en": "Help", "de": "Hilfe", "es": "Ayuda", "fr": "Aide", "it": "Aiuto", "pt-BR": "Ajuda"},
			stored.FooterLinks[0].Labels)
	})
}

// storedFooterBrand is a brand with three footer links, the first with a label in every built-in
// language, and all three contact values.
func storedFooterBrand() *record.Brand {
	stored := storedBrand(5, "Acme", record.BrandAppearanceLight, "guava")
	stored.FooterLinks = record.BrandFooterLinks{
		{URL: "https://acme.example/privacy", Label: "Privacy", Labels: map[string]string{
			"en": "Privacy notice", "de": "Datenschutz", "es": "Privacidad", "fr": "Confidentialité", "it": "Privacy", "pt-BR": "Privacidade"}},
		{URL: "https://status.acme.example", Label: "Status"},
		{URL: "https://acme.example", Label: "Acme & Co"},
	}
	stored.SupportEmail = "help+brand%desk@acme.example"
	stored.SupportURL = "https://help.acme.example"
	stored.SupportPhone = "+15550100199"
	return stored
}

// A brand read and sent back as it came is saved unchanged, its links and contact included
// (decision 9), and the answer is the read's.
func TestBrandFooter_ABrandReadAndWrittenBackIsUnchanged(t *testing.T) {
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(storedFooterBrand(), nil).Twice()
	database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
		Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Twice()
	database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Twice()
	var written record.Brand
	database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
		written = *args.Get(2).(*record.Brand)
	}).Return(nil).Once()
	auditLogger := handlersmocks.NewAuditLogger(t)
	auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, mock.Anything).Once()

	status, read := serveBrand(HandleBrandGet(database, brandBaseURL), brandRequest(t, http.MethodGet, nil, "id", "5"))
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, []any{
		map[string]any{"url": "https://acme.example/privacy", "label": "Privacy", "labels": map[string]any{
			"en": "Privacy notice", "de": "Datenschutz", "es": "Privacidad", "fr": "Confidentialité", "it": "Privacy", "pt-BR": "Privacidade"}},
		map[string]any{"url": "https://status.acme.example", "label": "Status", "labels": map[string]any{}},
		map[string]any{"url": "https://acme.example", "label": "Acme & Co", "labels": map[string]any{}},
	}, brandAt(read, "brand", "footerLinks"))

	status, again := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
		brandRequest(t, http.MethodPut, read["brand"], "id", "5"))

	require.Equal(t, http.StatusOK, status, "%v", again)
	assert.Equal(t, *storedFooterBrand(), written)
	assert.Equal(t, read["brand"], again["brand"])
}

// An update is a full replace: links and contact left out are removed, and the audit event lists
// the contact values and each link's URL the brand holds after the save, leaving out what is unset.
func TestBrandFooter_UpdateReplacesAndAudits(t *testing.T) {
	t.Run("new links and contact", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(storedFooterBrand(), nil).Once()
		var written record.Brand
		database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
			written = *args.Get(2).(*record.Brand)
		}).Return(nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, map[string]interface{}{
			"brand_id": int64(5), "brand_name": "Acme", "appearance": "dark", "theme": "plum",
			"corners": "pill", "font": "serif", "background_fit": "contain", "hide_app_name": false,
			"support_phone":    "+390612345678",
			"footer_link_urls": []string{"https://status.acme.example", "https://acme.example/terms"},
			"logged_in_user":   brandCaller,
		}).Once()
		body := withFooterLinks(statusLink, footerLink("https://acme.example/terms", "Terms", map[string]any{"it": "Termini"}))
		body["supportPhone"] = "+39 06 1234 5678"

		status, answer := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPut, body, "id", "5"))

		require.Equal(t, http.StatusOK, status, "%v", answer)
		assert.Equal(t, record.BrandFooterLinks{
			{URL: "https://status.acme.example", Label: "Status"},
			{URL: "https://acme.example/terms", Label: "Terms", Labels: map[string]string{"it": "Termini"}},
		}, written.FooterLinks)
		assert.Equal(t, []string{"", "", "+390612345678"}, []string{written.SupportEmail, written.SupportURL, written.SupportPhone})
	})

	t.Run("everything removed", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(5)).Return(storedFooterBrand(), nil).Once()
		var written record.Brand
		database.On("UpdateBrand", mock.Anything, (*sql.Tx)(nil), mock.Anything).Run(func(args mock.Arguments) {
			written = *args.Get(2).(*record.Brand)
		}).Return(nil).Once()
		database.On("GetDefaultBrand", mock.Anything, (*sql.Tx)(nil)).
			Return(storedBrand(1, "Default", record.BrandAppearanceAuto, "blueberry"), nil).Once()
		database.On("CountClientsPerBrand", mock.Anything, (*sql.Tx)(nil)).Return(map[int64]int{}, nil).Once()
		auditLogger := handlersmocks.NewAuditLogger(t)
		auditLogger.On("Log", mock.Anything, audit.EventUpdatedBrand, map[string]interface{}{
			"brand_id": int64(5), "brand_name": "Acme", "appearance": "dark", "theme": "plum",
			"corners": "pill", "font": "serif", "background_fit": "contain", "hide_app_name": false,
			"logged_in_user": brandCaller,
		}).Once()

		status, answer := serveBrand(HandleBrandUpdatePut(database, auditLogger, brandBaseURL),
			brandRequest(t, http.MethodPut, validBrandBody(), "id", "5"))

		require.Equal(t, http.StatusOK, status, "%v", answer)
		assert.Nil(t, written.FooterLinks)
		assert.Equal(t, []string{"", "", ""}, []string{written.SupportEmail, written.SupportURL, written.SupportPhone})
		assert.Equal(t, []any{}, brandAt(answer, "brand", "footerLinks"))
	})
}
