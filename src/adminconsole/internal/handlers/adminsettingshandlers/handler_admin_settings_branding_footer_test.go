package adminsettingshandlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// The editor's Footer links and Support contact sections (#814 decision 11): three fixed rows, each a
// label, a URL and a label for each of the six built-in languages, and the contact's three fields. A
// row left empty is no link, and the links keep their order with empty rows skipped. A refusal about
// a link names the input it is about in the error answer's error_field (decision 10), which the editor
// marks.

// footerForm is a brand form's own fields, with the footer fields named added.
func footerForm(values url.Values) url.Values {
	return withValues(url.Values{"name": {"Spring"}, "appearance": {"auto"}, "theme": {"plum"},
		"corners": {"rounded"}, "font": {"system-ui"}, "backgroundFit": {"cover"}}, values)
}

// refusalAt is a refusal of the admin API about the member of the body field points at.
func refusalAt(code, message, field string) error {
	return &apiclient.APIError{Code: code, Message: message, Field: field, StatusCode: http.StatusBadRequest}
}

// A stored brand's links fill the rows in their order, the rest left empty, and its contact the three
// fields, the phone number as stored. The language labels are offered for the six built-in languages.
func TestHandleBrandGet_DrawsTheStoredFooterInItsRows(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

	HandleBrandGet(httpHelper, newSettingsTestStore(), newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/4/edit", handlertest.WithAccessToken(),
			handlertest.WithPathValue("brandId", "4")))

	bind := handlertest.Bind(t, httpHelper)
	form := bind["brand"].(BrandForm)
	assert.Equal(t, [3]BrandFooterLinkRow{
		{Label: "Privacy", Url: "https://autumn.example/privacy", Labels: map[string]string{"de": "Datenschutz", "pt-BR": "Privacidade"}},
		{Label: "Status", Url: "https://status.autumn.example"},
		{},
	}, form.FooterLinks)
	assert.Equal(t, "help@autumn.example", form.SupportEmail)
	assert.Equal(t, "https://help.autumn.example", form.SupportUrl)
	assert.Equal(t, "+15550100199", form.SupportPhone)

	languages, _ := bind["footerLanguages"].([]FooterLanguage)
	var tags []string
	for _, language := range languages {
		tags = append(tags, language.Tag)
	}
	assert.Equal(t, []string{"en", "de", "es", "fr", "it", "pt-BR"}, tags)
}

// A new brand's form starts with its three rows and its contact empty.
func TestHandleBrandNewGet_StartsWithNoFooter(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()

	HandleBrandNewGet(httpHelper, newBrandingAPI()).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodGet, "/admin/settings/branding/new", handlertest.WithAccessToken()))

	bind := handlertest.Bind(t, httpHelper)
	form := bind["brand"].(BrandForm)
	assert.Equal(t, [3]BrandFooterLinkRow{}, form.FooterLinks)
	assert.Empty(t, form.SupportEmail+form.SupportUrl+form.SupportPhone)
	assert.Len(t, bind["footerLanguages"], 6)
}

// The links are sent in the rows' order with empty rows skipped: an empty first row, a row whose
// language labels are blank but for one, and a row with a label and no URL, which is sent for the
// admin API to refuse at its URL. A row is empty only when all of its eight fields are; blank language
// labels are left out. The contact is sent as typed, the phone number with its separators, which the
// auth server strips.
func TestHandleBrandNewPost_SendsTheRowsInOrderSkippingEmptyOnes(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(footerForm(url.Values{
				"footerLinks-0-label": {"  "}, "footerLinks-0-url": {""}, "footerLinks-0-labels-de": {" "},
				"footerLinks-1-label": {" Privacy "}, "footerLinks-1-url": {" https://spring.example/privacy "},
				"footerLinks-1-labels-de": {" Datenschutz "}, "footerLinks-1-labels-fr": {"  "},
				"footerLinks-2-label": {"Status"},
				"supportEmail":        {" help@spring.example "}, "supportUrl": {" https://help.spring.example "},
				"supportPhone": {" +1 (555) 010-0199 "},
			}))))

	require.NotNil(t, apiClient.created)
	assert.Equal(t, []api.BrandFooterLink{
		{Url: "https://spring.example/privacy", Label: "Privacy", Labels: map[string]string{"de": "Datenschutz"}},
		{Url: "", Label: "Status"},
	}, apiClient.created.FooterLinks)
	assert.Equal(t, "help@spring.example", apiClient.created.SupportEmail)
	assert.Equal(t, "https://help.spring.example", apiClient.created.SupportUrl)
	assert.Equal(t, "+1 (555) 010-0199", apiClient.created.SupportPhone)
}

// A row holding only a language label is a link, sent for the admin API to refuse at its label.
func TestHandleBrandNewPost_ARowWithOnlyALanguageLabelIsALink(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()

	HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
		handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
			handlertest.WithForm(footerForm(url.Values{"footerLinks-2-labels-pt-BR": {"Ajuda"}}))))

	require.NotNil(t, apiClient.created)
	assert.Equal(t, []api.BrandFooterLink{{Labels: map[string]string{"pt-BR": "Ajuda"}}}, apiClient.created.FooterLinks)
}

// A form with every row and the contact empty sends no links and no contact, which a save of a stored
// brand with them therefore clears: the form holds the footer now.
func TestHandleBrandPost_SendsTheFooterTheFormHolds(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	apiClient := newBrandingAPI()

	HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
		httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
			handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"),
			handlertest.WithForm(footerForm(url.Values{
				"footerLinks-0-label": {""}, "footerLinks-0-url": {""},
				"footerLinks-2-label": {"Status"}, "footerLinks-2-url": {"https://status.autumn.example"},
				"supportEmail": {""}, "supportUrl": {""}, "supportPhone": {"+15550100199"},
			}))))

	require.NotNil(t, apiClient.updated)
	assert.Equal(t, []api.BrandFooterLink{{Url: "https://status.autumn.example", Label: "Status"}}, apiClient.updated.FooterLinks)
	assert.Empty(t, apiClient.updated.SupportEmail, "the stored address is cleared")
	assert.Empty(t, apiClient.updated.SupportUrl)
	assert.Equal(t, "+15550100199", apiClient.updated.SupportPhone)

	apiClient = newBrandingAPI()
	HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
		httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
			handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"), handlertest.WithForm(footerForm(nil))))
	require.NotNil(t, apiClient.updated)
	assert.Nil(t, apiClient.updated.FooterLinks, "no links, sent as null")
}

// A refused form is drawn again with its links in the order they were sent, empty rows last, so the
// link a refusal names by its index, and its sentence by its number, is the row of that number.
func TestHandleBrandWrite_ARefusedFormDrawsItsLinksInTheOrderSent(t *testing.T) {
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
	apiClient := newBrandingAPI()
	apiClient.writeErr = refusalAt("handler.brand.footer_link_url_required", "Link 1 needs a URL.", "/footerLinks/0/url")

	HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
		httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
			handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"),
			handlertest.WithForm(footerForm(url.Values{
				"footerLinks-1-label": {"Help"}, "footerLinks-1-labels-it": {"Aiuto"},
				"supportEmail": {"not an address"}, "supportPhone": {"555 0100"},
			}))))

	bind := handlertest.Bind(t, httpHelper)
	form := bind["brand"].(BrandForm)
	assert.Equal(t, [3]BrandFooterLinkRow{{Label: "Help", Labels: map[string]string{"it": "Aiuto"}}, {}, {}}, form.FooterLinks)
	assert.Equal(t, "not an address", form.SupportEmail, "with what was sent")
	assert.Equal(t, "555 0100", form.SupportPhone)
	assert.Equal(t, "footerLinks-0-url", bind["errorField"])
	assert.Equal(t, "Link 1 needs a URL.", bind["error"])
}

// Each refusal about a link is marked at the input its error_field points at: the label, the URL or
// one language's label of the row of its index. A pointer to no input the form has, a fourth link
// or a language the form does not offer, marks none. The contact's refusals, one code per field, mark
// their fields.
func TestHandleBrandWrite_EachFooterRefusalIsShownOnItsInput(t *testing.T) {
	cases := []struct {
		err   error
		field string
	}{
		{refusalAt("handler.brand.footer_link_label_required", "No.", "/footerLinks/0/label"), "footerLinks-0-label"},
		{refusalAt("handler.brand.footer_link_label_too_long", "No.", "/footerLinks/2/label"), "footerLinks-2-label"},
		{refusalAt("handler.brand.footer_link_url_invalid", "No.", "/footerLinks/1/url"), "footerLinks-1-url"},
		{refusalAt("handler.brand.footer_link_url_too_long", "No.", "/footerLinks/2/url"), "footerLinks-2-url"},
		{refusalAt("handler.brand.footer_link_language_label_too_long", "No.", "/footerLinks/1/labels/pt-BR"), "footerLinks-1-labels-pt-BR"},
		{refusalAt("handler.brand.footer_link_language_label_angle_brackets", "No.", "/footerLinks/0/labels/en"), "footerLinks-0-labels-en"},
		{refusalAt("handler.brand.footer_link_language_invalid", "No.", "/footerLinks/0/labels/nl"), ""},
		{refusalAt("handler.brand.footer_links_too_many", "No.", "/footerLinks/3"), ""},
		{refusalAt("handler.brand.footer_link_url_invalid", "No.", "/footerLinks/3/url"), ""},
		{refusalAt("handler.brand.footer_link_url_invalid", "No.", "/footerLinks/01/url"), ""},
		{refusalAt("handler.brand.footer_link_url_invalid", "No.", "/footerLinks/-1/url"), ""},
		{refusalAt("handler.brand.footer_link_url_invalid", "No.", "/footerLinks/1/url/x"), ""},
		{refusalAt("handler.brand.footer_link_url_invalid", "No.", "/footerLinks/1/website"), ""},
		{refusalAt("handler.brand.footer_link_url_invalid", "No.", "/supportLinks/1/url"), ""},
		{refusal("handler.brand.support_email_invalid", "No."), "supportEmail"},
		{refusal("handler.brand.support_email_too_long", "No."), "supportEmail"},
		{refusal("handler.brand.support_url_invalid", "No."), "supportUrl"},
		{refusal("handler.brand.support_url_too_long", "No."), "supportUrl"},
		{refusal("handler.brand.support_phone_invalid", "No."), "supportPhone"},
		{refusalAt("handler.brand.name_required", "No.", ""), "name"},
	}
	for _, tc := range cases {
		var apiErr *apiclient.APIError
		require.ErrorAs(t, tc.err, &apiErr)
		t.Run(apiErr.Code+apiErr.Field, func(t *testing.T) {
			for name, post := range map[string]func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI){
				"new form": func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI) {
					HandleBrandNewPost(httpHelper, apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(),
						handlertest.Request(http.MethodPost, "/admin/settings/branding/new", handlertest.WithAccessToken(),
							handlertest.WithForm(footerForm(nil))))
				},
				"brand's form": func(httpHelper *handlersmocks.HttpHelper, apiClient *brandingAPI) {
					HandleBrandPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(
						httptest.NewRecorder(), handlertest.Request(http.MethodPost, "/admin/settings/branding/4/edit",
							handlertest.WithAccessToken(), handlertest.WithPathValue("brandId", "4"), handlertest.WithForm(footerForm(nil))))
				},
			} {
				t.Run(name, func(t *testing.T) {
					httpHelper := handlersmocks.NewHttpHelper(t)
					handlertest.RefuseInternalServerError(t, httpHelper)
					handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html").Once()
					apiClient := newBrandingAPI()
					apiClient.writeErr = tc.err

					post(httpHelper, apiClient)

					assert.Equal(t, tc.field, handlertest.Bind(t, httpHelper)["errorField"])
				})
			}
		})
	}
}
