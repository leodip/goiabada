package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's footer links and support contact through the admin API on a real engine (#814
// decisions 1, 5, 9 and 10): what a create stores and a read answers, a brand read and written
// back unchanged, the refusals with the member error_field points at, and the two audit events.

// footerBrandBody is a brand write with three links, the first labelled in every built-in
// language and with a blank label dropped, and all three contact values, the phone number typed
// with separators.
func footerBrandBody(name string) map[string]any {
	return brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "guava",
		"footerLinks": []any{
			map[string]any{"url": "https://acme.example/privacy", "label": " Privacy ", "labels": map[string]any{
				"en": "Privacy notice", "de": "Datenschutz", "es": "Privacidad", "fr": "Confidentialité",
				"it": "Riservatezza", "pt-BR": "Privacidade"}},
			map[string]any{"url": "https://status.acme.example", "label": "Status", "labels": map[string]any{"de": "  "}},
			map[string]any{"url": "https://acme.example", "label": "Acme & Co"},
		},
		"supportEmail": " help+desk%2@acme.example ",
		"supportUrl":   "https://help.acme.example/contact",
		"supportPhone": "+44 (20) 7946-0958",
	})
}

func TestAPIBrandFooter_StoredReadAndWrittenBackUnchanged(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	ctx := context.Background()

	status, body, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, footerBrandBody(brandName("Footer")))
	require.Equal(t, http.StatusCreated, status, "create: %v", body)
	brand := body["brand"].(map[string]any)
	id := int64(brand["id"].(float64))
	*created = append(*created, id)

	assert.Equal(t, []any{
		map[string]any{"url": "https://acme.example/privacy", "label": "Privacy", "labels": map[string]any{
			"en": "Privacy notice", "de": "Datenschutz", "es": "Privacidad", "fr": "Confidentialité",
			"it": "Riservatezza", "pt-BR": "Privacidade"}},
		map[string]any{"url": "https://status.acme.example", "label": "Status", "labels": map[string]any{}},
		map[string]any{"url": "https://acme.example", "label": "Acme & Co", "labels": map[string]any{}},
	}, brand["footerLinks"])
	assert.Equal(t, "help+desk%2@acme.example", brand["supportEmail"])
	assert.Equal(t, "https://help.acme.example/contact", brand["supportUrl"])
	assert.Equal(t, "+442079460958", brand["supportPhone"])

	stored, err := database.GetBrandById(ctx, nil, id)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, record.BrandFooterLinks{
		{URL: "https://acme.example/privacy", Label: "Privacy", Labels: map[string]string{
			"en": "Privacy notice", "de": "Datenschutz", "es": "Privacidad", "fr": "Confidentialité",
			"it": "Riservatezza", "pt-BR": "Privacidade"}},
		{URL: "https://status.acme.example", Label: "Status"},
		{URL: "https://acme.example", Label: "Acme & Co"},
	}, stored.FooterLinks)
	assert.Equal(t, "help+desk%2@acme.example", stored.SupportEmail)
	assert.Equal(t, "https://help.acme.example/contact", stored.SupportURL)
	assert.Equal(t, "+442079460958", stored.SupportPhone, "the phone number is stored without its separators")

	status, body, _ = brandCall(t, accessToken, http.MethodGet, brandPath(id, ""), nil)
	require.Equal(t, http.StatusOK, status)
	read := body["brand"].(map[string]any)
	assertBrandReadsAsCreated(t, brand, read)

	status, body, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""), read)
	require.Equal(t, http.StatusOK, status, "write back: %v", body)
	rewritten, err := database.GetBrandById(ctx, nil, id)
	require.NoError(t, err)
	rewritten.UpdatedAt = stored.UpdatedAt
	assert.Equal(t, stored, rewritten, "a brand read and written back is unchanged")

	// An update that leaves the four out removes them.
	status, body, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
		brandBody(map[string]any{"name": read["name"], "appearance": "auto", "theme": "guava"}))
	require.Equal(t, http.StatusOK, status, "update: %v", body)
	assert.Equal(t, []any{}, body["brand"].(map[string]any)["footerLinks"])
	assert.Empty(t, body["brand"].(map[string]any)["supportPhone"])
	cleared, err := database.GetBrandById(ctx, nil, id)
	require.NoError(t, err)
	assert.Nil(t, cleared.FooterLinks)
	assert.Equal(t, []string{"", "", ""}, []string{cleared.SupportEmail, cleared.SupportURL, cleared.SupportPhone})
}

func TestAPIBrandFooter_Refusals(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	other := createBrandOverAPI(t, accessToken, created, brandName("Other"), "auto", "blueberry")

	with := func(edit func(map[string]any)) map[string]any {
		body := footerBrandBody(brandName("New"))
		edit(body)
		return body
	}
	link := func(b map[string]any, i int) map[string]any { return b["footerLinks"].([]any)[i].(map[string]any) }
	refusals := []struct {
		name, code, field, description string
		body                           map[string]any
	}{
		{"a fourth link", "handler.brand.footer_links_too_many", "/footerLinks/3", "A brand has at most 3 footer links.",
			with(func(b map[string]any) {
				b["footerLinks"] = append(b["footerLinks"].([]any), map[string]any{"url": "https://acme.example/terms", "label": "Terms"})
			})},
		{"a label of 41 characters", "handler.brand.footer_link_label_too_long", "/footerLinks/2/label",
			"The label of link 3 cannot exceed 40 characters.",
			with(func(b map[string]any) { link(b, 2)["label"] = strings.Repeat("ü", 41) })},
		{"a language that is not built in", "handler.brand.footer_link_language_invalid", "/footerLinks/1/labels/nl",
			"Link 2 has a label for nl, which is not a built-in language.",
			with(func(b map[string]any) { link(b, 1)["labels"] = map[string]any{"nl": "Status"} })},
		{"a language label with an angle bracket", "handler.brand.footer_link_language_label_angle_brackets", "/footerLinks/0/labels/pt-BR",
			"The pt-BR label of link 1 cannot contain the characters < or >.",
			with(func(b map[string]any) { link(b, 0)["labels"] = map[string]any{"pt-BR": "<b>Privacidade</b>"} })},
		{"an http: URL", "handler.brand.footer_link_url_invalid", "/footerLinks/1/url",
			"The URL of link 2 must start with https:// and name a site, with no user name or password.",
			with(func(b map[string]any) { link(b, 1)["url"] = "http://status.acme.example" })},
		{"a URL with a user name", "handler.brand.footer_link_url_invalid", "/footerLinks/0/url",
			"The URL of link 1 must start with https:// and name a site, with no user name or password.",
			with(func(b map[string]any) { link(b, 0)["url"] = "https://acme.com@other.example" })},
		{"a URL of 257 characters", "handler.brand.footer_link_url_too_long", "/footerLinks/2/url",
			"The URL of link 3 cannot exceed 256 characters.",
			with(func(b map[string]any) { link(b, 2)["url"] = "https://acme.example/" + strings.Repeat("a", 236) })},
		{"a support address of the wrong shape", "handler.brand.support_email_invalid", "",
			"Enter a valid support email address.",
			with(func(b map[string]any) { b["supportEmail"] = "help@acme" })},
		{"an http: support page", "handler.brand.support_url_invalid", "",
			"The support page URL must start with https:// and name a site, with no user name or password.",
			with(func(b map[string]any) { b["supportUrl"] = "http://help.acme.example" })},
		{"a phone number with no country code", "handler.brand.support_phone_invalid", "",
			"Enter the support phone number in international format: + and the country code, then the number, at most 15 digits in all, such as +44 20 7946 0958.",
			with(func(b map[string]any) { b["supportPhone"] = "020 7946 0958" })},
	}
	for _, c := range refusals {
		for _, write := range []struct{ method, path string }{{http.MethodPost, brandsPath}, {http.MethodPut, brandPath(other, "")}} {
			t.Run(write.method+" "+c.name, func(t *testing.T) {
				status, body, _ := brandCall(t, accessToken, write.method, write.path, c.body)
				assert.Equal(t, http.StatusBadRequest, status)
				assert.Equal(t, c.code, body["error_code"])
				assert.Equal(t, c.description, body["error_description"])
				field, present := body["error_field"]
				if c.field == "" {
					assert.False(t, present, "a contact refusal sets no error_field: %v", field)
				} else {
					assert.Equal(t, c.field, field)
				}
			})
		}
	}

	stored, err := database.GetBrandById(context.Background(), nil, other)
	require.NoError(t, err)
	assert.Nil(t, stored.FooterLinks, "no refused update wrote the brand")
	assert.Empty(t, stored.SupportPhone)
}

func TestAPIBrandFooter_ChangesAreAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	who := caller.ClientIdentifier
	_, created := keepDefaultBrand(t)

	name := brandName("AuditFooter")
	resp, requestId := sendAdmin(t, accessToken, http.MethodPost, brandsPath, footerBrandBody(name))
	var answer map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&answer))
	_ = resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "%v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": name,
		"support_email": "help+desk%2@acme.example", "support_url": "https://help.acme.example/contact",
		"support_phone":    "+442079460958",
		"footer_link_urls": []any{"https://acme.example/privacy", "https://status.acme.example", "https://acme.example"},
		"logged_in_user":   who}},
		auditRows(t, accessToken, "created_brand", requestId))

	_, _, requestId = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""),
		brandBody(map[string]any{"name": name, "appearance": "dark", "theme": "plum",
			"footerLinks":  []any{map[string]any{"url": "https://acme.example/terms", "label": "Terms"}},
			"supportEmail": "support@acme.example"}))
	assert.Equal(t, []map[string]any{{"brand_id": float64(id), "brand_name": name, "appearance": "dark",
		"theme": "plum", "corners": "rounded", "font": "system-ui", "background_fit": "cover",
		"hide_app_name": false, "support_email": "support@acme.example",
		"footer_link_urls": []any{"https://acme.example/terms"}, "logged_in_user": who}},
		auditRows(t, accessToken, "updated_brand", requestId))
}
