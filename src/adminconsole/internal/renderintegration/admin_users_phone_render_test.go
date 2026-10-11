package renderintegration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// phoneTabAPI is the auth server as the user Phone tab reaches it: the user as stored, the country
// list, and a save it refuses with a 400 the administrator can act on.
type phoneTabAPI struct {
	stored  *api.UserResponse
	refusal string
}

func (s *phoneTabAPI) GetPhoneCountries(_ context.Context, _ string) ([]api.PhoneCountryResponse, error) {
	return []api.PhoneCountryResponse{
		{UniqueId: "BRA_0", Alpha2: "BR", CallingCode: "+55", Name: "Brazil"},
		{UniqueId: "PRT_0", Alpha2: "PT", CallingCode: "+351", Name: "Portugal"},
	}, nil
}

func (s *phoneTabAPI) GetUserById(_ context.Context, _ string, _ int64) (*api.UserResponse, error) {
	return s.stored, nil
}

func (s *phoneTabAPI) UpdateUserPhone(_ context.Context, _ string, _ int64,
	_ *api.UpdateUserPhoneRequest) (*api.UserResponse, error) {
	return nil, &apiclient.APIError{Code: "VALIDATION_ERROR", Message: s.refusal, StatusCode: http.StatusBadRequest}
}

// userTabLinkRe matches the href of every tab the users tab strip draws.
var userTabLinkRe = regexp.MustCompile(`<a href="(/admin/users/[^"]*)" class="tab tab-bordered`)

// A refused save draws the tab with its user, as the first draw does: the title names the user's
// email and every tab links to that user, keeping the list position. It used to bind no user at
// all, so the title named nobody and every tab linked to /admin/users//… (#562). The inputs keep
// what was submitted.
func TestRender_AdminUserPhone_ARefusedSaveDrawsThePageWithItsUser(t *testing.T) {
	const refusal = "The phone number is invalid."
	apiClient := &phoneTabAPI{
		stored: &api.UserResponse{Id: 9, Email: "ana@example.com", PhoneNumberCountryUniqueId: "PRT_0",
			PhoneNumber: "912345678", PhoneNumberVerified: true},
		refusal: refusal,
	}

	req := handlertest.Request(http.MethodPost, "/admin/users/9/phone?page=2&query=ana",
		handlertest.WithAccessToken(), handlertest.WithRouteParam("userId", "9"),
		handlertest.WithSettings(&api.PublicSettingsResponse{AppName: "Test", UITheme: "dark"}),
		handlertest.WithForm(url.Values{"phoneCountryUniqueId": {"BRA_0"}, "phoneNumber": {"12"}}))
	req = req.WithContext(i18n.WithLocale(req.Context(), true, "pt-BR"))
	rec := httptest.NewRecorder()

	adminuserhandlers.HandlePhonePost(render.New(web.TemplateFS()), nil, apiClient, "https://console.example").
		ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "the refused save is drawn again, not redirected: %s", rec.Body.String())
	out := rec.Body.String()

	assert.Contains(t, out, `<p>`+refusal+`</p>`)
	assert.Contains(t, out, `<span class="text-accent">ana@example.com</span>`, "the page title names the user")
	assert.Contains(t, out, `<title>Test - Usuário - Telefone - ana@example.com</title>`)

	links := userTabLinkRe.FindAllStringSubmatch(out, -1)
	require.Len(t, links, 12, "the twelve user tabs")
	for _, link := range links {
		assert.True(t, strings.HasPrefix(link[1], "/admin/users/9/"), "a tab links to the user: %s", link[1])
		assert.True(t, strings.HasSuffix(link[1], "?page=2&query=ana"), "and keeps the list position: %s", link[1])
	}

	assert.Contains(t, out, `<option class="country-flags" value="BRA_0" selected>`, "the country as submitted")
	assert.NotContains(t, out, `value="PRT_0" selected`)
	assert.Contains(t, out, `name="phoneNumber" value="12"`, "the number as typed")
	verified := regexp.MustCompile(`<input type="checkbox" name="phoneNumberVerified"[^>]*>`).FindString(out)
	require.NotEmpty(t, verified)
	assert.NotContains(t, verified, "checked", "the verified switch as submitted: off")
}
