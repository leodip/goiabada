package renderintegration

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/leodip/goiabada/adminconsole/internal/handlers/accounthandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/admingrouphandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/adminuserhandlers"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/render"
	web "github.com/leodip/goiabada/adminconsole/web"
	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refused save draws every input as it was submitted, the switches and the date of birth among
// them, so nothing the person typed or chose is lost and no input contradicts the message beside it
// (#562 sections 4 and 5).

// ---- Groups > New ----

// groupNewAPI is the auth server as the new group page reaches it: a creation it refuses.
type groupNewAPI struct{ refusal string }

func (s *groupNewAPI) CreateGroup(_ context.Context, _ string, _ *api.CreateGroupRequest) (*api.GroupResponse, error) {
	return nil, refusedSave(s.refusal)
}

// groupSwitchRe matches the include switch named, whatever order its attributes come in.
func groupSwitchRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`<input type="checkbox" name="` + name + `"[^>]*>`)
}

// The new group form opens with both include switches on.
func TestRender_AdminGroupNew_AFirstDrawHasBothSwitchesOn(t *testing.T) {
	out := servePage(t, admingrouphandlers.HandleNewGet(render.New(web.TemplateFS())), http.MethodGet, "/admin/groups/new")

	for _, name := range []string{"includeInAccessToken", "includeInIdToken"} {
		toggle := groupSwitchRe(name).FindString(out)
		require.NotEmpty(t, toggle, "the %s switch is rendered", name)
		assert.Contains(t, toggle, "checked", "%s is on", name)
	}
}

// A refused new group keeps both switches as submitted. They were drawn on whatever was submitted,
// so the administrator who had switched one off saw it on again beside the refusal (#562 section 4).
func TestRender_AdminGroupNew_ARefusalKeepsTheSwitchesAsSubmitted(t *testing.T) {
	const refusal = "The group identifier is already in use."

	testCases := []struct {
		name       string
		form       url.Values
		wantAccess bool
		wantId     bool
	}{
		{name: "both off", form: url.Values{}},
		{name: "access token only", form: url.Values{"includeInAccessToken": {"on"}}, wantAccess: true},
		{name: "ID token only", form: url.Values{"includeInIdToken": {"on"}}, wantId: true},
		{name: "both on", form: url.Values{"includeInAccessToken": {"on"}, "includeInIdToken": {"on"}},
			wantAccess: true, wantId: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.form.Set("groupIdentifier", "sales")
			tc.form.Set("description", "Sales team")

			out := serveRefusal(t, admingrouphandlers.HandleNewPost(render.New(web.TemplateFS()),
				&groupNewAPI{refusal: refusal}, "https://console.example"), "/admin/groups/new", tc.form)

			assert.Contains(t, out, `<p>`+refusal+`</p>`)
			assert.Contains(t, out, `name="groupIdentifier" value="sales"`)
			assert.Contains(t, out, `name="description" value="Sales team"`)

			access := groupSwitchRe("includeInAccessToken").FindString(out)
			require.NotEmpty(t, access)
			assert.Equal(t, tc.wantAccess, regexp.MustCompile(`\bchecked\b`).MatchString(access), "access token: %s", access)
			id := groupSwitchRe("includeInIdToken").FindString(out)
			require.NotEmpty(t, id)
			assert.Equal(t, tc.wantId, regexp.MustCompile(`\bchecked\b`).MatchString(id), "ID token: %s", id)
		})
	}
}

// ---- Users > Profile and Account > Profile ----

// profilePageAPI is the auth server as both profile pages reach it: the user as stored, and a
// profile save it refuses.
type profilePageAPI struct {
	stored  *api.UserResponse
	refusal string
}

func (s *profilePageAPI) GetUserById(_ context.Context, _ string, _ int64) (*api.UserResponse, error) {
	stored := *s.stored
	return &stored, nil
}

func (s *profilePageAPI) UpdateUserProfile(_ context.Context, _ string, _ int64,
	_ *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return nil, refusedSave(s.refusal)
}

func (s *profilePageAPI) GetAccountProfile(_ context.Context, _ string) (*api.UserResponse, error) {
	stored := *s.stored
	return &stored, nil
}

func (s *profilePageAPI) UpdateAccountProfile(_ context.Context, _ string,
	_ *api.UpdateUserProfileRequest) (*api.UserResponse, error) {
	return nil, refusedSave(s.refusal)
}

// dateOfBirthRe matches the date-of-birth input, whatever order its attributes come in.
var dateOfBirthRe = regexp.MustCompile(`<input type="text" name="dateOfBirth"[^>]*>`)

// profilePages are the two pages that share the profile form, each served for a refused save.
func profilePages(apiClient *profilePageAPI) []struct {
	name    string
	handler http.HandlerFunc
	target  string
	options []handlertest.Option
} {
	renderer := render.New(web.TemplateFS())
	return []struct {
		name    string
		handler http.HandlerFunc
		target  string
		options []handlertest.Option
	}{
		{
			name:    "Users > Profile",
			handler: adminuserhandlers.HandleProfilePost(renderer, nil, apiClient, "https://console.example"),
			target:  "/admin/users/9/profile",
			options: []handlertest.Option{handlertest.WithRouteParam("userId", "9")},
		},
		{
			name:    "Account > Profile",
			handler: accounthandlers.HandleProfilePost(renderer, nil, apiClient, "https://console.example"),
			target:  "/account/profile",
		},
	}
}

// A refused date of birth is drawn exactly as it was typed, on both pages that share the profile
// form, whatever it was: a date the server refuses, text that is no date, or nothing. The field
// used to show the stored date instead, or nothing, so a valid date sat beside "the date of birth
// is invalid" and what was typed was gone (#562 decision 3).
func TestRender_ProfilePages_ARefusedDateOfBirthIsDrawnAsTyped(t *testing.T) {
	const refusal = "A data de nascimento é inválida."
	born := time.Date(1980, 1, 2, 0, 0, 0, 0, time.UTC)
	apiClient := &profilePageAPI{
		stored:  &api.UserResponse{Id: 9, Email: "ana@example.com", GivenName: "Ana", BirthDate: &born},
		refusal: refusal,
	}

	testCases := []struct {
		name  string
		typed string
	}{
		{name: "a date in the future", typed: "2999-05-17"},
		{name: "text that is no date", typed: "17/05/1990"},
		{name: "nothing", typed: ""},
		{name: "text with spaces around it", typed: " 17/05/1990 "},
	}

	for _, page := range profilePages(apiClient) {
		for _, tc := range testCases {
			t.Run(page.name+", "+tc.name, func(t *testing.T) {
				out := serveRefusal(t, page.handler, page.target, url.Values{
					"givenName":   {"Ana Maria"},
					"dateOfBirth": {tc.typed},
				}, page.options...)

				assert.Contains(t, out, `<p>`+refusal+`</p>`)
				input := dateOfBirthRe.FindString(out)
				require.NotEmpty(t, input, "the date-of-birth input is rendered")
				assert.Contains(t, input, `value="`+tc.typed+`"`, "the date of birth as typed")
				assert.NotContains(t, input, "1980-01-02", "never the stored date")
				assert.Contains(t, out, `name="givenName" value="Ana Maria"`, "every other input as submitted too")
			})
		}
	}
}

// The text is drawn escaped, as every other input's value is.
func TestRender_ProfilePages_ARefusedDateOfBirthIsDrawnEscaped(t *testing.T) {
	apiClient := &profilePageAPI{
		stored:  &api.UserResponse{Id: 9, Email: "ana@example.com"},
		refusal: "A data de nascimento é inválida.",
	}

	for _, page := range profilePages(apiClient) {
		t.Run(page.name, func(t *testing.T) {
			out := serveRefusal(t, page.handler, page.target, url.Values{
				"dateOfBirth": {`"><script>alert(1)</script>`},
			}, page.options...)

			assert.NotContains(t, out, `<script>alert(1)</script>`)
			assert.Contains(t, dateOfBirthRe.FindString(out), `value="&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"`)
		})
	}
}
