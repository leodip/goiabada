package adminsettingshandlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// stubApiClient implements the keys page's port. The method no test here reaches panics, which is
// the right outcome for a call the test did not expect. There is no generated mock: adminconsole
// has no .mockery.yaml. Same shape as adminclienthandlers' stub, for the same reason.
type stubApiClient struct {
	rotateErr error
	keys      []api.SettingsSigningKeyResponse
}

func (s *stubApiClient) RotateSettingsKeys(_ context.Context, accessToken string) error {
	return s.rotateErr
}

func (s *stubApiClient) GetSettingsKeys(_ context.Context, accessToken string) ([]api.SettingsSigningKeyResponse, error) {
	return s.keys, nil
}

// The rest of the ports stubApiClient is passed to, which no test here reaches.

func (*stubApiClient) DeleteSettingsKey(context.Context, string, int64) error {
	panic("unexpected call to DeleteSettingsKey")
}

// A refused rotation answers with the keys page again, beside the API's sentence. The auth server
// answers 409 ROTATION_IN_PROGRESS when another rotation won the race, which is a fact about the
// administrator's own request and something they can act on, so its sentence is what the page says
// (#251). A genuine server fault stays the error page, its detail in the log rather than on the
// screen.
func TestHandleKeysRotatePost_ARefusalRedrawsThePageWithItsSentence(t *testing.T) {
	const refusal = "Another key rotation is in progress"
	for _, apiErr := range []error{
		&apiclient.APIError{Code: "ROTATION_IN_PROGRESS", Message: refusal, StatusCode: http.StatusConflict},
		&apiclient.APIError{Code: "handler.settings_keys.rotation_in_progress", Message: refusal, StatusCode: http.StatusBadRequest},
	} {
		httpHelper := handlersmocks.NewHttpHelper(t)
		handlertest.RefuseInternalServerError(t, httpHelper)
		handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_keys.html").Once()
		keys := []api.SettingsSigningKeyResponse{{Id: 1, State: "current", KeyIdentifier: "key-1"}}

		req := handlertest.Request(http.MethodPost, "/admin/settings/keys/rotate", handlertest.WithAccessToken())
		rec := httptest.NewRecorder()
		HandleKeysRotatePost(httpHelper, newSettingsTestStore(), &stubApiClient{rotateErr: apiErr, keys: keys}, consoleBaseURL).ServeHTTP(rec, req)

		bind := handlertest.Bind(t, httpHelper)
		assert.Equal(t, refusal, bind["error"])
		require.Len(t, bind["keys"], 1, "the keys are drawn beside the refusal")
	}
}

func TestHandleKeysRotatePost_AServerFaultIsTheErrorPage(t *testing.T) {
	for _, apiErr := range []error{
		&apiclient.APIError{Code: "KEY_SET_INCOMPLETE", Message: "Expected current and next keys to exist", StatusCode: http.StatusInternalServerError},
		errors.New("connection refused"),
	} {
		httpHelper := handlersmocks.NewHttpHelper(t)
		httpHelper.On("InternalServerError", mock.Anything, mock.Anything, mock.Anything).Once()

		req := handlertest.Request(http.MethodPost, "/admin/settings/keys/rotate", handlertest.WithAccessToken())
		HandleKeysRotatePost(httpHelper, newSettingsTestStore(), &stubApiClient{rotateErr: apiErr}, consoleBaseURL).ServeHTTP(httptest.NewRecorder(), req)

		httpHelper.AssertNotCalled(t, "RenderTemplate", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	}
}

// A rotation answers with a redirect to the keys page, which says once that the keys rotated.
func TestHandleKeysRotatePost_ARotationRedirectsToThePageThatSaysSo(t *testing.T) {
	store := newSettingsTestStore()
	httpHelper := handlersmocks.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)

	req := handlertest.Request(http.MethodPost, "/admin/settings/keys/rotate", handlertest.WithAccessToken())
	rec := httptest.NewRecorder()
	HandleKeysRotatePost(httpHelper, store, &stubApiClient{}, consoleBaseURL).ServeHTTP(rec, req)

	require.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, consoleBaseURL+"/admin/settings/keys", rec.Header().Get("Location"))

	for _, want := range []bool{true, false} {
		handlertest.ExpectRender(httpHelper, "/layouts/menu_layout.html", "/admin_settings_keys.html").Once()
		get := handlertest.Request(http.MethodGet, "/admin/settings/keys", handlertest.WithAccessToken())
		for _, cookie := range rec.Result().Cookies() {
			get.AddCookie(cookie)
		}
		HandleKeysGet(httpHelper, store, &stubApiClient{}).ServeHTTP(httptest.NewRecorder(), get)
		assert.Equal(t, want, handlertest.Bind(t, httpHelper)["keysRotated"], "said once, then no more")
		httpHelper.Calls = nil
	}
}

// TestHandleKeysGet_RendersTheApiOrder owns the console half of the claim that freed
// KeyState from core (#385 decision 7). The page used to re-sort the list with a structurally
// identical copy of the loop GET /api/v1/admin/settings/keys already applies, which is the only
// reason the console named a signing-key state at all.
//
// The first row is the property a reader cares about: the page still shows next, then current, then
// every previous. The remaining rows are what makes the deletion observable rather than merely
// harmless -- they hand the handler an order the API would not produce, and pass only if the page
// renders it through untouched. Restoring the loop turns each of them red.
//
// The producer's own guarantee is pinned where it is produced, in the auth server's
// handler_api_settings_keys_test.go. Without that half this file would only prove its own stub
// returned what it was told to.
func TestHandleKeysGet_RendersTheApiOrder(t *testing.T) {

	testCases := []struct {
		name  string
		given []string
		why   string
	}{
		{
			name:  "the order the API returns",
			given: []string{"next", "current", "previous", "previous"},
			why:   "next, then current, then every previous, which is what the page has always shown",
		},
		{
			name:  "an order the API would not produce is not repaired here",
			given: []string{"previous", "current", "next"},
			why:   "the page reports what the API ordered; it no longer has an opinion of its own",
		},
		{
			name:  "two previous keys keep their relative order",
			given: []string{"current", "previous", "next", "previous"},
			why:   "the deleted loop would have hoisted next and current out of this",
		},
		{
			name:  "an incomplete key set renders what there is",
			given: []string{"current"},
			why:   "no next key is a deployment state the page has to survive",
		},
		{
			name:  "an empty list renders an empty table",
			given: nil,
			why:   "the page binds a slice either way",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			apiKeys := make([]api.SettingsSigningKeyResponse, 0, len(tc.given))
			for i, state := range tc.given {
				apiKeys = append(apiKeys, api.SettingsSigningKeyResponse{
					Id:            int64(i + 1),
					State:         state,
					KeyIdentifier: "key-" + strconv.Itoa(i+1),
					Type:          "RSA",
					Algorithm:     "RS256",
				})
			}

			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper,
				"/layouts/menu_layout.html", "/admin_settings_keys.html").Once()

			req := handlertest.Request(http.MethodGet, "/admin/settings/keys",
				handlertest.WithAccessToken())

			handler := HandleKeysGet(httpHelper, newSettingsTestStore(), &stubApiClient{keys: apiKeys})
			handler.ServeHTTP(httptest.NewRecorder(), req)

			bind := handlertest.Bind(t, httpHelper, "for %v", tc.given)

			keys, ok := bind["keys"].([]SettingsKey)
			require.True(t, ok, "the page binds keys as []SettingsKey, got %T", bind["keys"])

			states := make([]string, 0, len(keys))
			identifiers := make([]string, 0, len(keys))
			for _, k := range keys {
				states = append(states, k.State)
				identifiers = append(identifiers, k.KeyIdentifier)
			}

			assert.Equal(t, tc.given, statesOrNil(states), "rendered order: %s", tc.why)

			// The identifiers pin that the rows are the API's own rather than rebuilt from the
			// states: two previous keys are indistinguishable by state alone, so a loop that
			// reordered them would pass the assertion above.
			wantIdentifiers := make([]string, 0, len(tc.given))
			for i := range tc.given {
				wantIdentifiers = append(wantIdentifiers, "key-"+strconv.Itoa(i+1))
			}
			assert.Equal(t, statesOrNil(wantIdentifiers), statesOrNil(identifiers),
				"each row carries the API row it was built from")
		})
	}
}

// statesOrNil collapses an empty slice to nil so the empty-list row compares against the nil the
// table declares, rather than against a zero-length slice assert.Equal treats as different.
func statesOrNil(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return values
}
