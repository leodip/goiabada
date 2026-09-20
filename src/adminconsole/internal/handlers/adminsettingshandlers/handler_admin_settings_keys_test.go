package adminsettingshandlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/adminconsole/internal/apiclient"
	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	mocks_handlerhelpers "github.com/leodip/goiabada/adminconsole/internal/handlerhelpers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	adminmiddleware "github.com/leodip/goiabada/adminconsole/internal/middleware"
	"github.com/leodip/goiabada/core/api"
)

// stubApiClient embeds apiclient.ApiClient so its hundred-odd other methods come for free
// and any of them that a test does not stub panics on a nil interface, which is the right
// outcome for a call the test did not expect. There is no generated mock: adminconsole has
// no .mockery.yaml. Same shape as adminclienthandlers' stub, for the same reason.
type stubApiClient struct {
	apiclient.ApiClient
	rotateErr error
	keys      []api.SettingsSigningKeyResponse
}

func (s *stubApiClient) RotateSettingsKeys(accessToken string) error {
	return s.rotateErr
}

func (s *stubApiClient) GetSettingsKeys(accessToken string) ([]api.SettingsSigningKeyResponse, error) {
	return s.keys, nil
}

// TestHandleAdminSettingsKeysRotatePost_APIErrorReachesTheBrowser owns the wiring between
// the rotate handler and HandleAPIErrorJson. The helper's own forwarding is pinned next
// door in api_error_helper_test.go, but that test cannot see which of the two error paths
// this handler calls: swapping HandleAPIErrorJson back to a direct JsonError leaves the
// helper's tests and the whole admin console suite green while putting the 409 back behind
// "An unexpected server error has occurred" and a request id.
//
// That sentence is the entire point of the change. The auth server answers 409
// ROTATION_IN_PROGRESS when another rotation won the race, which is a fact about the
// administrator's own request and something they can act on, and the modal that
// sendAjaxRequest opens shows error_description verbatim (#251).
//
// The rows for the other statuses are what keeps the forwarding narrow: a genuine server
// fault must stay a generic 500 with its detail in the log rather than on the screen.
func TestHandleAdminSettingsKeysRotatePost_APIErrorReachesTheBrowser(t *testing.T) {

	const refusal = "Another key rotation is in progress"

	const generic = "An unexpected server error has occurred"

	testCases := []struct {
		name            string
		apiErr          error
		wantStatus      int
		wantError       string
		wantDescription string
	}{
		{
			name:            "a 409 is forwarded with its status and description",
			apiErr:          &apiclient.APIError{Code: "ROTATION_IN_PROGRESS", Message: refusal, StatusCode: http.StatusConflict},
			wantStatus:      http.StatusConflict,
			wantError:       "ROTATION_IN_PROGRESS",
			wantDescription: refusal,
		},
		{
			name:            "a 400 is forwarded too, which is what #122 established",
			apiErr:          &apiclient.APIError{Code: "VALIDATION_ERROR", Message: "bad request", StatusCode: http.StatusBadRequest},
			wantStatus:      http.StatusBadRequest,
			wantError:       "VALIDATION_ERROR",
			wantDescription: "bad request",
		},
		{
			name:            "an incomplete key set stays generic, since 500 is not the administrator's mistake",
			apiErr:          &apiclient.APIError{Code: "KEY_SET_INCOMPLETE", Message: "Expected current and next keys to exist", StatusCode: http.StatusInternalServerError},
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
		{
			name:            "a transport error stays generic",
			apiErr:          errors.New("connection refused"),
			wantStatus:      http.StatusInternalServerError,
			wantError:       "server_error",
			wantDescription: generic,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// templateFS is nil because JsonError renders no template. This is the real
			// helper rather than a mock so the assertions below are on the bytes the
			// browser receives.
			httpHelper := handlerhelpers.NewHttpHelper(nil, adminmiddleware.SettingsReader{})

			req := handlertest.Request(http.MethodPost, "/admin/settings/keys/rotate",
				handlertest.WithAccessToken(),
			)

			rec := httptest.NewRecorder()

			handler := HandleAdminSettingsKeysRotatePost(httpHelper, &stubApiClient{rotateErr: tc.apiErr})
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tc.wantStatus, rec.Code)

			var response map[string]string
			err := json.Unmarshal(rec.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, tc.wantError, response["error"])
			assert.Contains(t, response["error_description"], tc.wantDescription)

			if tc.wantStatus == http.StatusInternalServerError {
				// The generic branch must not leak the API's message either: that is
				// what sends it to the log rather than the screen.
				assert.NotContains(t, response["error_description"], tc.apiErr.Error())
			}
		})
	}
}

// TestHandleAdminSettingsKeysRotatePost_SuccessIsUnchanged is here so that routing the
// failure path through a different helper cannot alter what a successful rotation answers.
func TestHandleAdminSettingsKeysRotatePost_SuccessIsUnchanged(t *testing.T) {

	httpHelper := handlerhelpers.NewHttpHelper(nil, adminmiddleware.SettingsReader{})

	req := handlertest.Request(http.MethodPost, "/admin/settings/keys/rotate", handlertest.WithAccessToken())

	rec := httptest.NewRecorder()

	handler := HandleAdminSettingsKeysRotatePost(httpHelper, &stubApiClient{rotateErr: nil})
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response struct {
		Success bool
	}
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
}

// TestHandleAdminSettingsKeysGet_RendersTheApiOrder owns the console half of the claim that freed
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
func TestHandleAdminSettingsKeysGet_RendersTheApiOrder(t *testing.T) {

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

			httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			handlertest.ExpectRender(httpHelper,
				"/layouts/menu_layout.html", "/admin_settings_keys.html").Once()

			req := handlertest.Request(http.MethodGet, "/admin/settings/keys",
				handlertest.WithAccessToken())

			handler := HandleAdminSettingsKeysGet(httpHelper, &stubApiClient{keys: apiKeys})
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
