package adminsettingshandlers

import (
	"context"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mocks_handlers "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/adminconsole/internal/sessionkeys"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
)

// issuerChangingAPI answers the issuer the settings held before the save, then the one the save
// wrote.
type issuerChangingAPI struct {
	before, after string
}

func (a issuerChangingAPI) GetSettingsGeneral(context.Context, string) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{Issuer: a.before}, nil
}

func (a issuerChangingAPI) UpdateSettingsGeneral(context.Context, string, *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{Issuer: a.after}, nil
}

// Changing the issuer signs the administrator who changed it out, and the access token's recorded
// expiry goes with the token response it describes. The console reads that expiry instead of
// decoding its access token, so a value left behind would describe a token the session no longer
// holds (#427 decision 15).
//
// Observed through the store's own Get with the cookie the handler answered with, which is what
// the next request would load; the unrelated value proves the session was edited, not discarded.
func TestHandleAdminSettingsGeneralPost_AnIssuerChangeDeletesTheTokenResponseAndItsExpiry(t *testing.T) {
	gob.Register(oauth.TokenResponse{})
	store := newSettingsTestStore()

	seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	seeded, err := store.Get(seedReq, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	seeded.Values[sessionkeys.JWT] = oauth.TokenResponse{AccessToken: "the-access-token"}
	seeded.Values[sessionkeys.JWTExpiresAt] = int64(1_900_000_000)
	seeded.Values["Unrelated"] = "kept"
	seedW := httptest.NewRecorder()
	require.NoError(t, store.Save(seedReq, seedW, seeded))
	cookies := seedW.Result().Cookies()
	require.NotEmpty(t, cookies)

	req := handlertest.Request(http.MethodPost, "/admin/settings/general",
		handlertest.WithAccessToken(),
		handlertest.WithForm(url.Values{"issuer": {"https://new-issuer.example"}}))
	for _, c := range cookies {
		req.AddCookie(c)
	}

	httpHelper := mocks_handlers.NewHttpHelper(t)
	handlertest.RefuseInternalServerError(t, httpHelper)
	w := httptest.NewRecorder()
	HandleAdminSettingsGeneralPost(httpHelper, store,
		issuerChangingAPI{before: "https://old-issuer.example", after: "https://new-issuer.example"},
		&invalidationRecorder{}, consoleBaseURL,
	).ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://console.example.test/auth/logout", w.Header().Get("Location"),
		"the sign-out goes to the base URL the handler was built with")

	readReq := httptest.NewRequest(http.MethodGet, "/", nil)
	answered := w.Result().Cookies()
	if len(answered) == 0 {
		answered = cookies
	}
	for _, c := range answered {
		readReq.AddCookie(c)
	}
	readBack, err := store.Get(readReq, builtin.AdminConsoleSessionName)
	require.NoError(t, err)
	require.False(t, readBack.IsNew, "the session is still there")
	assert.NotContains(t, readBack.Values, sessionkeys.JWT)
	assert.NotContains(t, readBack.Values, sessionkeys.JWTExpiresAt)
	assert.Equal(t, "kept", readBack.Values["Unrelated"])
}
