package adminsettingshandlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	handlersmocks "github.com/leodip/goiabada/adminconsole/internal/handlers/mocks"
	"github.com/leodip/goiabada/adminconsole/internal/handlertest"
	"github.com/leodip/goiabada/core/api"
)

// policyRecordingAPI records the general settings save it is sent and answers it unchanged.
type policyRecordingAPI struct {
	sent *api.UpdateSettingsGeneralRequest
}

func (a *policyRecordingAPI) GetSettingsGeneral(context.Context, string) (*api.SettingsGeneralResponse, error) {
	return &api.SettingsGeneralResponse{Issuer: "https://auth.example.test", PasswordPolicy: "low"}, nil
}

func (a *policyRecordingAPI) UpdateSettingsGeneral(_ context.Context, _ string, req *api.UpdateSettingsGeneralRequest) (*api.SettingsGeneralResponse, error) {
	a.sent = req
	return &api.SettingsGeneralResponse{Issuer: req.Issuer, PasswordPolicy: req.PasswordPolicy}, nil
}

// Choosing a card saves that policy: the NIST SP 800-63B card's value reaches the admin API as
// nist, the wire value the auth server stores as 4, and each older card's as its own (#550
// decision 3).
func TestHandleGeneralPost_SavesThePolicyChosen(t *testing.T) {
	for _, policy := range []string{"nist", "none", "low", "medium", "high"} {
		t.Run(policy, func(t *testing.T) {
			req := handlertest.Request(http.MethodPost, "/admin/settings/general",
				handlertest.WithAccessToken(),
				handlertest.WithForm(url.Values{"issuer": {"https://auth.example.test"}, "passwordPolicy": {policy}}))

			httpHelper := handlersmocks.NewHttpHelper(t)
			handlertest.RefuseInternalServerError(t, httpHelper)
			apiClient := &policyRecordingAPI{}
			w := httptest.NewRecorder()
			HandleGeneralPost(httpHelper, newSettingsTestStore(), apiClient, &invalidationRecorder{}, consoleBaseURL).ServeHTTP(w, req)

			require.Equal(t, http.StatusFound, w.Code)
			assert.Equal(t, consoleBaseURL+"/admin/settings/general", w.Header().Get("Location"))
			require.NotNil(t, apiClient.sent)
			assert.Equal(t, policy, apiClient.sent.PasswordPolicy)
		})
	}
}
