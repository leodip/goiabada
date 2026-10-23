package integration

// The nist password policy over the wire (#550): the general settings API accepts and returns
// nist, stored as 4, and under it the Admin API refuses a common password, and one too close to
// the account's email, with the refusal's catalog key as its error_code.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPISettingsGeneralPut_AcceptsAndReturnsNist(t *testing.T) {
	settings := restoreSettings(t)
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/settings/general"

	resp := makeAPIRequest(t, "PUT", url, accessToken, api.UpdateSettingsGeneralRequest{
		AppName:        settings.AppName,
		Issuer:         settings.Issuer,
		PasswordPolicy: "nist",
	})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var saved api.SettingsGeneralResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&saved))
	assert.Equal(t, "nist", saved.PasswordPolicy)

	stored, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.Equal(t, record.PasswordPolicy(4), stored.PasswordPolicy, "nist is stored as 4")

	got := makeAPIRequest(t, "GET", url, accessToken, nil)
	defer func() { _ = got.Body.Close() }()
	require.Equal(t, http.StatusOK, got.StatusCode)
	var read api.SettingsGeneralResponse
	require.NoError(t, json.NewDecoder(got.Body).Decode(&read))
	assert.Equal(t, "nist", read.PasswordPolicy)
}

func TestAPIUserCreatePost_HoldsThePasswordToNist(t *testing.T) {
	changeSettings(t, func(settings *record.Settings) { settings.PasswordPolicy = record.PasswordPolicyNist })
	accessToken, _ := createAdminClientWithToken(t)
	url := appConfig.AuthServer.BaseURL + "/api/v1/admin/users/create"
	email := uniqueEmail("nist@create.test")
	localPart := email[:strings.LastIndex(email, "@")]

	for name, tc := range map[string]struct {
		password string
		code     string
	}{
		"a listed password":             {"PasswordPassword", "validator.password.too_common"},
		"the email's local part padded": {localPart + "2026!!!!!!!!!!!", "validator.password.too_close_to_account"},
		"14 characters":                 {"violettractorx", "validator.password.too_short"},
	} {
		t.Run(name, func(t *testing.T) {
			resp := makeAPIRequest(t, "POST", url, accessToken, api.CreateUserAdminRequest{
				Email: email, SetPasswordType: "now", Password: tc.password,
			})
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var refusal api.ErrorResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&refusal))
			assert.Equal(t, tc.code, refusal.ErrorCode)
			user, err := database.GetUserByEmail(context.Background(), nil, email)
			require.NoError(t, err)
			assert.Nil(t, user, "a refused password creates no user")
		})
	}

	t.Run("a passphrase of 15 characters or more is accepted", func(t *testing.T) {
		resp := makeAPIRequest(t, "POST", url, accessToken, api.CreateUserAdminRequest{
			Email: email, SetPasswordType: "now", Password: "violet tractor umbrella",
		})
		defer func() { _ = resp.Body.Close() }()

		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var created api.CreateUserResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
		t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, created.User.Id) })
	})
}

// The settings row the tier runs against is the one the first start seeded, so the general
// settings API answering nist here is a new installation starting with it.
func TestAPISettingsGeneralGet_ANewInstallationAnswersNist(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/admin/settings/general", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body api.SettingsGeneralResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "nist", body.PasswordPolicy)
}
