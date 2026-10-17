package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/uithemes"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Saves of different settings sections sent at once, end to end (#407). Each section's save used
// to write the whole settings row from the copy its request loaded when it started, so of saves of
// different sections whose requests overlapped, the last to write carried every other section back
// from its copy, and their changes were lost with every request answered 200. Each save now takes
// the row, reads it again under that lock and writes its own section onto what it read.
//
// The handler tier's TestSettingsSectionSaves_ConcurrentSavesOfDifferentSectionsAllSurvive shows
// the shape over an in-memory lock, and the data tier's
// TestAcquireSettingsRow_ASaveUnderTheLockKeepsAConcurrentSaveOfAnotherSection the lock on each
// engine; this sends the saves through the server's own middleware and handlers to the engine it
// runs on. Overlap cannot be forced from outside the server, only made likely, so a save written
// from its request's copy could still pass one round; several rounds are run to make that unlikely.

// settingsSectionPut is one section's save: the route and the body it sends.
type settingsSectionPut struct {
	section string
	route   string
	body    any
}

// sendSettingsSavesAtOnce sends every save at once and returns each response, read whole. Like
// sendConcurrently, it reports every failure here rather than from the request goroutines.
func sendSettingsSavesAtOnce(t *testing.T, accessToken string, saves []settingsSectionPut) []concurrentResult {
	t.Helper()
	client := createHttpClient(t)
	requests := make([]*http.Request, len(saves))
	for i, save := range saves {
		encoded, err := json.Marshal(save.body)
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPut, appConfig.AuthServer.BaseURL+save.route, bytes.NewReader(encoded))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		requests[i] = req
	}

	results := make([]concurrentResult, len(saves))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range requests {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp, err := client.Do(requests[i])
			if err != nil {
				results[i] = concurrentResult{err: err}
				return
			}
			defer func() { _ = resp.Body.Close() }()
			read, err := io.ReadAll(resp.Body)
			results[i] = concurrentResult{status: resp.StatusCode, body: read, err: err}
		}(i)
	}
	close(start)
	wg.Wait()

	for i, result := range results {
		require.NoError(t, result.err, "the %s save", saves[i].section)
	}
	return results
}

func TestAPISettingsSections_ConcurrentSavesOfDifferentSectionsAllSurvive(t *testing.T) {
	// SMTP pointed at Mailpit with no password stored, so the email save's dial reaches a server
	// and keeping the host asks for no password. The whole row is put back when the test ends.
	start := changeSettings(t, func(settings *record.Settings) {
		settings.SMTPEnabled = true
		settings.SMTPHost = "mailpit"
		settings.SMTPPort = 1025
		settings.SMTPEncryption = emaildelivery.SMTPEncryptionNone.String()
		settings.SMTPUsername = ""
		settings.SMTPPasswordEncrypted = nil
	})
	accessToken, _ := createAdminClientWithToken(t)
	themes := uithemes.Get()
	require.GreaterOrEqual(t, len(themes), 2, "two themes, so consecutive rounds save different ones")

	// Each round saves every section at once with values no other round uses, every field the
	// section does not vary sent as the row started, so a section written back from a copy
	// loaded before another round's saves reads as that round's value, or as the row's start.
	const rounds = 10
	for round := 1; round <= rounds; round++ {
		appName := fmt.Sprintf("Concurrent saves %d", round)
		theme := themes[round%len(themes)]
		idleTimeout := 3000 + round
		tokenExpiration := 600 + round
		retentionDays := 30 + round
		fromName := fmt.Sprintf("Concurrent saves %d", round)

		saves := []settingsSectionPut{
			{section: "general", route: "/api/v1/admin/settings/general", body: api.UpdateSettingsGeneralRequest{
				AppName:                 appName,
				Issuer:                  start.Issuer,
				SelfRegistrationEnabled: start.SelfRegistrationEnabled,
				SelfRegistrationRequiresEmailVerification: start.SelfRegistrationRequiresEmailVerification,
				DynamicClientRegistrationEnabled:          start.DynamicClientRegistrationEnabled,
				PasswordPolicy:                            start.PasswordPolicy.String(),
				PKCERequired:                              start.PKCERequired,
				ImplicitFlowEnabled:                       start.ImplicitFlowEnabled,
				ResourceOwnerPasswordCredentialsEnabled:   start.ResourceOwnerPasswordCredentialsEnabled,
			}},
			{section: "ui theme", route: "/api/v1/admin/settings/ui-theme", body: api.UpdateSettingsUIThemeRequest{
				UITheme: theme,
			}},
			{section: "email", route: "/api/v1/admin/settings/email", body: api.UpdateSettingsEmailRequest{
				SMTPEnabled:    true,
				SMTPHost:       start.SMTPHost,
				SMTPPort:       start.SMTPPort,
				SMTPEncryption: start.SMTPEncryption,
				SMTPFromName:   fromName,
				SMTPFromEmail:  "concurrent.saves@settings.test",
			}},
			{section: "sessions", route: "/api/v1/admin/settings/sessions", body: api.UpdateSettingsSessionsRequest{
				UserSessionIdleTimeoutInSeconds: idleTimeout,
				UserSessionMaxLifetimeInSeconds: 86400,
				MaxUserSessionsPerUser:          &start.MaxUserSessionsPerUser,
			}},
			{section: "tokens", route: "/api/v1/admin/settings/tokens", body: api.UpdateSettingsTokensRequest{
				TokenExpirationInSeconds:                tokenExpiration,
				RefreshTokenOfflineIdleTimeoutInSeconds: start.RefreshTokenOfflineIdleTimeoutInSeconds,
				RefreshTokenOfflineMaxLifetimeInSeconds: start.RefreshTokenOfflineMaxLifetimeInSeconds,
				IncludeOpenIDConnectClaimsInAccessToken: start.IncludeOpenIDConnectClaimsInAccessToken,
				IncludeOpenIDConnectClaimsInIdToken:     start.IncludeOpenIDConnectClaimsInIdToken,
			}},
			{section: "audit logs", route: "/api/v1/admin/settings/audit-logs", body: api.UpdateSettingsAuditLogsRequest{
				AuditLogsInConsoleEnabled:  start.AuditLogsInConsoleEnabled,
				AuditLogsInDatabaseEnabled: start.AuditLogsInDatabaseEnabled,
				AuditLogRetentionDays:      retentionDays,
			}},
		}

		results := sendSettingsSavesAtOnce(t, accessToken, saves)
		for i, result := range results {
			require.Equal(t, http.StatusOK, result.status, "round %d: the %s save: %s", round, saves[i].section, result.body)
		}

		row := settingsRow(t)
		require.NotNil(t, row)
		assert.Equal(t, appName, row.AppName, "round %d: the general save was lost", round)
		assert.Equal(t, theme, row.UITheme, "round %d: the ui theme save was lost", round)
		assert.Equal(t, fromName, row.SMTPFromName, "round %d: the email save was lost", round)
		assert.Equal(t, idleTimeout, row.UserSessionIdleTimeoutInSeconds, "round %d: the sessions save was lost", round)
		assert.Equal(t, tokenExpiration, row.TokenExpirationInSeconds, "round %d: the tokens save was lost", round)
		assert.Equal(t, retentionDays, row.AuditLogRetentionDays, "round %d: the audit logs save was lost", round)
		assert.Equal(t, start.Issuer, row.Issuer, "round %d: a save moved the issuer", round)
		assert.Equal(t, start.SMTPHost, row.SMTPHost, "round %d: a save moved the SMTP host", round)
	}
}
