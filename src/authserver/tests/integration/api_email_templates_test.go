package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/builtin"
)

// The admin API's email templates over HTTP (#818 decisions 8, 9, 10 and 13): the list and the
// read with each language's status, a save that reaches the next email sent and a reset that
// restores the built-in text, the refusals a save names, the scopes, and the audit entries.
//
// Edits are global, so every test that saves one removes it when it ends.

const emailTemplatesPath = "/api/v1/admin/email-templates"

// resetEmailTemplateWhenDone removes the edit of email in lang when the test ends, whatever the
// test left.
func resetEmailTemplateWhenDone(t *testing.T, email, lang string) {
	t.Cleanup(func() {
		_, err := database.DeleteEmailTemplate(context.Background(), nil, email, lang)
		assert.NoError(t, err)
	})
}

// emailTemplateCall sends one admin API request and decodes its JSON answer.
func emailTemplateCall(t *testing.T, accessToken, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	resp, requestId := sendAdmin(t, accessToken, method, path, body)
	defer func() { _ = resp.Body.Close() }()
	var answer map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&answer)
	return resp.StatusCode, answer, requestId
}

// emailTemplateLanguage is lang of the read of email.
func emailTemplateLanguage(t *testing.T, accessToken, email, lang string) map[string]any {
	t.Helper()
	status, body, _ := emailTemplateCall(t, accessToken, http.MethodGet, emailTemplatesPath+"/"+email, nil)
	require.Equal(t, http.StatusOK, status, "read: %v", body)
	for _, l := range body["emailTemplate"].(map[string]any)["languages"].([]any) {
		if l.(map[string]any)["language"] == lang {
			return l.(map[string]any)
		}
	}
	t.Fatalf("no language %s", lang)
	return nil
}

// listedStatus is the status the list gives lang of email.
func listedStatus(t *testing.T, accessToken, email, lang string) string {
	t.Helper()
	status, body, _ := emailTemplateCall(t, accessToken, http.MethodGet, emailTemplatesPath, nil)
	require.Equal(t, http.StatusOK, status, "list: %v", body)
	require.Len(t, body["emailTemplates"], 19)
	for _, e := range body["emailTemplates"].([]any) {
		if e.(map[string]any)["id"] != email {
			continue
		}
		for _, l := range e.(map[string]any)["languages"].([]any) {
			if l.(map[string]any)["language"] == lang {
				return l.(map[string]any)["status"].(string)
			}
		}
	}
	t.Fatalf("no %s/%s in the list", email, lang)
	return ""
}

func TestAPIEmailTemplates_ASavedEditIsSentAndAResetRestoresTheBuiltInText(t *testing.T) {
	useMailpitSMTP(t)
	manageToken, _ := createAdminClientWithToken(t)
	resetEmailTemplateWhenDone(t, "password_reset_link", "en")
	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)

	status, body, _ := emailTemplateCall(t, manageToken, http.MethodPut, emailTemplatesPath+"/password_reset_link/en", map[string]any{
		"subject":     "Choose a new password for {{app_name}}",
		"buttonLabel": "Reset password",
		"body":        "Hi {{name}}, open {{link}} within {{expiry}}.\n\n{{button}}",
	})
	require.Equal(t, http.StatusOK, status, "save: %v", body)
	assert.Equal(t, "edited", body["status"])
	assert.Equal(t, []any{"subject", "body"}, body["editedFields"], "the label left as the built-in one is not stored")

	en := emailTemplateLanguage(t, manageToken, "password_reset_link", "en")
	assert.Equal(t, "edited", en["status"])
	assert.Equal(t, "Choose a new password for {{app_name}}", en["editorText"].(map[string]any)["subject"])
	assert.Equal(t, "Password reset", en["builtInText"].(map[string]any)["subject"])
	assert.Equal(t, "edited", listedStatus(t, manageToken, "password_reset_link", "en"))
	assert.Equal(t, "default", listedStatus(t, manageToken, "password_reset_link", "fr"))

	subject, button, text := resetLinkEmailSent(t, resetLinkUser(t, "Ana", "en"))
	assert.Equal(t, "Choose a new password for "+settings.AppName, subject)
	assert.Equal(t, "Reset password", button)
	assert.True(t, strings.HasPrefix(text, "Hi Ana, open <link> within 5 minutes.\n"), text)

	t.Run("an edit in English leaves the French email as it is", func(t *testing.T) {
		frSubject, _, _ := resetLinkEmailSent(t, resetLinkUser(t, "Camille", "fr"))
		assert.Equal(t, "Réinitialisation du mot de passe", frSubject)
	})

	resp, _ := sendAdmin(t, manageToken, http.MethodDelete, emailTemplatesPath+"/password_reset_link/en", nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	assert.Equal(t, "default", emailTemplateLanguage(t, manageToken, "password_reset_link", "en")["status"])
	subject, button, text = resetLinkEmailSent(t, resetLinkUser(t, "Ana", "en"))
	assert.Equal(t, "Password reset", subject)
	assert.Equal(t, "Reset password", button)
	assert.True(t, strings.HasPrefix(text, "Hello Ana,\n\nYou can reset your password by clicking the link below:\n"), text)
}

// An edit a release made invalid is read with its problems, and its email is sent with the
// built-in text (#818 decision 8).
func TestAPIEmailTemplates_AnInvalidEditIsMarkedWithItsProblems(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	// Stored as a release that offered {{full_name}} might have left it: no save would take it today.
	saveEmailTemplateEdit(t, "password_changed", "es", "", "", "Hola {{full_name}}.")

	es := emailTemplateLanguage(t, manageToken, "password_changed", "es")

	assert.Equal(t, "invalid", es["status"])
	assert.Equal(t, "Hola {{full_name}}.", es["editorText"].(map[string]any)["body"])
	assert.Equal(t, []any{map[string]any{
		"field": "body", "rule": "unknown_placeholder", "placeholder": "full_name",
		"message": "This email does not offer {{full_name}}. It offers {{app_name}}, {{name}}.",
	}}, es["problems"])
	assert.Equal(t, "invalid", listedStatus(t, manageToken, "password_changed", "es"))
}

// A body that types characters but draws nothing to read, an empty list here, is refused by a save,
// and one already stored is read as invalid, naming the rule, so its email is sent with the
// built-in text (#818 decisions 8 and 17).
func TestAPIEmailTemplates_ABodyThatDrawsNothingToReadIsRefusedAndInvalid(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	resetEmailTemplateWhenDone(t, "otp_enabled", "en")

	status, answer, _ := emailTemplateCall(t, manageToken, http.MethodPut, emailTemplatesPath+"/otp_enabled/en",
		map[string]any{"subject": "Two-factor on", "body": "- "})

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.email_template.nothing_to_read", answer["error_code"])
	assert.Equal(t, "/body", answer["error_field"])
	edit, err := database.GetEmailTemplate(context.Background(), nil, "otp_enabled", "en")
	require.NoError(t, err)
	assert.Nil(t, edit, "a refused save stores nothing")

	// Stored as a release whose rule read the characters typed might have left it.
	saveEmailTemplateEdit(t, "otp_enabled", "en", "", "", "- ")

	en := emailTemplateLanguage(t, manageToken, "otp_enabled", "en")
	assert.Equal(t, "invalid", en["status"])
	assert.Equal(t, []any{map[string]any{
		"field": "body", "rule": "nothing_to_read",
		"message": "The body needs something to read besides the button.",
	}}, en["problems"])
	assert.Equal(t, "invalid", listedStatus(t, manageToken, "otp_enabled", "en"))
}

// Two first saves of one email and language at once both succeed, the last one's edit left
// stored: the API saves inside RunInTransaction, which retries a deadlock victim on MySQL and SQL
// Server (#818 decision 7).
func TestAPIEmailTemplates_SimultaneousFirstSavesBothSucceed(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	resetEmailTemplateWhenDone(t, "otp_disabled", "fr")
	path := emailTemplatesPath + "/otp_disabled/fr"
	subjects := []string{"Première", "Seconde"}

	for round := 0; round < 10; round++ {
		_, deleteErr := database.DeleteEmailTemplate(context.Background(), nil, "otp_disabled", "fr")
		require.NoError(t, deleteErr)

		requests := make([]*http.Request, len(subjects))
		for i, subject := range subjects {
			encoded, err := json.Marshal(map[string]any{"subject": subject, "body": "Bonjour {{name}}."})
			require.NoError(t, err)
			requests[i], err = http.NewRequest(http.MethodPut, appConfig.AuthServer.BaseURL+path, bytes.NewReader(encoded))
			require.NoError(t, err)
			requests[i].Header.Set("Authorization", "Bearer "+manageToken)
			requests[i].Header.Set("Content-Type", "application/json")
		}
		client := createHttpClient(t)
		statuses := make([]int, len(requests))
		failures := make([]error, len(requests))
		var wg sync.WaitGroup
		for i, req := range requests {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := client.Do(req)
				if err != nil {
					failures[i] = err
					return
				}
				statuses[i] = resp.StatusCode
				_ = resp.Body.Close()
			}()
		}
		wg.Wait()

		for i := range requests {
			require.NoErrorf(t, failures[i], "round %d, save %d", round, i)
			require.Equalf(t, http.StatusOK, statuses[i], "round %d, save %d", round, i)
		}
		edit, readErr := database.GetEmailTemplate(context.Background(), nil, "otp_disabled", "fr")
		require.NoError(t, readErr)
		require.NotNil(t, edit, "round %d", round)
		assert.Contains(t, subjects, edit.Subject.String, "round %d: one save's edit is left", round)
	}
}

// A save that breaks a rule is refused 400, naming the field and the rule, in the caller's
// language, and stores nothing.
func TestAPIEmailTemplates_ARefusalNamesThePlaceholderInTheCallersLanguage(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	resetEmailTemplateWhenDone(t, "verification_code", "de")
	body := map[string]any{"subject": "Ihr Code", "body": "Ihr Code lautet {{otp}}."}

	status, answer, _ := emailTemplateCall(t, manageToken, http.MethodPut, emailTemplatesPath+"/verification_code/de", body)

	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "handler.email_template.unknown_placeholder", answer["error_code"])
	assert.Equal(t, "/body", answer["error_field"])
	assert.Equal(t, "This email does not offer {{otp}}. It offers {{app_name}}, {{name}}, {{code}}, {{link}}, {{expiry}}.",
		answer["error_description"])

	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPut, appConfig.AuthServer.BaseURL+emailTemplatesPath+"/verification_code/de", bytes.NewReader(encoded))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+manageToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Language", "pt-BR")
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var translated map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&translated))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "handler.email_template.unknown_placeholder", translated["error_code"])
	assert.Equal(t, "Este e-mail não oferece {{otp}}. Ele oferece {{app_name}}, {{name}}, {{code}}, {{link}}, {{expiry}}.",
		translated["error_description"])

	edit, err := database.GetEmailTemplate(context.Background(), nil, "verification_code", "de")
	require.NoError(t, err)
	assert.Nil(t, edit, "a refused save stores nothing")
}

func TestAPIEmailTemplates_AnUnknownEmailOrLanguageIsA404(t *testing.T) {
	manageToken, _ := createAdminClientWithToken(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, emailTemplatesPath + "/no_such_email"},
		{http.MethodPut, emailTemplatesPath + "/welcome/fr-CA"},
		{http.MethodPut, emailTemplatesPath + "/no_such_email/en"},
		{http.MethodDelete, emailTemplatesPath + "/welcome/nl"},
	} {
		status, body, _ := emailTemplateCall(t, manageToken, c.method, c.path, map[string]any{"subject": "S", "body": "B"})
		assert.Equalf(t, http.StatusNotFound, status, "%s %s", c.method, c.path)
		assert.Equalf(t, "NOT_FOUND", body["error_code"], "%s %s", c.method, c.path)
	}
}

// Reading takes any scope that reads settings; saving and resetting take authserver:manage alone,
// and authserver:manage-settings is refused and audited under the settings ceiling (#818
// decision 9).
func TestAPIEmailTemplates_TheScopes(t *testing.T) {
	requireDatabaseAuditLogs(t)
	manageToken, _ := createAdminClientWithToken(t)
	resetEmailTemplateWhenDone(t, "welcome", "it")

	reads := []string{emailTemplatesPath, emailTemplatesPath + "/welcome"}
	writes := []struct {
		method string
		body   any
	}{
		{http.MethodPut, map[string]any{"subject": "Benvenuto", "buttonLabel": "Attiva", "body": "Ciao.\n\n{{button}}"}},
		{http.MethodDelete, nil},
	}
	const writePath = emailTemplatesPath + "/welcome/it"

	for _, c := range []struct {
		permission string
		read       int
		writeCode  string
	}{
		{builtin.AdminReadPermissionIdentifier, http.StatusOK, "INSUFFICIENT_SCOPE"},
		{builtin.ManageUsersPermissionIdentifier, http.StatusForbidden, "INSUFFICIENT_SCOPE"},
		{builtin.ManageClientsPermissionIdentifier, http.StatusForbidden, "INSUFFICIENT_SCOPE"},
		{builtin.ManageSettingsPermissionIdentifier, http.StatusOK, "MANAGE_SCOPE_REQUIRED"},
	} {
		t.Run(c.permission, func(t *testing.T) {
			token, client := createClientWithGranularScope(t, c.permission)
			t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

			for _, path := range reads {
				status, _, _ := emailTemplateCall(t, token, http.MethodGet, path, nil)
				assert.Equalf(t, c.read, status, "GET %s", path)
			}
			for _, w := range writes {
				status, body, requestId := emailTemplateCall(t, token, w.method, writePath, w.body)
				assert.Equalf(t, http.StatusForbidden, status, "%s %s", w.method, writePath)
				assert.Equalf(t, c.writeCode, body["error_code"], "%s %s", w.method, writePath)
				if c.writeCode != "MANAGE_SCOPE_REQUIRED" {
					continue
				}
				rows := refusalRows(t, manageToken, requestId)
				require.Lenf(t, rows, 1, "%s: one administrator_change_refused row", w.method)
				assert.Equal(t, "settings", rows[0]["ceiling"])
				assert.Equal(t, w.method, rows[0]["method"])
				assert.Equal(t, "/api/v1/admin/email-templates/{email}/{language}", rows[0]["route"])
				assert.Equal(t, client.ClientIdentifier, rows[0]["logged_in_user"])
			}
			edit, err := database.GetEmailTemplate(context.Background(), nil, "welcome", "it")
			require.NoError(t, err)
			assert.Nil(t, edit, "a refused save stores nothing")
		})
	}
}

func TestAPIEmailTemplates_ChangesAreAudited(t *testing.T) {
	requireDatabaseAuditLogs(t)
	accessToken, caller := createAdminClientWithToken(t)
	who := caller.ClientIdentifier
	resetEmailTemplateWhenDone(t, "otp_enabled", "fr")
	const path = emailTemplatesPath + "/otp_enabled/fr"

	status, body, requestId := emailTemplateCall(t, accessToken, http.MethodPut, path, map[string]any{
		"subject": "Authentification à deux facteurs activée", "body": "Bonjour {{name}}, c'est fait.",
	})
	require.Equal(t, http.StatusOK, status, "save: %v", body)
	assert.Equal(t, []map[string]any{{
		"email_template": "otp_enabled", "language": "fr", "edited_fields": []any{"subject", "body"}, "logged_in_user": who,
	}}, auditRows(t, accessToken, "updated_email_template", requestId))

	// Saving the built-in text back removes the edit, and is recorded as a reset.
	builtIn := emailTemplateLanguage(t, accessToken, "otp_enabled", "fr")["builtInText"].(map[string]any)
	status, body, requestId = emailTemplateCall(t, accessToken, http.MethodPut, path, map[string]any{
		"subject": builtIn["subject"], "body": builtIn["body"],
	})
	require.Equal(t, http.StatusOK, status, "save: %v", body)
	assert.Equal(t, "default", body["status"])
	assert.Empty(t, auditRows(t, accessToken, "updated_email_template", requestId))
	assert.Equal(t, []map[string]any{{"email_template": "otp_enabled", "language": "fr", "logged_in_user": who}},
		auditRows(t, accessToken, "reset_email_template", requestId))

	// A reset with no edit records nothing.
	resp, requestId := sendAdmin(t, accessToken, http.MethodDelete, path, nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Empty(t, auditRows(t, accessToken, "reset_email_template", requestId))

	// A reset of an edit records one.
	status, body, _ = emailTemplateCall(t, accessToken, http.MethodPut, path, map[string]any{
		"subject": "Activée", "body": builtIn["body"],
	})
	require.Equal(t, http.StatusOK, status, "save: %v", body)
	resp, requestId = sendAdmin(t, accessToken, http.MethodDelete, path, nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, []map[string]any{{"email_template": "otp_enabled", "language": "fr", "logged_in_user": who}},
		auditRows(t, accessToken, "reset_email_template", requestId))
}
