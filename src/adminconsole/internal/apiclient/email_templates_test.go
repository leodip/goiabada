package apiclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/api"
)

// The email templates pages (#818 decision 14) bind what these methods decode. The bodies are
// literal JSON text, as in legal_documents_test.go, so a renamed json tag in core/api fails here
// rather than leaving the editor blank.
//
// serves lives in users_test.go.
const emailTemplateBody = `{
	"emailTemplate": {
		"id": "password_reset_link",
		"hasButton": true,
		"placeholders": [
			{"name": "app_name", "required": false, "inSubject": true},
			{"name": "link", "required": true, "inSubject": false}
		],
		"languages": [
			{
				"language": "fr",
				"status": "invalid",
				"builtInText": {"subject": "Réinitialisation", "buttonLabel": "Réinitialiser", "body": "Bonjour {{name}},"},
				"editorText": {"subject": "Mot de passe", "buttonLabel": "Réinitialiser", "body": "Bonjour {{nom}},"},
				"editedFields": ["subject", "body"],
				"problems": [
					{"field": "body", "rule": "unknown_placeholder", "placeholder": "nom", "message": "Le corps utilise {{nom}}."}
				]
			}
		]
	}
}`

// The editor reads the placeholders, the button and each language's two texts, status and problems
// out of one answer: a decode that dropped the editor's text would open the editor on the built-in
// text and lose the administrator's edit, and one that dropped the problems would hide why the
// built-in text is being sent.
func TestAuthServerClient_GetEmailTemplateDecodesEveryFieldTheEditorBinds(t *testing.T) {
	client, recorded := serves(t, emailTemplateBody)

	email, err := client.GetEmailTemplate(context.Background(), "an-access-token", "password_reset_link")
	require.NoError(t, err)

	gotPath, gotAuthorization := recorded()
	assert.Equal(t, "/api/v1/admin/email-templates/password_reset_link", gotPath)
	assert.Equal(t, "Bearer an-access-token", gotAuthorization)

	assert.Equal(t, "password_reset_link", email.Id)
	assert.True(t, email.HasButton)
	assert.Equal(t, []api.EmailTemplatePlaceholderResponse{
		{Name: "app_name", Required: false, InSubject: true},
		{Name: "link", Required: true, InSubject: false},
	}, email.Placeholders)
	require.Len(t, email.Languages, 1)
	fr := email.Languages[0]
	assert.Equal(t, "fr", fr.Language)
	assert.Equal(t, "invalid", fr.Status)
	assert.Equal(t, "Réinitialisation", fr.BuiltInText.Subject)
	assert.Equal(t, "Mot de passe", fr.EditorText.Subject)
	require.NotNil(t, fr.EditorText.ButtonLabel)
	assert.Equal(t, "Réinitialiser", *fr.EditorText.ButtonLabel)
	assert.Equal(t, "Bonjour {{nom}},", fr.EditorText.Body)
	assert.Equal(t, []string{"subject", "body"}, fr.EditedFields)
	assert.Equal(t, []api.EmailTemplateProblemResponse{
		{Field: "body", Rule: "unknown_placeholder", Placeholder: "nom", Message: "Le corps utilise {{nom}}."},
	}, fr.Problems)
}

// The list reads each email's identifier and its languages' status.
func TestAuthServerClient_GetEmailTemplatesDecodesEachEmailsLanguages(t *testing.T) {
	client, recorded := serves(t, `{"emailTemplates": [
		{"id": "welcome", "languages": [{"language": "en", "status": "default"}, {"language": "de", "status": "invalid"}]}
	]}`)

	emails, err := client.GetEmailTemplates(context.Background(), "an-access-token")
	require.NoError(t, err)

	gotPath, _ := recorded()
	assert.Equal(t, "/api/v1/admin/email-templates", gotPath)
	assert.Equal(t, []api.EmailTemplateSummaryResponse{{Id: "welcome", Languages: []api.EmailTemplateLanguageStatusResponse{
		{Language: "en", Status: "default"}, {Language: "de", Status: "invalid"},
	}}}, emails)
}

// The email and the language come from the console's own URL, so each is escaped as one path
// segment: one holding a slash names no other admin API route.
func TestAuthServerClient_EmailTemplateCallsEscapeTheEmailAndTheLanguage(t *testing.T) {
	var gotPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.EscapedPath())
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut:
			_, _ = w.Write([]byte(`{"language":"en","status":"edited"}`))
		default:
			_, _ = w.Write([]byte(`{"emailTemplate":{"id":"x"}}`))
		}
	}))
	t.Cleanup(server.Close)
	client := NewAuthServerClient(server.URL, nil, nil)
	ctx := context.Background()

	_, err := client.GetEmailTemplate(ctx, "t", "../users")
	require.NoError(t, err)
	_, err = client.SaveEmailTemplate(ctx, "t", "welcome/../x", "en/..", &api.SaveEmailTemplateRequest{})
	require.NoError(t, err)
	require.NoError(t, client.ResetEmailTemplate(ctx, "t", "welcome", "pt BR"))

	assert.Equal(t, []string{
		"/api/v1/admin/email-templates/..%2Fusers",
		"/api/v1/admin/email-templates/welcome%2F..%2Fx/en%2F..",
		"/api/v1/admin/email-templates/welcome/pt%20BR",
	}, gotPaths)
}
