package rendertest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The sign-in refusal page through the real renderer, in pt-BR, with each of the five messages
// the callback chooses (#427 decisions 10 and 11, seam 7). The callback's own tests assert which
// keys it binds; this is what those keys render to. A 400 offers the way back to the console's
// home, from which every card starts a sign-in; a 500 names the request id the log has the cause
// under instead, since starting again cannot fix what an operator must.
func TestRender_SignInErrorPage(t *testing.T) {
	const requestID = "req-sign-in-error"
	const startAgain = "Começar de novo"
	const logLine = "O log do servidor registra a causa sob este ID de requisição:"

	testCases := []struct {
		name        string
		titleKey    string
		messageKey  string
		code        string
		description string
		serverFault bool
		wantTitle   string
		wantMessage string
	}{
		{
			name:        "session",
			titleKey:    "adminconsole.sign_in_error.session.title",
			messageKey:  "adminconsole.sign_in_error.session.body",
			wantTitle:   "Não foi possível concluir este acesso",
			wantMessage: "Ele pode ter expirado, sido iniciado em outra aba ou janela, ou sido interrompido.",
		},
		{
			name:        "no session came back",
			titleKey:    "adminconsole.sign_in_error.session.title",
			messageKey:  "adminconsole.sign_in_error.no_session.body",
			wantTitle:   "Não foi possível concluir este acesso",
			wantMessage: "Seu navegador não trouxe de volta a sessão deste acesso.",
		},
		{
			name:        "the auth server's description",
			titleKey:    "adminconsole.sign_in_error.refused.title",
			messageKey:  "adminconsole.sign_in_error.refused.body_description",
			code:        "access_denied",
			description: "O usuário está desativado.",
			wantTitle:   "O servidor de autenticação recusou o acesso",
			wantMessage: "Ele respondeu: O usuário está desativado.",
		},
		{
			name:        "the auth server's code",
			titleKey:    "adminconsole.sign_in_error.refused.title",
			messageKey:  "adminconsole.sign_in_error.refused.body_code",
			code:        "access_denied",
			wantTitle:   "O servidor de autenticação recusou o acesso",
			wantMessage: "Ele respondeu com o código de erro access_denied, sem descrição.",
		},
		{
			name:        "the exchange failed",
			titleKey:    "adminconsole.sign_in_error.failed.title",
			messageKey:  "adminconsole.sign_in_error.exchange.body",
			serverFault: true,
			wantTitle:   "Falha no acesso",
			wantMessage: "O console de administração não conseguiu concluir o acesso com o servidor de autenticação.",
		},
		{
			name:        "the answer could not be verified",
			titleKey:    "adminconsole.sign_in_error.failed.title",
			messageKey:  "adminconsole.sign_in_error.unverified.body",
			serverFault: true,
			wantTitle:   "Falha no acesso",
			wantMessage: "Não foi possível verificar a resposta do servidor de autenticação.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := renderWithLayout(t, "/layouts/no_menu_layout.html", "/sign_in_error.html", map[string]interface{}{
				"titleKey":    tc.titleKey,
				"messageKey":  tc.messageKey,
				"code":        tc.code,
				"description": tc.description,
				"serverFault": tc.serverFault,
				"requestId":   requestID,
			})

			assert.Contains(t, out, tc.wantTitle)
			assert.Contains(t, out, tc.wantMessage)
			if tc.serverFault {
				assert.Contains(t, out, logLine)
				assert.Contains(t, out, requestID)
				assert.NotContains(t, out, startAgain)
			} else {
				assert.Contains(t, out, `href="/"`)
				assert.Contains(t, out, startAgain)
				assert.NotContains(t, out, logLine)
				assert.NotContains(t, out, requestID)
			}
		})
	}
}

// The description is the auth server's text passed through the browser, conformed to RFC 6749's
// error_description characters, which admit '<' and '>'. It reaches the page as text.
func TestRender_SignInErrorPage_EscapesTheAuthServersDescription(t *testing.T) {
	out := renderWithLayout(t, "/layouts/no_menu_layout.html", "/sign_in_error.html", map[string]interface{}{
		"titleKey":    "adminconsole.sign_in_error.refused.title",
		"messageKey":  "adminconsole.sign_in_error.refused.body_description",
		"code":        "access_denied",
		"description": "<script>alert(1)</script><b>bold</b>",
		"serverFault": false,
		"requestId":   "req",
	})

	assert.NotContains(t, out, "<script>alert(1)</script>")
	assert.NotContains(t, out, "<b>bold</b>")
	assert.True(t, strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;"), "rendered as text")
}
