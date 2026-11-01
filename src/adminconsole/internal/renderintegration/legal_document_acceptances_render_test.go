package renderintegration

import (
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
)

// A user's acceptances of legal documents (#622 decision 10): My Account's Legal documents page and
// the user's Legal documents tab, drawn by the real templates in pt-BR from the DTOs the API client
// hands the handlers.

// twoAcceptances is version 1 of "Regras da casa", whose document is retired, accepted after version
// 2 of "Termos de uso", whose document is in effect: the latest first, as the API answers them.
func twoAcceptances() []api.LegalDocumentAcceptanceResponse {
	accepted := time.Date(2026, 10, 21, 14, 5, 0, 0, time.UTC)
	earlier := time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)
	url := "https://auth.example/legal/terms/versions/2"
	return []api.LegalDocumentAcceptanceResponse{
		{Id: 4, AcceptedAt: &accepted, LegalDocumentId: 8, ShortName: "house", Version: 1, Title: "Regras da casa", Retired: true},
		{Id: 3, AcceptedAt: &earlier, LegalDocumentId: 7, ShortName: "terms", Version: 2, Title: "Termos de uso", URL: &url},
	}
}

func TestRender_AccountLegalDocuments(t *testing.T) {
	t.Run("acceptances", func(t *testing.T) {
		out := renderMenuPageAt(t, "/account/legal-documents", "/account_legal_documents.html", map[string]interface{}{
			"acceptances": twoAcceptances(),
		})

		assert.Contains(t, out, `href="/account/legal-documents" aria-current="page">`, "the menu marks the page")
		assert.Contains(t, out, `<h1 class="page-title" id="page-title">Documentos legais</h1>`)
		assert.Contains(t, out, `<a class="text-link" href="https://auth.example/legal/terms/versions/2">Termos de uso</a>`,
			"a document in effect links the accepted version's public page")
		assert.Contains(t, out, `<span class="font-semibold">Regras da casa</span>`)
		assert.Contains(t, out, `<span class="cell-secondary">Não está mais em vigor</span>`,
			"a retired document's pages answer not found, so it says so instead of linking")
		assert.NotContains(t, out, `/legal/house`)
		assert.Contains(t, out, `<td data-label="Versão">2</td>`)
		assert.Contains(t, out, `<td class="sm:whitespace-nowrap" data-label="Aceito em">21/10/2026 14:05</td>`)
		assert.Less(t, strings.Index(out, "Regras da casa"), strings.Index(out, "Termos de uso"), "in the order the API answers, the latest first")
		assert.NotContains(t, out, "<form", "the page only reads")
	})

	t.Run("none", func(t *testing.T) {
		out := renderMenuPage(t, "/account_legal_documents.html", map[string]interface{}{
			"acceptances": []api.LegalDocumentAcceptanceResponse{},
		})

		assert.Contains(t, out, "Você não aceitou nenhum documento legal.")
		assert.NotContains(t, out, `id="acceptancesTable"`)
	})
}

func TestRender_AdminUserLegalDocuments(t *testing.T) {
	t.Run("acceptances", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_users_legal_documents.html", map[string]interface{}{
			"user":        &api.UserResponse{Id: 5, Email: "someone@example.com"},
			"acceptances": twoAcceptances(),
			"page":        "2",
			"query":       "some",
		})

		assert.Contains(t, out, `href="/admin/users/5/legal-documents?page=2&query=some" aria-current="page">Documentos legais</a>`,
			"the tab is marked and keeps the list's page and search")
		assert.Contains(t, out, `href="/admin/legal-documents/8/versions/1">Ver texto`,
			"a retired document's accepted version opens in the console")
		assert.Contains(t, out, `href="/admin/legal-documents/7/versions/2">Ver texto`)
		assert.Contains(t, out, `<span class="font-semibold">Regras da casa</span> <span class="tag">Retirado</span>`)
		assert.NotContains(t, out, `Termos de uso</span> <span class="tag">`, "a document in effect is not marked retired")
		assert.Contains(t, out, `<span class="cell-secondary font-mono text-sm">terms</span>`)
		assert.Contains(t, out, `<td class="sm:whitespace-nowrap" data-label="Aceito em">20/10/2026 09:30</td>`)
		assert.NotContains(t, out, "https://auth.example", "the console opens the text itself")
		assert.NotContains(t, out, "<form", "the tab only reads")
	})

	t.Run("none", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_users_legal_documents.html", map[string]interface{}{
			"user":        &api.UserResponse{Id: 5, Email: "someone@example.com"},
			"acceptances": []api.LegalDocumentAcceptanceResponse{},
			"page":        "",
			"query":       "",
		})

		assert.Contains(t, out, "Este usuário não aceitou nenhum documento legal.")
	})
}
