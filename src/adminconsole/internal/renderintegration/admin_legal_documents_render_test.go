package renderintegration

import (
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/api"

	"github.com/stretchr/testify/assert"
)

// The Legal documents section's pages (#622), drawn by the real templates, funcmap and layout, in
// pt-BR, from the DTOs the API client hands the handlers.

func legalDocumentAt(id int64, shortName, kind, title string, version int) api.LegalDocumentResponse {
	published := time.Date(2026, 10, 20, 12, 30, 0, 0, time.UTC)
	doc := api.LegalDocumentResponse{Id: id, ShortName: shortName, Kind: kind, Title: title, CurrentVersion: version,
		AppliesTo: "all_apps", ClientIds: []int64{}}
	if version > 0 {
		doc.PublishedAt = &published
	}
	return doc
}

// The list names each document by its title, linking to its draft, with its short name, its kind
// and its state; only a document never published offers Delete.
func TestRender_AdminLegalDocuments(t *testing.T) {
	retired := legalDocumentAt(9, "old-terms", "must_accept", "Termos antigos", 3)
	retired.Retired = true
	withDraft := legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2)
	withDraft.HasDraft = true
	out := renderMenuPageAt(t, "/admin/legal-documents", "/admin_legal_documents.html", map[string]interface{}{
		"legalDocuments": []api.LegalDocumentResponse{
			withDraft,
			legalDocumentAt(8, "privacy", "for_information", "Aviso de privacidade", 0),
			retired,
		},
	})

	assert.Contains(t, out, `<a class="text-link" href="/admin/legal-documents/7/draft">Termos de uso</a>`)
	assert.Contains(t, out, `<span class="cell-secondary font-mono">terms-of-use</span>`)
	assert.Contains(t, out, `<span class="tag tag-note">Os usuários devem aceitar</span>`)
	assert.Contains(t, out, `<span class="tag tag-positive">Versão 2</span><span class="tag">Rascunho</span>`,
		"a published document with a draft shows both")
	//nolint:misspell // the pt-BR catalog's text: "Informativo" is Portuguese, not a misspelling of "Information"
	assert.Contains(t, out, `<span class="tag">Informativo</span><span class="tag">Não publicado</span>`)
	assert.Contains(t, out, `<span class="tag tag-caution">Retirado</span>`)
	assert.Contains(t, out, `href="/admin/legal-documents/8/delete"`)
	assert.NotContains(t, out, `href="/admin/legal-documents/7/delete"`, "a published document is never deleted")
	assert.NotContains(t, out, `href="/admin/legal-documents/9/delete"`)
	assert.Contains(t, out, `href="/admin/legal-documents" aria-current="page"`, "the sidebar marks the section")
}

func TestRender_AdminLegalDocumentsEmpty(t *testing.T) {
	out := renderMenuPage(t, "/admin_legal_documents.html", map[string]interface{}{
		"legalDocuments": []api.LegalDocumentResponse{},
	})

	assert.Contains(t, out, "Nenhum documento legal ainda.")
	assert.Contains(t, out, `href="/admin/legal-documents/new"`)
}

// The new document form offers both kinds and chooses neither; a refusal marks the field it is
// about and keeps what was typed.
func TestRender_AdminLegalDocumentNew(t *testing.T) {
	t.Run("as it opens", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_new.html", map[string]interface{}{
			"kind": "", "title": "", "shortName": "",
		})

		assert.Contains(t, out, `name="kind" value="must_accept" aria-labelledby`)
		assert.Contains(t, out, `name="kind" value="for_information" aria-labelledby`)
		assert.NotContains(t, out, " checked", "no kind is chosen for the administrator")
		assert.Contains(t, out, `src="/static/pages/legal-document-new.js`)
	})

	t.Run("refused at the short name", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_new.html", map[string]interface{}{
			"kind": "for_information", "title": "Aviso", "shortName": "Aviso!",
			"error": "Outro documento já usa este nome curto.", "errorField": "shortName",
		})

		assert.Contains(t, out, `value="for_information" checked`)
		assert.Contains(t, out, `id="shortName" type="text" name="shortName" value="Aviso!"`)
		assert.Regexp(t, `id="shortName"[^>]*aria-describedby="legal-document-error shortNameHint" aria-invalid="true" autofocus>`, out)
		assert.NotRegexp(t, `id="title"[^>]*aria-invalid`, out)
	})
}

// The editor: the text as stored in its textarea, escaped, the preview beside it, and Publish only
// for a saved draft of a document in effect.
func TestRender_AdminLegalDocumentDraft(t *testing.T) {
	bind := func(doc api.LegalDocumentResponse, hasDraft bool) map[string]interface{} {
		return map[string]interface{}{
			"doc": doc, "shortName": doc.ShortName, "title": doc.Title,
			"markdown": "# Termos\n\n<script>alert(1)</script>", "hasDraft": hasDraft,
			"shortNameFixed": doc.CurrentVersion > 0, "nextVersion": doc.CurrentVersion + 1,
			"mustAccept": doc.Kind == "must_accept",
		}
	}

	t.Run("a published document's draft", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_draft.html",
			bind(legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2), true))

		assert.Contains(t, out, "# Termos\n\n&lt;script&gt;alert(1)&lt;/script&gt;</textarea>",
			"the text is the textarea's as written, never markup")
		assert.Contains(t, out, `<input class="control control-mono" id="shortName" type="text" value="terms-of-use" readonly`,
			"a published document's short name is shown, fixed, and not posted")
		assert.NotContains(t, out, `name="shortName"`)
		assert.Contains(t, out, `id="legalDocumentPreview" data-preview-url="/admin/legal-documents/preview" data-preview-source="markdown"`)
		assert.Contains(t, out, `src="/static/pages/legal-document-preview.js`)
		assert.Contains(t, out, `action="/admin/legal-documents/7/publish" data-confirm-dialog="confirmPublish"`)
		assert.Contains(t, out, ">Publicar a versão 3</button>")
		assert.Contains(t, out, "serão solicitados a aceitá-la", "a must-accept version is accepted again")
		assert.Contains(t, out, `action="/admin/legal-documents/7/retire" data-confirm-dialog="confirmRetire"`)
	})

	t.Run("a document never published", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_draft.html",
			bind(legalDocumentAt(8, "privacy", "for_information", "Aviso de privacidade", 0), true))

		assert.Contains(t, out, `id="shortName" type="text" name="shortName" value="privacy"`, "its short name can still change")
		assert.Contains(t, out, ">Publicar a versão 1</button>")
		assert.NotContains(t, out, "serão solicitados a aceitá-la", "a notice is never accepted")
		assert.Contains(t, out, `href="/admin/legal-documents/8/delete"`)
		assert.NotContains(t, out, "/retire")
	})

	t.Run("no draft", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_draft.html",
			bind(legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2), false))

		assert.Contains(t, out, "o texto abaixo é a versão 2")
		assert.NotContains(t, out, "/publish", "there is no draft to publish")
	})

	t.Run("retired", func(t *testing.T) {
		doc := legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2)
		doc.Retired = true
		out := renderMenuPage(t, "/admin_legal_documents_draft.html", bind(doc, true))

		assert.Contains(t, out, "Este documento está retirado")
		assert.Contains(t, out, `id="markdown" name="markdown" rows="20" spellcheck="true" readonly`)
		assert.NotContains(t, out, `id="btnSave"`)
		assert.NotContains(t, out, "/publish")
		assert.Contains(t, out, `action="/admin/legal-documents/7/restore" data-confirm-dialog="confirmRestore"`)
		assert.Contains(t, out, "na versão 2. Os usuários que aceitaram essa versão não serão solicitados novamente.")
	})
}

// The versions, the first first, each linking to its text, the current one marked, and what the
// write that redirected here did.
func TestRender_AdminLegalDocumentVersions(t *testing.T) {
	published := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	out := renderMenuPage(t, "/admin_legal_documents_versions.html", map[string]interface{}{
		"doc": legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2),
		"versions": []api.LegalDocumentVersionSummaryResponse{
			{Version: 1, Title: "Termos", PublishedAt: &published},
			{Version: 2, Title: "Termos de uso", PublishedAt: &published},
		},
		"publishedVersion": "2", "retired": false, "restored": false, "mustAccept": true,
	})

	assert.Contains(t, out, `href="/admin/legal-documents/7/versions/1">Versão 1</a></td>`)
	assert.Contains(t, out, `href="/admin/legal-documents/7/versions/2">Versão 2</a> <span class="tag tag-positive">Atual</span>`)
	assert.Equal(t, 1, strings.Count(out, ">Atual</span>"))
	assert.Contains(t, out, "Versão 2 publicada.")
	assert.Contains(t, out, `href="/admin/legal-documents/7/versions" aria-current="page"`)
}

// One version: its Markdown handed to the preview script as JSON, which no HTML parser reads, and
// shown as written.
func TestRender_AdminLegalDocumentVersion(t *testing.T) {
	published := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	out := renderMenuPage(t, "/admin_legal_documents_version.html", map[string]interface{}{
		"doc": legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2),
		"version": api.LegalDocumentVersionResponse{Version: 1, Title: "Termos",
			Markdown: "Seja gentil.\n</script><b>", PublishedAt: &published},
	})

	assert.Contains(t, out, `<script type="application/json" id="version-markdown">"Seja gentil.\n\u003c/script\u003e\u003cb\u003e"</script>`)
	assert.Contains(t, out, `<pre class="legal-source" id="versionMarkdown">Seja gentil.
&lt;/script&gt;&lt;b&gt;</pre>`)
	assert.Contains(t, out, `data-preview-source="version-markdown"`)
	assert.Contains(t, out, `<h1 class="page-title">Versão 1</h1>`)
}

// A document never published is deleted once its short name is typed; a published one's page says
// to retire it and offers no deletion.
func TestRender_AdminLegalDocumentDelete(t *testing.T) {
	t.Run("never published", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_delete.html", map[string]interface{}{
			"doc": legalDocumentAt(8, "privacy", "for_information", "Aviso de privacidade", 0), "published": false,
			"mustAccept": false,
		})

		assert.Contains(t, out, `<dd class="font-mono text-sm break-words">privacy</dd>`)
		assert.Contains(t, out, `id="btnDelete"`)
	})

	t.Run("published", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_delete.html", map[string]interface{}{
			"doc": legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2), "published": true,
			"mustAccept": true,
		})

		assert.Contains(t, out, "Um documento publicado não pode ser excluído")
		assert.NotContains(t, out, `id="btnDelete"`)
		assert.NotContains(t, out, `<form class="panel" method="post"`)
	})
}

// The list says what each document applies to, and flags one set to selected apps that lists none,
// which applies to nobody. A retired document applies to no app anyway, so it is not flagged.
func TestRender_AdminLegalDocumentsAppliesTo(t *testing.T) {
	selected := legalDocumentAt(7, "shop-terms", "must_accept", "Termos da loja", 1)
	selected.AppliesTo, selected.ClientIds = "selected_apps", []int64{4}
	none := legalDocumentAt(8, "nobody", "must_accept", "Ninguém", 1)
	none.AppliesTo = "selected_apps"
	retiredNone := legalDocumentAt(9, "old", "must_accept", "Antigo", 1)
	retiredNone.AppliesTo, retiredNone.Retired = "selected_apps", true
	out := renderMenuPage(t, "/admin_legal_documents.html", map[string]interface{}{
		"legalDocuments": []api.LegalDocumentResponse{
			legalDocumentAt(6, "privacy", "for_information", "Aviso de privacidade", 1), selected, none, retiredNone,
		},
	})

	assert.Contains(t, out, `<th scope="col">Aplica-se a</th>`)
	assert.Contains(t, out, `<td data-label="Aplica-se a">Todos os aplicativos</td>`)
	assert.Contains(t, out, `<td data-label="Aplica-se a">Aplicativos selecionados</td>`)
	assert.Equal(t, 1, strings.Count(out, `<span class="tag tag-caution">Nenhum aplicativo</span><span class="cell-secondary">Não se aplica a ninguém</span>`),
		"only the document in effect with no apps is flagged")
}

// The Applies to tab: both choices, the apps offered as boxes, the list as stored carried back
// with the save, and a document left with no apps said to apply to nobody.
func TestRender_AdminLegalDocumentApps(t *testing.T) {
	bind := func(doc api.LegalDocumentResponse, allApps bool, apps []map[string]any) map[string]interface{} {
		type appChoice struct {
			Id          int64
			Identifier  string
			Description string
			Selected    bool
		}
		choices := []appChoice{}
		for _, a := range apps {
			choices = append(choices, appChoice{Id: a["id"].(int64), Identifier: a["identifier"].(string),
				Description: a["description"].(string), Selected: a["selected"].(bool)})
		}
		return map[string]interface{}{
			"doc": doc, "allApps": allApps, "apps": choices, "expectedClientIds": doc.ClientIds,
			"noApps": doc.AppliesTo != "all_apps" && len(doc.ClientIds) == 0,
		}
	}
	shop := map[string]any{"id": int64(4), "identifier": "shop", "description": "A loja", "selected": true}
	blog := map[string]any{"id": int64(6), "identifier": "blog", "description": "", "selected": false}

	t.Run("selected apps", func(t *testing.T) {
		doc := legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2)
		doc.AppliesTo, doc.ClientIds = "selected_apps", []int64{4}
		out := renderMenuPage(t, "/admin_legal_documents_apps.html", bind(doc, false, []map[string]any{blog, shop}))

		assert.Contains(t, out, `href="/admin/legal-documents/7/apps" aria-current="page">Aplica-se a</a>`, "the tab is current")
		assert.Contains(t, out, `<form class="panel" id="appsForm" method="post" action="/admin/legal-documents/7/apps" novalidate>`)
		assert.Contains(t, out, `<input type="hidden" name="expectedClientId" value="4">`)
		assert.Contains(t, out, `name="appliesTo" value="all_apps" aria-labelledby`)
		assert.Contains(t, out, `name="appliesTo" value="selected_apps" checked`)
		assert.Contains(t, out, `<input type="checkbox" id="app-4" name="clientId" value="4" checked aria-describedby="app-4-hint">`)
		assert.Contains(t, out, `<input type="checkbox" id="app-6" name="clientId" value="6">`)
		assert.Contains(t, out, `<span class="field-hint" id="app-4-hint">A loja</span>`)
		assert.Contains(t, out, `id="btnSaveApps"`)
		assert.NotContains(t, out, `id="noAppsNotice"`)
	})

	t.Run("all apps", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_apps.html",
			bind(legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2), true, []map[string]any{blog}))

		assert.Contains(t, out, `name="appliesTo" value="all_apps" checked`)
		assert.NotContains(t, out, `name="expectedClientId"`, "an empty list carries no id")
	})

	t.Run("selected apps with none", func(t *testing.T) {
		doc := legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2)
		doc.AppliesTo = "selected_apps"
		out := renderMenuPage(t, "/admin_legal_documents_apps.html", bind(doc, false, []map[string]any{blog}))

		assert.Contains(t, out, `id="noAppsNotice"`)
		assert.Contains(t, out, "este documento não se aplica a ninguém")
	})

	t.Run("no app to choose", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_legal_documents_apps.html",
			bind(legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2), true, nil))

		assert.Contains(t, out, "Não há aplicativos para escolher.")
	})

	t.Run("retired", func(t *testing.T) {
		doc := legalDocumentAt(7, "terms-of-use", "must_accept", "Termos de uso", 2)
		doc.Retired = true
		out := renderMenuPage(t, "/admin_legal_documents_apps.html", bind(doc, true, []map[string]any{blog}))

		assert.Contains(t, out, "Este documento está retirado, então os aplicativos")
		assert.Equal(t, 2, strings.Count(out, "<fieldset disabled>"), "both choices are read only")
		assert.NotContains(t, out, `id="btnSaveApps"`)
	})
}

// A client's Legal documents tab lists, read only, the documents that apply to it.
func TestRender_AdminClientLegalDocuments(t *testing.T) {
	selected := legalDocumentAt(8, "shop-terms", "must_accept", "Termos da loja", 0)
	selected.AppliesTo, selected.ClientIds = "selected_apps", []int64{3}

	t.Run("an app", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_clients_legal_documents.html", map[string]interface{}{
			"client": &api.ClientResponse{Id: 3, ClientIdentifier: "shop"},
			"legalDocuments": []api.LegalDocumentResponse{
				legalDocumentAt(7, "privacy", "for_information", "Aviso de privacidade", 1), selected,
			},
		})

		assert.Contains(t, out, `href="/admin/clients/3/legal-documents" aria-current="page">Documentos legais</a>`)
		assert.Contains(t, out, `<a class="text-link" href="/admin/legal-documents/7/draft">Aviso de privacidade</a>`)
		assert.Contains(t, out, `<td data-label="Aplica-se a">Todos os aplicativos</td>`)
		assert.Contains(t, out, `<td data-label="Aplica-se a">Aplicativos selecionados</td>`)
		assert.Contains(t, out, `<span class="tag">Não publicado</span>`, "a document not yet published says so")
		assert.NotContains(t, out, "<form", "the tab is read only")
		assert.NotContains(t, out, "nunca são solicitados a aceitar um documento legal ao entrar no console")
	})

	t.Run("none", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_clients_legal_documents.html", map[string]interface{}{
			"client":         &api.ClientResponse{Id: 3, ClientIdentifier: "shop"},
			"legalDocuments": []api.LegalDocumentResponse{},
		})

		assert.Contains(t, out, "Nenhum documento legal se aplica a este aplicativo.")
	})

	t.Run("the admin console's own client", func(t *testing.T) {
		out := renderMenuPage(t, "/admin_clients_legal_documents.html", map[string]interface{}{
			"client":         &api.ClientResponse{Id: 1, ClientIdentifier: "admin-console-client", IsSystemLevelClient: true},
			"legalDocuments": []api.LegalDocumentResponse{legalDocumentAt(7, "privacy", "for_information", "Aviso de privacidade", 1)},
		})

		assert.Contains(t, out, "Os usuários nunca são solicitados a aceitar um documento legal ao entrar no console de administração.")
	})
}
