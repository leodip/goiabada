package adminlegaldocumenthandlers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The Applies to tab (#622): a document applies to all apps, the default, or to the apps ticked.
// The admin console's own client is never offered: users are never asked to accept a document when
// they sign in to it. The tab draws the document's list as stored and sends it back with the save,
// so the auth server refuses a save from a page another save has outdated. A document set to
// selected apps with none ticked applies to nobody, which the tab says.

// legalDocumentAppsAPI is what the Applies to tab needs: the document, the apps to choose from,
// and the save.
type legalDocumentAppsAPI interface {
	legalDocumentReader
	GetAllClients(ctx context.Context, accessToken string) ([]api.ClientResponse, error)
	UpdateLegalDocumentApps(ctx context.Context, accessToken string, legalDocumentId int64, request *api.UpdateLegalDocumentAppsRequest) (*api.LegalDocumentDetailResponse, error)
}

// appsForm is the tab's choice as it is drawn: as stored, or as posted when a save was refused.
type appsForm struct {
	allApps  bool
	selected map[int64]bool
}

// storedApps is the document's Applies to as stored.
func storedApps(doc api.LegalDocumentResponse) appsForm {
	form := appsForm{allApps: doc.AppliesTo == appliesToAllApps, selected: map[int64]bool{}}
	for _, id := range doc.ClientIds {
		form.selected[id] = true
	}
	return form
}

// renderApps draws the tab with form in its fields and extra beside them, the flash or the
// refusal. It reads the apps to offer, answering the request when it cannot.
func renderApps(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient legalDocumentAppsAPI, token string,
	detail *api.LegalDocumentDetailResponse, form appsForm, extra map[string]interface{}) {
	clients, err := apiClient.GetAllClients(r.Context(), token)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return
	}
	apps := make([]appChoice, 0, len(clients))
	for _, client := range clients {
		if client.IsSystemLevelClient {
			continue
		}
		apps = append(apps, appChoice{
			Id:          client.Id,
			Identifier:  client.ClientIdentifier,
			Description: client.Description,
			Selected:    !form.allApps && form.selected[client.Id],
		})
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Identifier < apps[j].Identifier })

	doc := detail.LegalDocument
	expected := append([]int64{}, doc.ClientIds...)
	bind := map[string]interface{}{
		"doc":               doc,
		"allApps":           form.allApps,
		"apps":              apps,
		"expectedClientIds": expected,
		"noApps":            doc.AppliesTo != appliesToAllApps && len(doc.ClientIds) == 0,
	}
	for k, v := range extra {
		bind[k] = v
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_legal_documents_apps.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

func HandleAppsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentAppsAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		token, ok := accessToken(httpHelper, w, r)
		if !ok {
			return
		}
		detail, ok := loadLegalDocument(httpHelper, w, r, apiClient, token)
		if !ok {
			return
		}
		flashes, ok := takeFlashes(httpHelper, httpSession, w, r, flashAppsSaved)
		if !ok {
			return
		}

		_, appsSaved := flashes[flashAppsSaved]
		renderApps(httpHelper, w, r, apiClient, token, detail, storedApps(detail.LegalDocument),
			map[string]interface{}{"appsSaved": appsSaved})
	}
}

// postedIds reads the ids posted under name, in the order posted. A value that is not an id is
// left out: only an edited page sends one.
func postedIds(r *http.Request, name string) []int64 {
	ids := []int64{}
	for _, value := range r.PostForm[name] {
		if id, err := strconv.ParseInt(value, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// HandleAppsPost saves the tab's choice. All apps sends no app, whatever boxes were left ticked.
func HandleAppsPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentAppsAPI,
	settingsCache publicSettingsCache,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		token, ok := accessToken(httpHelper, w, r)
		if !ok {
			return
		}
		detail, ok := loadLegalDocument(httpHelper, w, r, apiClient, token)
		if !ok {
			return
		}
		if err := r.ParseForm(); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		appliesTo := r.PostFormValue("appliesTo")
		request := &api.UpdateLegalDocumentAppsRequest{
			AppliesTo:         appliesTo,
			ClientIds:         []int64{},
			ExpectedClientIds: postedIds(r, "expectedClientId"),
		}
		form := appsForm{allApps: appliesTo == appliesToAllApps, selected: map[int64]bool{}}
		if !form.allApps {
			request.ClientIds = postedIds(r, "clientId")
			for _, id := range request.ClientIds {
				form.selected[id] = true
			}
		}

		_, err := apiClient.UpdateLegalDocumentApps(r.Context(), token, detail.LegalDocument.Id, request)
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderApps(httpHelper, w, r, apiClient, token, detail, form, map[string]interface{}{"error": message})
			})
			return
		}
		settingsCache.Invalidate()

		if !setFlash(httpHelper, httpSession, w, r, flashAppsSaved, "true") {
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/legal-documents/%v/apps", baseURL, detail.LegalDocument.Id), http.StatusFound)
	}
}
