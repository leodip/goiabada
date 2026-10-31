package adminlegaldocumenthandlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/sessionstore"
)

// HandleVersionsGet lists the document's published versions, the first first, saying what the
// write that redirected here did: a publish, a retirement or a restoration.
func HandleVersionsGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentReader,
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
		flashes, ok := takeFlashes(httpHelper, httpSession, w, r, flashPublished, flashRetired, flashRestored)
		if !ok {
			return
		}

		_, retired := flashes[flashRetired]
		_, restored := flashes[flashRestored]
		renderVersions(httpHelper, w, r, detail, map[string]interface{}{
			"publishedVersion": flashes[flashPublished],
			"retired":          retired,
			"restored":         restored,
		})
	}
}

// legalDocumentVersionAPI is what one version's page needs: the version with its text.
type legalDocumentVersionAPI interface {
	GetLegalDocumentVersion(ctx context.Context, accessToken string, legalDocumentId int64, version int) (*api.GetLegalDocumentVersionResponse, error)
}

// HandleVersionGet shows one published version's text, a retired document's included, rendered as
// its public page renders it, with the Markdown it was written in.
func HandleVersionGet(
	httpHelper HttpHelper,
	apiClient legalDocumentVersionAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, ok := legalDocumentId(r)
		if !ok {
			httpHelper.NotFound(w, r)
			return
		}
		number, err := strconv.Atoi(r.PathValue("version"))
		if err != nil || number <= 0 {
			httpHelper.NotFound(w, r)
			return
		}
		token, ok := accessToken(httpHelper, w, r)
		if !ok {
			return
		}

		version, err := apiClient.GetLegalDocumentVersion(r.Context(), token, id, number)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		bind := map[string]interface{}{
			"doc":     version.LegalDocument,
			"version": version.Version,
		}
		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_legal_documents_version.html", bind); err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}
