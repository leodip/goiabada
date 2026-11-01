package adminlegaldocumenthandlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/sessionstore"
)

// legalDocumentRetireAPI is what Retire needs: the document, which a refusal is drawn with, and
// the write.
type legalDocumentRetireAPI interface {
	legalDocumentReader
	RetireLegalDocument(ctx context.Context, accessToken string, legalDocumentId int64) (*api.LegalDocumentDetailResponse, error)
}

// legalDocumentRestoreAPI is the same for Restore.
type legalDocumentRestoreAPI interface {
	legalDocumentReader
	RestoreLegalDocument(ctx context.Context, accessToken string, legalDocumentId int64) (*api.LegalDocumentDetailResponse, error)
}

// HandleRetirePost retires a published document: it applies to no one from then on, and its
// versions stay, readable here. It can be restored.
func HandleRetirePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentRetireAPI,
	settingsCache publicSettingsCache,
	baseURL string,
) http.HandlerFunc {
	return lifecycleAction(httpHelper, httpSession, apiClient, settingsCache, baseURL, flashRetired, apiClient.RetireLegalDocument)
}

// HandleRestorePost restores a retired document as it was, its current version included.
func HandleRestorePost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentRestoreAPI,
	settingsCache publicSettingsCache,
	baseURL string,
) http.HandlerFunc {
	return lifecycleAction(httpHelper, httpSession, apiClient, settingsCache, baseURL, flashRestored, apiClient.RestoreLegalDocument)
}

// lifecycleAction asks the API to act on the document the path names and opens its versions,
// saying so through flash, or says the API's refusal there.
func lifecycleAction(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient legalDocumentReader,
	settingsCache publicSettingsCache,
	baseURL string,
	flash string,
	act func(ctx context.Context, accessToken string, legalDocumentId int64) (*api.LegalDocumentDetailResponse, error),
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

		if _, err := act(r.Context(), token, detail.LegalDocument.Id); err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderVersions(httpHelper, w, r, detail, map[string]interface{}{"error": message})
			})
			return
		}
		settingsCache.Invalidate()

		if !setFlash(httpHelper, httpSession, w, r, flash, "true") {
			return
		}
		http.Redirect(w, r, fmt.Sprintf("%v/admin/legal-documents/%v/versions", baseURL, detail.LegalDocument.Id), http.StatusFound)
	}
}
