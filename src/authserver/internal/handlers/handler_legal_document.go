package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/legalmarkdown"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// legalDocumentPageDatabase is what a legal document's public page needs: the document its short
// name names, and its versions.
type legalDocumentPageDatabase interface {
	GetLegalDocumentByShortName(ctx context.Context, tx *sql.Tx, shortName string) (*record.LegalDocument, error)
	GetLegalDocumentVersionsByLegalDocumentId(ctx context.Context, tx *sql.Tx, legalDocumentId int64) ([]record.LegalDocumentVersion, error)
}

// legalDocumentVersionLink is one version the page lists.
type legalDocumentVersionLink struct {
	Number int
}

// HandleLegalDocumentGet answers a legal document's public pages, which need no sign-in (#622
// decision 5): GET /legal/{shortName} shows its current version, and GET
// /legal/{shortName}/versions/{version} the version numbered so, each with its number and publish
// date and a link to every version. Drafts are never public. A document never published, a retired
// one, and a version the document does not have, all answer the not-found page, as an unknown short
// name does. A version is written in its canonical decimal form: versions/01 names no page, so a
// version has one address.
func HandleLegalDocumentGet(pageRenderer PageRenderer, database legalDocumentPageDatabase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc, err := database.GetLegalDocumentByShortName(r.Context(), nil, r.PathValue("shortName"))
		if err != nil {
			pageRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to read the legal document"))
			return
		}
		if doc == nil || doc.IsRetired() {
			pageRenderer.NotFound(w, r)
			return
		}
		versions, err := database.GetLegalDocumentVersionsByLegalDocumentId(r.Context(), nil, doc.Id)
		if err != nil {
			pageRenderer.InternalServerError(w, r, errs.Wrap(err, "unable to read the legal document's versions"))
			return
		}
		if len(versions) == 0 {
			pageRenderer.NotFound(w, r)
			return
		}
		current := versions[len(versions)-1]

		shown := &current
		if requested := r.PathValue("version"); requested != "" {
			shown = nil
			number, parseErr := strconv.Atoi(requested)
			if parseErr == nil && strconv.Itoa(number) == requested {
				for i := range versions {
					if versions[i].VersionNumber == number {
						shown = &versions[i]
					}
				}
			}
			if shown == nil {
				pageRenderer.NotFound(w, r)
				return
			}
		}

		documentHTML, err := legalmarkdown.Render(shown.Markdown)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		links := make([]legalDocumentVersionLink, len(versions))
		for i, v := range versions {
			links[i] = legalDocumentVersionLink{Number: v.VersionNumber}
		}

		bind := map[string]interface{}{
			"shortName":            doc.ShortName,
			"documentTitle":        shown.Title,
			"documentHTML":         documentHTML,
			"versionNumber":        shown.VersionNumber,
			"publishedAt":          shown.PublishedAt.UTC().Format("2006-01-02"),
			"isCurrent":            shown.VersionNumber == current.VersionNumber,
			"currentVersionNumber": current.VersionNumber,
			"versions":             links,
			"layoutWide":           true,
		}
		if err := pageRenderer.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/legal_document.html", bind); err != nil {
			pageRenderer.InternalServerError(w, r, err)
		}
	}
}
