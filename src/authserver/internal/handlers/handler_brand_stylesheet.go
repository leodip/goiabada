package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// brandStylesheetDatabase is what a brand's stylesheet needs: the brand.
type brandStylesheetDatabase interface {
	GetBrandById(ctx context.Context, tx *sql.Tx, brandId int64) (*record.Brand, error)
}

const (
	// brandStylesheetCurrentCache is the answer to a request naming the stylesheet as it is now:
	// its URL changes whenever its contents do, so a browser may keep it for a year without asking
	// again (#810 decision 7).
	brandStylesheetCurrentCache = "public, max-age=31536000, immutable"
	// brandStylesheetOtherCache is the answer to any other request, a stale fingerprint, a
	// malformed one or none: the current stylesheet, kept five minutes as a static file is, so a
	// URL never holds for a year what it does not name.
	brandStylesheetOtherCache = "public, max-age=300"
)

// HandleBrandStylesheetGet answers a brand's full stylesheet, at brandthemes.StylesheetRoute, to
// anyone, as a static file is answered: the colors of the brand's theme, or none for Blueberry,
// whose are main.css's, and its corners and font (#813 decision 9). The auth server's pages and the
// admin console's end-user pages link it. A brand that does not exist is not found.
func HandleBrandStylesheetGet(pageRenderer PageRenderer, database brandStylesheetDatabase) http.HandlerFunc {
	return serveBrandStylesheet(pageRenderer, database, brandthemes.FullStylesheet)
}

// HandleBrandColorsStylesheetGet answers a brand's colors-only stylesheet, at
// brandthemes.ColorsStylesheetRoute, as HandleBrandStylesheetGet answers the full one: the colors of
// the brand's theme and nothing of its kit, which the admin console's admin pages link, so they
// never receive the kit (#813 decision 9).
func HandleBrandColorsStylesheetGet(pageRenderer PageRenderer, database brandStylesheetDatabase) http.HandlerFunc {
	return serveBrandStylesheet(pageRenderer, database, brandthemes.ColorsStylesheet)
}

// serveBrandStylesheet answers the stylesheet stylesheetOf builds for the brand the path names,
// kept for a year when the request names its current fingerprint and five minutes otherwise.
func serveBrandStylesheet(pageRenderer PageRenderer, database brandStylesheetDatabase,
	stylesheetOf func(*record.Brand) (brandthemes.Stylesheet, error)) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		brandId, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || brandId <= 0 {
			http.NotFound(w, r)
			return
		}

		brand, err := database.GetBrandById(r.Context(), nil, brandId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if brand == nil {
			http.NotFound(w, r)
			return
		}

		stylesheet, err := stylesheetOf(brand)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		cache := brandStylesheetOtherCache
		if fingerprints := r.URL.Query()["v"]; len(fingerprints) == 1 && fingerprints[0] == stylesheet.Fingerprint {
			cache = brandStylesheetCurrentCache
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", cache)
		w.Header().Set("Content-Length", strconv.Itoa(len(stylesheet.CSS)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(stylesheet.CSS))
	}
}
