package adminuserhandlers

import (
	"net/http"
	"net/url"

	"github.com/leodip/goiabada/adminconsole/internal/config"
)

// withListPosition is where a user page sends the browser after a save: path under the console's
// base URL, carrying the page and the search of the user list it was reached from, so the list
// reopens where the administrator left it. Each value is escaped through url.Values. Pasted in raw,
// a search term carrying & or # cut the query short or became a fragment, and the page it returned
// to searched for something else (#426).
func withListPosition(path string, r *http.Request) string {
	position := url.Values{
		"page":  {r.URL.Query().Get("page")},
		"query": {r.URL.Query().Get("query")},
	}
	return config.GetAdminConsole().BaseURL + path + "?" + position.Encode()
}
