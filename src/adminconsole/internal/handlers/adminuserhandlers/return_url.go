package adminuserhandlers

import (
	"net/http"
	"net/url"
)

// withListPosition is where a user page sends the browser after a save: path under baseURL, the
// console's base URL the handler was built with (#441), carrying the page and the search of the
// user list it was reached from, so the list reopens where the administrator left it. Each value
// is escaped through url.Values. Pasted in raw, a search term carrying & or # cut the query short
// or became a fragment, and the page it returned to searched for something else (#426).
func withListPosition(baseURL, path string, r *http.Request) string {
	position := url.Values{
		"page":  {r.URL.Query().Get("page")},
		"query": {r.URL.Query().Get("query")},
	}
	return baseURL + path + "?" + position.Encode()
}
