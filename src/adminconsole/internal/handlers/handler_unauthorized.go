package handlers

import (
	"net/http"
)

// HandleUnauthorizedGet is the page RequiresScope sends a signed-in administrator to when their
// grant lacks the scope a page requires.
//
// 403, not 401 (#427 decision 18). RFC 9110 section 15.5.2: a 401 means the request "lacks valid
// authentication credentials", and "The server generating a 401 response MUST send a
// WWW-Authenticate header field"; the console signs in with a cookie and has no challenge to send.
// Section 15.5.4: with 403, "If authentication credentials were provided in the request, the server
// considers them insufficient to grant access", which is this page's whole case.
func HandleUnauthorizedGet(
	httpHelper HttpHelper,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{
			"_httpStatus": http.StatusForbidden,
		}

		err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/unauthorized.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
