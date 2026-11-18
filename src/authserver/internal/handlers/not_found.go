package handlers

import "net/http"

// ResourceNotFound answers net/http's plain-text 404 for a public resource answered outside the
// page branch, a client logo, a profile picture, a brand's stylesheet or asset, or a static file,
// with Cache-Control: no-store and Pragma: no-cache, the pair the server's other no-store answers
// send. A 404 is heuristically cacheable (RFC 9110 section 15.5.5), and a cache may keep one that
// names no lifetime as long as it chooses (RFC 9111 section 4.2.2), so without it a "not found"
// could outlive the upload of the resource. Outside pages only the resource itself may be cached
// (#825 decision 3).
func ResourceNotFound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.NotFound(w, r)
}
