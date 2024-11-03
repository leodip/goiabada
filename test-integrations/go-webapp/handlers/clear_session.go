package handlers

import (
	"net/http"

	"github.com/gorilla/sessions"
)

func ClearSessionHandler(store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the current session
		session, err := store.Get(r, "auth-session")
		if err != nil {
			http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Clear all values in the session
		session.Values = make(map[interface{}]interface{})

		// Set MaxAge to -1 to delete the cookie
		session.Options.MaxAge = -1

		// Save the session (this will delete it)
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Failed to clear session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect back to the index page
		http.Redirect(w, r, "/", http.StatusFound)
	}
}
