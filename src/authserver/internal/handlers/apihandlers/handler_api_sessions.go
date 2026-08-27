package apihandlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/pkg/errors"
)

// The browser session endpoint: the network transport of sessionstore.Backend, for the
// admin console (#266).
//
// The admin console has no database connection of its own and is meant to keep it that
// way, so its browser sessions live in a row on the auth server's side of the wire and it
// reaches them through here. What crosses is ciphertext the admin console encrypted with
// its own session keys, so the auth server stores bytes it holds no key for: a dump of
// this database yields no administrator token, which is the invariant the auth server
// already has and this endpoint must not spend.
//
// Five operations, one per Backend method. Create and Update are separate because Update
// must never insert: a session that is gone was most likely removed by a request rotating
// the identifier, and re-creating its row would undo that rotation from a request still in
// flight under the old identifier. Collapsing them here would put that distinction on a
// boolean and let a caller get it wrong.
//
// Each handler writes its own statuses rather than delegating them to a shared helper.
// That is deliberate and it is not repetition for its own sake: openapi_contract_lint_test
// reads a handler's failure surface out of the http.Status constants its own body names,
// so a status written from inside a helper is invisible to the scan and openapi.yaml could
// drift under it with every test still passing. It also makes each operation's surface
// exact, which is why create declares no 404 and delete declares no 404 either.

// maxSessionRequestBytes bounds a request body. The largest real payload is an admin
// console session holding a full token set, which measures about 13 KB of ciphertext, and
// the chunked cookie store this replaces advertised a ~190 KB ceiling; a megabyte is five
// times that, so nothing a deployment can legitimately produce reaches it. What it buys is
// that the JSON decode below has a bound at all: the caller is authenticated, but an
// authenticated caller is still not a reason to read an arbitrary number of bytes into
// memory. This is this endpoint's own hygiene and not the deployment-wide request limits
// tracked in #205.
const maxSessionRequestBytes = 1 << 20

// adminConsoleSessions is the only place in this package that names an owner.
//
// The owner is what keeps the two applications' sessions apart in a table that holds
// both, so it is fixed here rather than taken from the request: no exported signature in
// this package accepts one, which is what makes "the admin console cannot reach an auth
// server session" a property of the code's shape instead of a check somebody has to
// remember to write. The identifier is hashed inside the backend, so a caller sends a
// handle and can never present a digest it did not derive from one.
//
// The owner value is the logical session name, which is the same string the store signs
// its cookies under and does not vary with the deployment's scheme; only the physical
// cookie name gains a prefix on https.
func adminConsoleSessions(database data.Database) sessionstore.Backend {
	return sessionstore.NewDatabaseBackend(database, constants.AdminConsoleSessionName)
}

// readSessionRequest decodes a bounded JSON body and checks the identifier is present. It
// reports whether the request is usable; the caller writes the 400, so the status stays
// visible in the handler that can answer it.
func readSessionRequest(r *http.Request, w http.ResponseWriter, target interface{}, id func() string) (message, code string, ok bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSessionRequestBytes)

	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		return "Invalid request body", "INVALID_REQUEST_BODY", false
	}
	if strings.TrimSpace(id()) == "" {
		return "Session id is required", "SESSION_ID_REQUIRED", false
	}
	return "", "", true
}

func writeSessionJSON(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// HandleAPISessionLoadPost - POST /api/v1/sessions/load
//
// 404 covers three things the caller must treat alike: no such session, one that was
// logged out or reaped, and one that has expired. The last needs no test here, because the
// read underneath matches only rows whose deadline is still ahead, so an expired row is
// already absent by the time an answer is chosen.
//
// 404 and 500 stay distinct, and that is the whole reason this handler does not simply
// answer "no session" on any failure: 404 means the session is gone, which the caller
// turns into a fresh session, while 500 means the lookup could not be performed, which is
// a refused request. Flattening them would sign every administrator out during a database
// interruption and leave nothing to diagnose it by.
func HandleAPISessionLoadPost(database data.Database) http.HandlerFunc {
	backend := adminConsoleSessions(database)

	return func(w http.ResponseWriter, r *http.Request) {
		var req api.SessionLoadRequest
		if message, code, ok := readSessionRequest(r, w, &req, func() string { return req.Id }); !ok {
			writeJSONError(w, message, code, http.StatusBadRequest)
			return
		}

		record, err := backend.Load(r.Context(), req.Id)
		if err != nil {
			if errors.Is(err, sessionstore.ErrNotFound) {
				writeJSONError(w, "Session not found", "SESSION_NOT_FOUND", http.StatusNotFound)
				return
			}
			slog.Error("failed to load a browser session", "error", err)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		writeSessionJSON(w, api.SessionLoadResponse{
			Data:         string(record.Data),
			LastAccessed: record.LastAccessed,
			ExpiresAt:    record.ExpiresAt,
		})
	}
}

// HandleAPISessionCreatePost - POST /api/v1/sessions/create
//
// No 404: creating names no existing session, so there is nothing here that can be absent.
func HandleAPISessionCreatePost(database data.Database) http.HandlerFunc {
	backend := adminConsoleSessions(database)

	return func(w http.ResponseWriter, r *http.Request) {
		var req api.SessionWriteRequest
		if message, code, ok := readSessionRequest(r, w, &req, func() string { return req.Id }); !ok {
			writeJSONError(w, message, code, http.StatusBadRequest)
			return
		}

		expiresAt, err := backend.Create(r.Context(), req.Id, []byte(req.Data), req.Authenticated)
		if err != nil {
			slog.Error("failed to create a browser session", "error", err)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		writeSessionJSON(w, api.SessionWriteResponse{ExpiresAt: expiresAt})
	}
}

// HandleAPISessionUpdatePost - POST /api/v1/sessions/update
//
// Never inserts. A 404 here means the session is gone, and the caller's store is written
// to fail the save rather than put it back, because the request that removed it was most
// likely rotating the identifier.
func HandleAPISessionUpdatePost(database data.Database) http.HandlerFunc {
	backend := adminConsoleSessions(database)

	return func(w http.ResponseWriter, r *http.Request) {
		var req api.SessionWriteRequest
		if message, code, ok := readSessionRequest(r, w, &req, func() string { return req.Id }); !ok {
			writeJSONError(w, message, code, http.StatusBadRequest)
			return
		}

		expiresAt, err := backend.Update(r.Context(), req.Id, []byte(req.Data), req.Authenticated)
		if err != nil {
			if errors.Is(err, sessionstore.ErrNotFound) {
				writeJSONError(w, "Session not found", "SESSION_NOT_FOUND", http.StatusNotFound)
				return
			}
			slog.Error("failed to update a browser session", "error", err)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		writeSessionJSON(w, api.SessionWriteResponse{ExpiresAt: expiresAt})
	}
}

// HandleAPISessionTouchPost - POST /api/v1/sessions/touch
//
// It moves the deadline as well as the last-accessed stamp, because the idle window is
// expressed in the deadline: a touch that left it alone would never extend the session and
// the idle timeout would behave as an absolute one.
func HandleAPISessionTouchPost(database data.Database) http.HandlerFunc {
	backend := adminConsoleSessions(database)

	return func(w http.ResponseWriter, r *http.Request) {
		var req api.SessionTouchRequest
		if message, code, ok := readSessionRequest(r, w, &req, func() string { return req.Id }); !ok {
			writeJSONError(w, message, code, http.StatusBadRequest)
			return
		}

		expiresAt, err := backend.Touch(r.Context(), req.Id, req.Authenticated)
		if err != nil {
			if errors.Is(err, sessionstore.ErrNotFound) {
				writeJSONError(w, "Session not found", "SESSION_NOT_FOUND", http.StatusNotFound)
				return
			}
			slog.Error("failed to touch a browser session", "error", err)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		writeSessionJSON(w, api.SessionWriteResponse{ExpiresAt: expiresAt})
	}
}

// HandleAPISessionDeletePost - POST /api/v1/sessions/delete
//
// 204 whether or not a row was there, so no 404. Deleting a session that is already gone
// is the outcome the caller asked for, and answering 404 would make a logout that raced a
// reap look like a failure.
func HandleAPISessionDeletePost(database data.Database) http.HandlerFunc {
	backend := adminConsoleSessions(database)

	return func(w http.ResponseWriter, r *http.Request) {
		var req api.SessionLoadRequest
		if message, code, ok := readSessionRequest(r, w, &req, func() string { return req.Id }); !ok {
			writeJSONError(w, message, code, http.StatusBadRequest)
			return
		}

		if err := backend.Delete(r.Context(), req.Id); err != nil {
			slog.Error("failed to delete a browser session", "error", err)
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
