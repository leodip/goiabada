package apihandlers

import (
	"errors"
	"net/http"

	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/i18n"
)

// writeJSONError emits the admin/account API error envelope with the
// caller-supplied UPPER_SNAKE code and English message. Consumers route
// on the HTTP status code, not on the body, so this helper is the only
// thing every callsite needs.
//
// i18n surface: C — admin/account API. Callers pass already-localized
// text (when relevant) or a stable English message for non-localized
// codes. writeValidationError is the localizing wrapper.
func writeJSONError(w http.ResponseWriter, message, code string, statusCode int) {
	apiresponse.WriteError(w, message, code, statusCode)
}

// writeJSON is the one JSON writer on this surface: it buffers the encode before the header, so a
// failure answers a real 500 instead of a superfluous WriteHeader on a body already half on the
// wire (#279 decision 8).
func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	apiresponse.WriteJSON(w, r, status, v)
}

// writeInternalServerError is the one 500 on this surface: one structured log record with the
// stack, the request id and the caller's own attributes, and one envelope naming
// INTERNAL_SERVER_ERROR and that request id. It replaced seven per-site codes, of which 194 sites
// logged nothing at all (#279 decision 7).
func writeInternalServerError(w http.ResponseWriter, r *http.Request, err error, attrs ...any) {
	apiresponse.WriteInternalServerError(w, r, err, attrs...)
}

// writeValidationError emits a 400 Bad Request envelope from a validation
// error. For *i18n.LocalizedError (the canonical UI/API path), error_code
// is the catalog key and error_description is the message localized to
// the request's locale. For legacy *customerrors.ErrorDetail, the code is
// the constant "VALIDATION_ERROR" and the description is the English text
// already on the error. Consumers route on the HTTP status code.
//
// i18n surface: C — admin/account API.
//
// Two errors.As tests rather than a type switch, in the switch's own order, so a validator's error
// keeps its code and its localized text after anything on the way up has wrapped it. A type switch
// reads only the outermost value, so a single wrap sent the whole thing to the default arm, where
// the code flattens to VALIDATION_ERROR and the description becomes the wrapped Error() string
// with the wrapper's prefix on it (#279 decision 6).
func writeValidationError(w http.ResponseWriter, r *http.Request, err error) {
	var localizedErr *i18n.LocalizedError
	if errors.As(err, &localizedErr) {
		writeJSONError(w, localizedErr.Localize(r.Context()), localizedErr.Code, http.StatusBadRequest)
		return
	}
	var errorDetail *customerrors.ErrorDetail
	if errors.As(err, &errorDetail) {
		writeJSONError(w, errorDetail.GetDescription(), "VALIDATION_ERROR", http.StatusBadRequest)
		return
	}
	writeJSONError(w, err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
}
