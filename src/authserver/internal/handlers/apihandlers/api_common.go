package apihandlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/leodip/goiabada/core/api"
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
	resp := api.ErrorResponse{
		ErrorCode:        code,
		ErrorDescription: message,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
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
