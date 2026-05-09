package apihandlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/i18n"
)

// writeJSONError emits the admin/account API error envelope with the
// caller-supplied UPPER_SNAKE code and English message. Consumers route
// on the HTTP status code, not on the body, so this helper is the only
// thing every callsite needs.
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
func writeValidationError(w http.ResponseWriter, r *http.Request, err error) {
	switch e := err.(type) {
	case *i18n.LocalizedError:
		writeJSONError(w, e.Localize(r.Context()), e.Code, http.StatusBadRequest)
	case *customerrors.ErrorDetail:
		writeJSONError(w, e.GetDescription(), "VALIDATION_ERROR", http.StatusBadRequest)
	default:
		writeJSONError(w, err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
	}
}
