package apihandlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/customerrors"
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

// writeValidationError extracts the description from a *customerrors.ErrorDetail
// (or err.Error() for any other error) and emits a 400 Bad Request envelope.
func writeValidationError(w http.ResponseWriter, err error) {
	if valErr, ok := err.(*customerrors.ErrorDetail); ok {
		writeJSONError(w, valErr.GetDescription(), "VALIDATION_ERROR", http.StatusBadRequest)
	} else {
		writeJSONError(w, err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
	}
}
