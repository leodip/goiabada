package apihandlers

import (
	"encoding/json"
	"net/http"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/customerrors"
)


// Helper functions
func writeJSONError(w http.ResponseWriter, message, code string, statusCode int) {
	errorResp := api.ErrorResponse{
		Error: struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		}{
			Message: message,
			Code:    code,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResp)
}

func writeValidationError(w http.ResponseWriter, err error) {
	if valErr, ok := err.(*customerrors.ErrorDetail); ok {
		writeJSONError(w, valErr.GetDescription(), "VALIDATION_ERROR", http.StatusBadRequest)
	} else {
		writeJSONError(w, err.Error(), "VALIDATION_ERROR", http.StatusBadRequest)
	}
}