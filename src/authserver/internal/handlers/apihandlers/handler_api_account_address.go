package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
)

// accountAddressDatabase is what the account address endpoints need: the caller's own user row,
// and the narrow write of its address columns.
type accountAddressDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	SetUserAddress(ctx context.Context, tx *sql.Tx, user *record.User) error
}

// HandleAccountAddressPut - PUT /api/v1/account/address
func HandleAccountAddressPut(
	database accountAddressDatabase,
	addressValidator *accountvalidation.AddressValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, subject, ok := accountCaller(w, r)
		if !ok {
			return
		}

		// Parse request body
		var req api.UpdateUserAddressRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Load current user
		user, err := database.GetUserBySubject(r.Context(), nil, subject)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate address input
		input := &accountvalidation.ValidateAddressInput{
			AddressLine1:      strings.TrimSpace(req.AddressLine1),
			AddressLine2:      strings.TrimSpace(req.AddressLine2),
			AddressLocality:   strings.TrimSpace(req.AddressLocality),
			AddressRegion:     strings.TrimSpace(req.AddressRegion),
			AddressPostalCode: strings.TrimSpace(req.AddressPostalCode),
			AddressCountry:    strings.TrimSpace(req.AddressCountry),
		}
		if err := addressValidator.ValidateAddress(input); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Apply sanitized updates
		user.AddressLine1 = input.AddressLine1
		user.AddressLine2 = input.AddressLine2
		user.AddressLocality = input.AddressLocality
		user.AddressRegion = input.AddressRegion
		user.AddressPostalCode = input.AddressPostalCode
		user.AddressCountry = input.AddressCountry

		// Only the address columns: writing back the row read above would undo a disable, a
		// password change or an OTP change made since (#471).
		if err := database.SetUserAddress(r.Context(), nil, user); err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Audit (self-service)
		auditLogger.Log(r.Context(), audit.EventUpdatedOwnAddress, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": subject,
		})

		// Response
		resp := api.UpdateUserResponse{User: *apimapping.ToUserResponse(user)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}
