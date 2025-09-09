package apihandlers

import (
    "encoding/json"
    "net/http"
    "strings"

    "github.com/leodip/goiabada/authserver/internal/handlers"
    "github.com/leodip/goiabada/authserver/internal/middleware"
    "github.com/leodip/goiabada/core/api"
    "github.com/leodip/goiabada/core/constants"
    "github.com/leodip/goiabada/core/data"
    "github.com/leodip/goiabada/core/inputsanitizer"
    "github.com/leodip/goiabada/core/validators"
)

// HandleAPIAccountAddressPut - PUT /api/v1/account/address
func HandleAPIAccountAddressPut(
    httpHelper handlers.HttpHelper,
    database data.Database,
    addressValidator *validators.AddressValidator,
    inputSanitizer *inputsanitizer.InputSanitizer,
    auditLogger handlers.AuditLogger,
) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Auth and scope are enforced by middleware; extract validated token
        jwtToken, ok := middleware.GetValidatedToken(r)
        if !ok {
            writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
            return
        }

        subject := jwtToken.GetStringClaim("sub")
        if strings.TrimSpace(subject) == "" {
            writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
            return
        }

        // Parse request body
        var req api.UpdateUserAddressRequest
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
            return
        }

        // Load current user
        user, err := database.GetUserBySubject(nil, subject)
        if err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }
        if user == nil {
            writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
            return
        }

        // Validate address input
        input := &validators.ValidateAddressInput{
            AddressLine1:      strings.TrimSpace(req.AddressLine1),
            AddressLine2:      strings.TrimSpace(req.AddressLine2),
            AddressLocality:   strings.TrimSpace(req.AddressLocality),
            AddressRegion:     strings.TrimSpace(req.AddressRegion),
            AddressPostalCode: strings.TrimSpace(req.AddressPostalCode),
            AddressCountry:    strings.TrimSpace(req.AddressCountry),
        }
        if err := addressValidator.ValidateAddress(input); err != nil {
            writeValidationError(w, err)
            return
        }

        // Apply sanitized updates
        user.AddressLine1 = inputSanitizer.Sanitize(input.AddressLine1)
        user.AddressLine2 = inputSanitizer.Sanitize(input.AddressLine2)
        user.AddressLocality = inputSanitizer.Sanitize(input.AddressLocality)
        user.AddressRegion = inputSanitizer.Sanitize(input.AddressRegion)
        user.AddressPostalCode = inputSanitizer.Sanitize(input.AddressPostalCode)
        user.AddressCountry = inputSanitizer.Sanitize(input.AddressCountry)

        if err := database.UpdateUser(nil, user); err != nil {
            writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
            return
        }

        // Audit (self-service)
        auditLogger.Log(constants.AuditUpdatedOwnAddress, map[string]interface{}{
            "userId":       user.Id,
            "loggedInUser": subject,
        })

        // Response
        resp := api.UpdateUserResponse{User: *api.ToUserResponse(user)}
        w.Header().Set("Content-Type", "application/json")
        if err := json.NewEncoder(w).Encode(resp); err != nil {
            writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
            return
        }
    }
}

