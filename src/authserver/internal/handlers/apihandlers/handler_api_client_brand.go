package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// clientBrandDatabase is what the client's brand assignment reads and writes: the client and what
// its answer loads, what the target ceiling reads, the brand it names, and the column's writer with
// the transaction its lock is held in.
type clientBrandDatabase interface {
	clientTargetPolicyDatabase
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error)
	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error
	ClientLoadPostLogoutRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error
	ClientLoadWebOrigins(ctx context.Context, tx *sql.Tx, client *record.Client) error
	GetBrandById(ctx context.Context, tx *sql.Tx, brandId int64) (*record.Brand, error)
	SetClientBrand(ctx context.Context, tx *sql.Tx, clientId int64, brandId sql.NullInt64) (bool, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// HandleClientBrandPut - PUT /api/v1/admin/clients/{id}/brand
//
// Gives a client a brand of its own, or with a null brandId puts it back on the default brand, and
// answers the client as stored (#812 decision 2). brandId is required: a body without it is
// refused rather than read as null, so a body that says nothing cannot reset the brand. A brandId
// that names no brand, also one deleted meanwhile, is refused as a validation error.
//
// The route takes the scopes of the client's other settings, and the administrator-client ceiling
// applies as on every client write, before anything is written. SetClientBrand takes the settings
// row's lock and reads the brand under it, as a brand's deletion does, so it is the transaction's
// first read (decision 1). An assignment that changed the brand is recorded as
// updated_client_brand once it has committed; one that changed nothing records none.
func HandleClientBrandPut(
	database clientBrandDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for brand update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// The body is read as a raw object first, to tell a brandId sent as null from one not sent.
		var fields map[string]json.RawMessage
		if decodeErr := json.NewDecoder(r.Body).Decode(&fields); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		rawBrandId, sent := fields["brandId"]
		if !sent {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientBrandIdRequired, nil))
			return
		}
		var req api.UpdateClientBrandRequest
		if decodeErr := json.Unmarshal(rawBrandId, &req.BrandId); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		var brandId sql.NullInt64
		if req.BrandId != nil {
			brandId = sql.NullInt64{Int64: *req.BrandId, Valid: true}
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		var changed bool
		var brand *record.Brand
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			changed, brand = false, nil
			var setErr error
			changed, setErr = database.SetClientBrand(r.Context(), tx, client.Id, brandId)
			if setErr != nil {
				return setErr
			}
			if changed && brandId.Valid {
				// Read under the lock SetClientBrand took, so it is the brand just given.
				brand, setErr = database.GetBrandById(r.Context(), tx, brandId.Int64)
				if setErr != nil {
					return errs.Wrap(setErr, "database error getting the brand given to the client")
				}
				if brand == nil {
					return errs.WithStack(data.ErrBrandNotFound)
				}
			}
			return nil
		})
		switch {
		case errors.Is(err, data.ErrBrandNotFound):
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientBrandNotFound, nil))
			return
		case err != nil:
			writeInternalServerError(w, r, errs.Wrap(err, "database error updating client brand"), "client_id", client.Id)
			return
		}

		// The change has committed: it is recorded now, before the reads building the answer, whose
		// failure answers 500 but does not undo it. Back on the default, the brand is left out.
		if changed {
			details := map[string]interface{}{
				"client_id":         client.Id,
				"client_identifier": client.ClientIdentifier,
				"logged_in_user":    callerSubject(r),
			}
			if brand != nil {
				details["brand_id"] = brand.Id
				details["brand_name"] = brand.Name
			}
			auditLogger.Log(r.Context(), audit.EventUpdatedClientBrand, details)
		}

		// The answer is the row as stored, read back after the write.
		client, err = database.GetClientById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client after brand update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		if err = database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after brand update"), "client_id", client.Id)
			return
		}
		if err = database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after brand update"), "client_id", client.Id)
			return
		}
		if err = database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after brand update"), "client_id", client.Id)
			return
		}

		writeJSON(w, r, http.StatusOK, api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)})
	}
}
