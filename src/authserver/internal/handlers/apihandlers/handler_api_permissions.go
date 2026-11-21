package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// permissionsDatabase is what the permission endpoints need: the resource that owns a permission
// and the permission rows under it.
type permissionsDatabase interface {
	CreatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error
	DeletePermission(ctx context.Context, tx *sql.Tx, permissionID int64) error
	GetPermissionsByResourceID(ctx context.Context, tx *sql.Tx, resourceID int64) ([]record.Permission, error)
	GetResourceByID(ctx context.Context, tx *sql.Tx, resourceID int64) (*record.Resource, error)
	PermissionsLoadResources(ctx context.Context, tx *sql.Tx, permissions []record.Permission) error
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UpdatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error
}

func HandlePermissionsByResourceGet(
	database permissionsDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resourceIDStr := r.PathValue("resourceId")
		if len(resourceIDStr) == 0 {
			writeJSONError(w, "Resource ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		resourceID, err := strconv.ParseInt(resourceIDStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid resource ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		permissions, err := database.GetPermissionsByResourceID(r.Context(), nil, resourceID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting permissions"), "resource_id", resourceID)
			return
		}

		// Ensure permissions is never nil
		if permissions == nil {
			permissions = []record.Permission{}
		}

		// Load resource information for each permission if we have any
		if len(permissions) > 0 {
			err = database.PermissionsLoadResources(r.Context(), nil, permissions)
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}
		}

		response := api.GetPermissionsByResourceResponse{
			Permissions: apimapping.ToPermissionResponses(permissions),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleResourcePermissionsPut - PUT /api/v1/admin/resources/{resourceId}/permissions
// Replaces the full set of permission definitions for a resource.
func HandleResourcePermissionsPut(
	database permissionsDatabase,
	identifierValidator *inputvalidation.IdentifierValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resourceIDStr := r.PathValue("resourceId")
		if len(resourceIDStr) == 0 {
			writeJSONError(w, "Resource ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		resourceID, err := strconv.ParseInt(resourceIDStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid resource ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		resource, err := database.GetResourceByID(r.Context(), nil, resourceID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting resource by ID for permissions update"), "resource_id", resourceID)
			return
		}
		if resource == nil {
			writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var req api.UpdateResourcePermissionsRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// The list as the caller loaded it, required as it is on every list save: absent or null
		// decodes to nil and is refused, [] means the caller read no permissions (#428).
		if req.ExpectedPermissions == nil {
			writeJSONError(w, "expectedPermissions is required: send the resource's permissions as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Deduplicate identifiers and validate entries
		seenIdentifiers := map[string]bool{}
		seenIDs := map[int64]bool{}
		for i := range req.Permissions {
			// Reject duplicate IDs (prevents bypass of built-in permission protection)
			if req.Permissions[i].ID > 0 {
				if seenIDs[req.Permissions[i].ID] {
					writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodePermissionDuplicateIDs, nil))
					return
				}
				seenIDs[req.Permissions[i].ID] = true
			}

			// Trim inputs
			rawIdentifier := strings.TrimSpace(req.Permissions[i].PermissionIdentifier)
			rawDescription := strings.TrimSpace(req.Permissions[i].Description)

			// Explicitly forbid HTML angle brackets in description
			if validateNoAngleBracketsErr := accountvalidation.ValidateNoAngleBrackets(rawDescription,
				i18n.ErrCodeAdminResourcePermissionsDescriptionHTMLNotAllowed); validateNoAngleBracketsErr != nil {
				writeValidationError(w, r, validateNoAngleBracketsErr)
				return
			}

			// The identifier is validated as it was sent, trimmed and nothing else. It used to be
			// run through the HTML sanitizer first, which meant "valid<b" was stored as "valid":
			// the sanitizer dropped everything from the "<" onwards and IdentifierValidator.Validate then
			// saw a name the caller never asked for. It is now refused instead (#275).
			if len(rawIdentifier) == 0 {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodePermissionIdentifierRequired, nil))
				return
			}

			if validateIdentifierErr := identifierValidator.Validate(rawIdentifier, true); validateIdentifierErr != nil {
				writeValidationError(w, r, validateIdentifierErr)
				return
			}

			const maxLengthDescription = 100
			if inputvalidation.TextLength(rawDescription) > maxLengthDescription {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeAdminResourcePermissionsDescriptionTooLong, map[string]any{"max": maxLengthDescription}))
				return
			}

			if seenIdentifiers[rawIdentifier] {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodePermissionDuplicated, map[string]any{"identifier": rawIdentifier}))
				return
			}
			seenIdentifiers[rawIdentifier] = true

			// Persist the trimmed values back on request for subsequent operations
			req.Permissions[i].PermissionIdentifier = rawIdentifier
			req.Permissions[i].Description = rawDescription
		}

		// The stored rows the checks below refuse against, read before the transaction: every
		// refusal is decided before it opens, and the transaction reads them again for its plan.
		existing, err := database.GetPermissionsByResourceID(r.Context(), nil, resource.ID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting existing permissions"), "resource_id", resource.ID)
			return
		}

		// Build a map for uniqueness checks
		existingByID := map[int64]record.Permission{}
		existingByIdentifier := map[string]record.Permission{}
		for _, p := range existing {
			existingByID[p.ID] = p
			existingByIdentifier[p.PermissionIdentifier] = p
		}

		// System-level resource protection: validate built-in permissions for the authserver resource
		if resource.ResourceIdentifier == builtin.AuthServerResourceIdentifier {
			for _, builtInIdentifier := range builtin.AuthServerPermissionIdentifiers() {
				// Check if the built-in permission exists in the database
				existingPerm, found := existingByIdentifier[builtInIdentifier]
				if !found {
					writeInternalServerError(w, r,
						errs.Errorf("built-in permission %q is missing from the system resource; the database may be corrupted or mis-seeded", builtInIdentifier),
						"built_in_identifier", builtInIdentifier, "resource_id", resource.ID)
					return
				}

				// The request must include an entry with the same DB row ID
				var requestEntry *api.ResourcePermissionUpsert
				for i := range req.Permissions {
					if req.Permissions[i].ID == existingPerm.ID {
						requestEntry = &req.Permissions[i]
						break
					}
				}

				if requestEntry == nil {
					writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodePermissionBuiltInDeleted, map[string]any{"identifier": builtInIdentifier}))
					return
				}

				// The identifier must not be changed
				if requestEntry.PermissionIdentifier != builtInIdentifier {
					writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodePermissionBuiltInRenamed, map[string]any{"identifier": builtInIdentifier}))
					return
				}

				// A description change is the policy's to judge, below, after the save's own answers.
			}
		}

		// An entry naming a stored row must name one of this resource's, and an identifier may not be
		// one a different stored row holds, whether or not that row is renamed or dropped by the same
		// save: a rename onto it, a swap of two identifiers, or a new permission reusing it is
		// refused. That is the rule the update and create loops this replaced applied through a map
		// they added to and never cleared, restated as what it was. It also keeps every write below
		// clear of the unique index on (permission_identifier, resource_id) for the rows as read
		// here, so the index is met only by another save racing this one, and answered 409 (#428).
		for _, p := range req.Permissions {
			if p.ID > 0 {
				if _, ok := existingByID[p.ID]; !ok {
					writeJSONError(w, "Permission not found", "NOT_FOUND", http.StatusNotFound)
					return
				}
			}
			if other, exists := existingByIdentifier[p.PermissionIdentifier]; exists && other.ID != p.ID {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodePermissionIdentifierInUse, map[string]any{"identifier": p.PermissionIdentifier}))
				return
			}
		}

		// Only authserver:manage rewrites what an administrative permission says it confers (#402).
		if !permissionDescriptionCeilingAllows(w, r, auditLogger, resource, existing, req.Permissions, req.ExpectedPermissions) {
			return
		}

		// One transaction, so a failure part way through commits nothing and the 500 is true, where
		// the autocommitted writes this replaced left the renames and creations before a failure in
		// place under the 500 (#406). No row lock, as for every list save. The stored rows are read
		// again on the transaction and compared with the list the caller loaded, entry by entry as
		// stored, so a save from an outdated page is refused 409 rather than undo another save's
		// rename, description or new permission. Opened through RunInTransaction, so a deadlock
		// victim is rerun whole (#301); the plan is recomputed from each attempt's read and nothing
		// is written to the response inside (#428).
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			stored, loadErr := database.GetPermissionsByResourceID(r.Context(), tx, resource.ID)
			if loadErr != nil {
				return errs.Wrap(loadErr, "database error loading resource permissions before update")
			}
			if !sameSet(stored, permissionEntryOf, req.ExpectedPermissions) {
				return errListChanged
			}

			storedByID := make(map[int64]record.Permission, len(stored))
			for _, p := range stored {
				storedByID[p.ID] = p
			}
			named := make(map[int64]bool, len(req.Permissions))
			for _, p := range req.Permissions {
				if p.ID <= 0 {
					continue
				}
				if _, ok := storedByID[p.ID]; !ok {
					// Validated against the rows read before the transaction and gone from this
					// read, with the loaded list still matching it: the list changed and changed
					// back between the two reads.
					return errListChanged
				}
				named[p.ID] = true
			}

			// A stored row the request does not name is dropped: its identifier cannot be wanted,
			// since an entry carrying it under another id was refused above.
			for _, p := range stored {
				if named[p.ID] {
					continue
				}
				if deleteErr := database.DeletePermission(r.Context(), tx, p.ID); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting permission %d", p.ID)
				}
			}
			for _, p := range req.Permissions {
				if p.ID <= 0 {
					continue
				}
				cur := storedByID[p.ID]
				if cur.PermissionIdentifier == p.PermissionIdentifier && cur.Description == p.Description {
					continue
				}
				cur.PermissionIdentifier = p.PermissionIdentifier
				cur.Description = p.Description
				if updateErr := database.UpdatePermission(r.Context(), tx, &cur); updateErr != nil {
					return errs.Wrapf(updateErr, "database error updating permission %d", cur.ID)
				}
			}
			for _, p := range req.Permissions {
				if p.ID > 0 {
					continue
				}
				if createErr := database.CreatePermission(r.Context(), tx, &record.Permission{
					ResourceID:           resource.ID,
					PermissionIdentifier: p.PermissionIdentifier,
					Description:          p.Description,
				}); createErr != nil {
					return errs.Wrapf(createErr, "database error creating permission %s", p.PermissionIdentifier)
				}
			}
			return nil
		})
		if err != nil {
			writeListSaveFailure(w, r, err, "resource_id", resource.ID)
			return
		}

		// Audit consolidated update, once the save has committed (#428).
		auditLogger.Log(r.Context(), audit.EventUpdatedResourcePermissions, map[string]interface{}{
			"resource_id":    resource.ID,
			"logged_in_user": callerSubject(r),
		})

		// Respond success
		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// permissionEntryOf is a stored permission as the loaded-list comparison sees it, in the shape the
// caller sends its loaded entries: id, identifier and description, so a rename or a changed
// description by another save makes the caller's list outdated as surely as an added or dropped
// permission does. The caller's entries are compared as sent: it echoes what it read, and stored
// values were trimmed when they were written (#428).
func permissionEntryOf(p record.Permission) api.ResourcePermissionUpsert {
	return api.ResourcePermissionUpsert{ID: p.ID, PermissionIdentifier: p.PermissionIdentifier, Description: p.Description}
}

// Note: The previous validation endpoint [/resources/validate-permission] was removed.
