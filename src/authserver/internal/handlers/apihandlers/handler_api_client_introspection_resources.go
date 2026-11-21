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
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// A client's introspection resources are the resources whose tokens it may introspect (#676
// decisions 5 and 14). They are administered as its permissions are: read and replaced whole, on
// the route the clients scopes reach, with the administrative policy judging the save.

// clientIntrospectionResourcesDatabase is what the introspection resource endpoints need: the
// client's list and the resources it names, the client's row to hold while a save adds to it, and
// what the administrative policy reads to judge a save.
type clientIntrospectionResourcesDatabase interface {
	clientTargetPolicyDatabase
	AcquireClientRow(ctx context.Context, tx *sql.Tx, clientID int64) error
	CreateClientIntrospectionResource(ctx context.Context, tx *sql.Tx, link *record.ClientIntrospectionResource) error
	DeleteClientIntrospectionResource(ctx context.Context, tx *sql.Tx, clientIntrospectionResourceID int64) error
	GetClientByID(ctx context.Context, tx *sql.Tx, clientID int64) (*record.Client, error)
	GetClientIntrospectionResourcesByClientID(ctx context.Context, tx *sql.Tx, clientID int64) ([]record.ClientIntrospectionResource, error)
	GetResourceByID(ctx context.Context, tx *sql.Tx, resourceID int64) (*record.Resource, error)
	GetResourcesByIDs(ctx context.Context, tx *sql.Tx, resourceIDs []int64) ([]record.Resource, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// errClientIsPublic is what a save's transaction returns when the client it adds to was made public
// after the request read it: the refusal the request's own check would have answered.
var errClientIsPublic = errors.New("the client is public")

// HandleClientIntrospectionResourcesGet - GET /api/v1/admin/clients/{id}/introspection-resources
func HandleClientIntrospectionResourcesGet(
	database clientIntrospectionResourcesDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for introspection resources"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		links, err := database.GetClientIntrospectionResourcesByClientID(r.Context(), nil, client.ID)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client introspection resources"), "client_id", client.ID)
			return
		}
		resourceIDs := make([]int64, 0, len(links))
		for _, link := range links {
			resourceIDs = append(resourceIDs, link.ResourceID)
		}
		resources, err := database.GetResourcesByIDs(r.Context(), nil, resourceIDs)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading introspection resources"), "client_id", client.ID)
			return
		}

		// Never null: a client listing nothing answers [].
		listed := apimapping.ToResourceResponses(resources)
		if listed == nil {
			listed = []api.ResourceResponse{}
		}
		writeJSON(w, r, http.StatusOK, api.GetClientIntrospectionResourcesResponse{
			Client:    *apimapping.ToClientResponse(client),
			Resources: listed,
		})
	}
}

// HandleClientIntrospectionResourcesPut - PUT /api/v1/admin/clients/{id}/introspection-resources
//
// Replaces the whole list of resources whose tokens the client may introspect, as a list save does
// (#428): the request's 400s and 404s first, then the administrative policy, then one transaction
// that refuses with 409 unless the stored list is the one the caller loaded. A public client cannot
// authenticate and so never introspects, so a list for one is refused; its empty list is not.
func HandleClientIntrospectionResourcesPut(
	database clientIntrospectionResourcesDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for introspection resources update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var request api.UpdateClientIntrospectionResourcesRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&request); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// The list as the caller loaded it, required as on every list save: absent or null decodes
		// to nil and is refused, [] means the caller read an empty list (#428).
		if request.ExpectedResourceIDs == nil {
			writeJSONError(w, "expectedResourceIds is required: send the resource ids as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		wanted := firstOccurrences(request.ResourceIDs)

		if client.IsPublic && len(wanted) > 0 {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientIntrospectionResourcesPublicClient, nil))
			return
		}

		resources := make([]record.Resource, 0, len(wanted))
		for _, resourceID := range wanted {
			resource, getErr := database.GetResourceByID(r.Context(), nil, resourceID)
			if getErr != nil {
				writeInternalServerError(w, r, errs.Wrap(getErr, "database error getting resource by ID for validation"), "resource_id", resourceID, "client_id", client.ID)
				return
			}
			if resource == nil {
				writeJSONError(w, "Resource not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
			resources = append(resources, *resource)
		}

		// Only authserver:manage lists the authserver resource (#676 decision 14), and only it
		// writes to an administrator client (#402 decision 1).
		if !introspectionResourceCeilingAllows(w, r, auditLogger, client, resources, request.ExpectedResourceIDs) {
			return
		}
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		listedKey := func(link record.ClientIntrospectionResource) int64 { return link.ResourceID }
		listedID := func(link record.ClientIntrospectionResource) int64 { return link.ID }

		// One transaction, rerun whole after a deadlock (#301), with nothing written to the response
		// inside it. No row lock for the list itself, as for every list save: overlapping saves merge
		// item by item, and a resource both add meets the unique key, answered 409 (#428).
		//
		// A save that adds a resource does take the client's row, because whether the client is
		// public is decided under that row: making it public takes the row first and clears the list
		// in the same transaction. Read under it, a client made public since the check above refuses
		// the save, and a client made public after this commits has its list cleared then, so no
		// public client is left holding a list (#245, #676 decision 14).
		added, removed := []int64{}, []int64{}
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			stored, loadErr := database.GetClientIntrospectionResourcesByClientID(r.Context(), tx, client.ID)
			if loadErr != nil {
				return errs.Wrap(loadErr, "database error loading client introspection resources before update")
			}
			if !sameSet(stored, listedKey, request.ExpectedResourceIDs) {
				return errListChanged
			}

			insert, remove := replaceSet(stored, listedKey, listedID, wanted)
			if len(insert) > 0 {
				if acquireErr := database.AcquireClientRow(r.Context(), tx, client.ID); acquireErr != nil {
					return acquireErr
				}
				current, getErr := database.GetClientByID(r.Context(), tx, client.ID)
				if getErr != nil {
					return errs.Wrap(getErr, "database error reading the client under its row lock")
				}
				if current != nil && current.IsPublic {
					return errClientIsPublic
				}
			}
			for _, rowID := range remove {
				if deleteErr := database.DeleteClientIntrospectionResource(r.Context(), tx, rowID); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting client introspection resource %d", rowID)
				}
			}
			for _, resourceID := range insert {
				if createErr := database.CreateClientIntrospectionResource(r.Context(), tx, &record.ClientIntrospectionResource{
					ClientID:   client.ID,
					ResourceID: resourceID,
				}); createErr != nil {
					return errs.Wrapf(createErr, "database error listing introspection resource %d", resourceID)
				}
			}
			// Assigned only by an attempt that reached its end. Never nil, so the record names an
			// empty list rather than null.
			added = append([]int64{}, insert...)
			removed = append([]int64{}, revokedKeys(stored, listedKey, wanted)...)
			return nil
		})
		if errors.Is(err, errClientIsPublic) {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientIntrospectionResourcesPublicClient, nil))
			return
		}
		if err != nil {
			writeListSaveFailure(w, r, err, "client_id", client.ID)
			return
		}

		auditLogger.Log(r.Context(), audit.EventUpdatedClientIntrospectionResources, map[string]interface{}{
			"client_id":            client.ID,
			"added_resource_ids":   added,
			"removed_resource_ids": removed,
			"logged_in_user":       callerSubject(r),
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}
