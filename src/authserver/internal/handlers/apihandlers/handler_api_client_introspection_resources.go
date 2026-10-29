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
	AcquireClientRow(ctx context.Context, tx *sql.Tx, clientId int64) error
	CreateClientIntrospectionResource(ctx context.Context, tx *sql.Tx, link *record.ClientIntrospectionResource) error
	DeleteClientIntrospectionResource(ctx context.Context, tx *sql.Tx, clientIntrospectionResourceId int64) error
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error)
	GetClientIntrospectionResourcesByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.ClientIntrospectionResource, error)
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*record.Resource, error)
	GetResourcesByIds(ctx context.Context, tx *sql.Tx, resourceIds []int64) ([]record.Resource, error)
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

		client, err := database.GetClientById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for introspection resources"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		links, err := database.GetClientIntrospectionResourcesByClientId(r.Context(), nil, client.Id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client introspection resources"), "client_id", client.Id)
			return
		}
		resourceIds := make([]int64, 0, len(links))
		for _, link := range links {
			resourceIds = append(resourceIds, link.ResourceId)
		}
		resources, err := database.GetResourcesByIds(r.Context(), nil, resourceIds)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading introspection resources"), "client_id", client.Id)
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

		client, err := database.GetClientById(r.Context(), nil, id)
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
		if request.ExpectedResourceIds == nil {
			writeJSONError(w, "expectedResourceIds is required: send the resource ids as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		wanted := firstOccurrences(request.ResourceIds)

		if client.IsPublic && len(wanted) > 0 {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientIntrospectionResourcesPublicClient, nil))
			return
		}

		resources := make([]record.Resource, 0, len(wanted))
		for _, resourceId := range wanted {
			resource, getErr := database.GetResourceById(r.Context(), nil, resourceId)
			if getErr != nil {
				writeInternalServerError(w, r, errs.Wrap(getErr, "database error getting resource by ID for validation"), "resource_id", resourceId, "client_id", client.Id)
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
		if !introspectionResourceCeilingAllows(w, r, auditLogger, client, resources, request.ExpectedResourceIds) {
			return
		}
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		listedKey := func(link record.ClientIntrospectionResource) int64 { return link.ResourceId }
		listedId := func(link record.ClientIntrospectionResource) int64 { return link.Id }

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
			stored, loadErr := database.GetClientIntrospectionResourcesByClientId(r.Context(), tx, client.Id)
			if loadErr != nil {
				return errs.Wrap(loadErr, "database error loading client introspection resources before update")
			}
			if !sameSet(stored, listedKey, request.ExpectedResourceIds) {
				return errListChanged
			}

			insert, remove := replaceSet(stored, listedKey, listedId, wanted)
			if len(insert) > 0 {
				if acquireErr := database.AcquireClientRow(r.Context(), tx, client.Id); acquireErr != nil {
					return acquireErr
				}
				current, getErr := database.GetClientById(r.Context(), tx, client.Id)
				if getErr != nil {
					return errs.Wrap(getErr, "database error reading the client under its row lock")
				}
				if current != nil && current.IsPublic {
					return errClientIsPublic
				}
			}
			for _, rowId := range remove {
				if deleteErr := database.DeleteClientIntrospectionResource(r.Context(), tx, rowId); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting client introspection resource %d", rowId)
				}
			}
			for _, resourceId := range insert {
				if createErr := database.CreateClientIntrospectionResource(r.Context(), tx, &record.ClientIntrospectionResource{
					ClientId:   client.Id,
					ResourceId: resourceId,
				}); createErr != nil {
					return errs.Wrapf(createErr, "database error listing introspection resource %d", resourceId)
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
			writeListSaveFailure(w, r, err, "client_id", client.Id)
			return
		}

		auditLogger.Log(r.Context(), audit.EventUpdatedClientIntrospectionResources, map[string]interface{}{
			"client_id":            client.Id,
			"added_resource_ids":   added,
			"removed_resource_ids": removed,
			"logged_in_user":       callerSubject(r),
		})

		writeJSON(w, r, http.StatusOK, api.SuccessResponse{Success: true})
	}
}
