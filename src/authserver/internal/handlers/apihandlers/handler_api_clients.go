package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/urlmatch"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/leodip/goiabada/core/securerandom"
)

// clientsDatabase is what the client endpoints need: the client row, its redirect URIs, sign-out
// redirect URIs and web origins, the resource row an identifier may not name (#151), and the
// transaction that changes them together.
//
// It embeds the revocation port because making a confidential client public revokes the grants it
// held while it still had to authenticate, and a change of its identifier revokes them too, and
// what the administrative policy reads to judge whether the client is an administrator.
type clientsDatabase interface {
	revocation.Database
	clientTargetPolicyDatabase

	AcquireClientRow(ctx context.Context, tx *sql.Tx, clientID int64) error
	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error
	ClientLoadPostLogoutRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error
	ClientLoadWebOrigins(ctx context.Context, tx *sql.Tx, client *record.Client) error
	CreateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error
	CreatePostLogoutRedirectURI(ctx context.Context, tx *sql.Tx, postLogoutRedirectURI *record.PostLogoutRedirectURI) error
	CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *record.RedirectURI) error
	CreateWebOrigin(ctx context.Context, tx *sql.Tx, webOrigin *record.WebOrigin) error
	DeleteClient(ctx context.Context, tx *sql.Tx, clientID int64) error
	DeleteClientIntrospectionResourcesByClientID(ctx context.Context, tx *sql.Tx, clientID int64) error
	DeletePostLogoutRedirectURI(ctx context.Context, tx *sql.Tx, postLogoutRedirectURIID int64) error
	DeleteRedirectURI(ctx context.Context, tx *sql.Tx, redirectURIID int64) error
	DeleteWebOrigin(ctx context.Context, tx *sql.Tx, webOriginID int64) error
	GetAllClients(ctx context.Context, tx *sql.Tx) ([]record.Client, error)
	GetClientIntrospectionResourcesByClientID(ctx context.Context, tx *sql.Tx, clientID int64) ([]record.ClientIntrospectionResource, error)
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetClientByID(ctx context.Context, tx *sql.Tx, clientID int64) (*record.Client, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*record.Resource, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	SetClientAdministrativeScopesAllowed(ctx context.Context, tx *sql.Tx, clientID int64, allowed bool) error
	SetClientPublic(ctx context.Context, tx *sql.Tx, clientID int64) (bool, error)
	SetClientRememberConsent(ctx context.Context, tx *sql.Tx, clientID int64, remember bool) error
	SetClientBackchannelLogout(ctx context.Context, tx *sql.Tx, clientID int64, uri string, sessionRequired bool) error
	SetClientDPoPBoundAccessTokens(ctx context.Context, tx *sql.Tx, clientID int64, required bool) error
	SetClientIdentifier(ctx context.Context, tx *sql.Tx, clientID int64, clientIdentifier string) (bool, error)
	UpdateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error
}

// clientSettingsSave is what the settings save writes beside the whole row, under the row's lock.
//
// identifier is the client identifier as submitted. Its one writer after creation is
// SetClientIdentifier, and this save is its one caller, so the other saves, which write from a copy
// loaded earlier in their request, cannot write back an identifier renamed since (#710 decision 4).
// identifierValidator holds a different identifier to the identifier format.
//
// rememberConsent is the save's optional Remember consent, nil to leave the stored value alone.
type clientSettingsSave struct {
	identifier          string
	identifierValidator *inputvalidation.IdentifierValidator
	rememberConsent     *bool
}

// updateClientNotOwningAuthenticationMode writes a client through an endpoint that changes some
// other part of it. Three of them exist (general settings, OAuth2 flows, token settings) and none
// of them means to touch how the client authenticates, but UpdateClient writes every mutable
// column, so each one silently carries is_public and client_secret_encrypted from the copy it
// loaded at the top of the request back into the row.
//
// That is a lost update with a security consequence, which is why it is closed here rather than
// left to the general concurrency of the endpoint. A save whose loaded copy said "public" and
// whose row now says "confidential" restores public mode and deletes the newer secret, and the
// handler doing it has no revocation of its own, so the client's outstanding grants stay
// redeemable with nothing presented. The confidential-to-public flip is the only write allowed to
// change this, and it revokes (#245, final review finding 1).
//
// So the row is ACQUIRED and then the two authentication-owned columns are re-read inside the
// transaction and copied over whatever the caller is holding.
//
// THE ACQUISITION IS NOT DECORATION, and taking it out reopens the window rather than merely
// slowing it down. A re-read is not atomic with the write that follows it: another transaction
// can commit in the gap between them, and this write then carries the value read before that
// commit. On mysql and postgres the re-read does not even wait for an in-flight writer, so the
// window is that writer's whole transaction rather than the gap between two statements; SQL
// Server's shared locks narrow it and do not close it. AcquireClientRow takes the row first, so
// the re-read happens under this transaction's own lock and nothing can get between it and the
// write. Measured on all four engines during #245's final review: a writer that re-read without
// first acquiring the row restored public mode over a concurrent confidential flip (#245).
//
// REFRESHING THE MODE IS NOT ENOUGH ON ITS OWN, because two other columns are derived from it.
// A public client must carry pkce_required true and client_credentials_enabled false, and every
// one of these endpoints writes both columns from its own snapshot. So a save that loaded the
// client while it was confidential, with PKCE optional and client credentials on, would preserve
// the refreshed public mode and restore both forbidden values underneath it. The server would
// still refuse client credentials and still require PKCE at runtime, because both rules are read
// at the point of use, but the stored row, the admin API's response and the console would all
// report the opposite of what the server does, which is the display lie #245 closed.
// Client.ApplyPublicClientInvariants therefore runs on every caller's behalf, after the refresh
// and before the write (#245).
//
// It does not close the lost update on the columns each endpoint DOES own: two concurrent saves
// of the same section still last-write-wins, which is how every entity in this codebase behaves
// and is a separate, wider question.
//
// settings is the settings save's own writes, nil for every other caller. Its identifier is decided
// here, against the row re-read under the lock, and never against the copy the request loaded,
// which a rename committed since makes stale (#710 decision 4). One that differs from the row's is
// held to the format, uniqueness and resource-name checks on this transaction, and refused, with
// nothing written, when one fails; one that equals the row's, compared byte for byte with the value
// as submitted, is not checked, which is what keeps a self-registered client's 40-character
// identifier editable elsewhere on the form (#108 decision 17), and a row that holds an identifier
// naming a resource from before #151. Then SetClientIdentifier writes it only when it differs, and
// every caller answers with the identifier the row holds. A write that changed the identifier
// revokes the client's grants in the same transaction: see saveClientNotOwningAuthenticationMode.
//
// The settings save's Remember consent is nil for a save without it, which leaves the stored value
// alone. A value is decided here,
// against the row re-read under the lock, because it depends on the mode as the property above
// does (#711 decisions 4 and 5): a confidential client is stored on whatever was sent; a public one
// takes the value only when the request also loaded it public. A save that loaded the client while
// it was confidential chose its value for a client that needed no vouching, so it never applies to
// one made public since, which the switch left off.
func updateClientNotOwningAuthenticationMode(ctx context.Context, database clientsDatabase, client *record.Client, settings *clientSettingsSave) error {
	_, err := saveClientNotOwningAuthenticationMode(ctx, database, client, settings)
	return err
}

// clientRename is what a settings save's identifier write came to: whether it changed the
// identifier, and so revoked the client's grants, and what that revocation revoked, which the save
// records after the commit.
type clientRename struct {
	renamed bool
	result  revocation.ClientGrantResult
}

// saveClientNotOwningAuthenticationMode is updateClientNotOwningAuthenticationMode answering what
// the identifier's write came to, for the settings save, which records the rename's revocation.
//
// A change of the identifier revokes the client's grants, in the transaction that writes it, by the
// sweep the switch to public uses, under ReasonClientIdentifierChanged (#710 decision 5). A refresh
// token names its client by row, so no check of the token can tell its client was renamed: a grant
// refreshed afterwards would be given an ID token whose aud is not the one its sign-in got, which
// OpenID Connect Core 1.0 section 12.2 forbids. What decides it is SetClientIdentifier's answer under
// the row's lock, never a comparison with the copy the request loaded, as the switch to public is
// decided by SetClientPublic's (#245): a rename another save committed meanwhile leaves this save's
// identifier already in the row, which is no change and revokes nothing. revocation.RevokeClientGrantsTx
// opens the transaction, so the rename and its sweep commit together or not at all.
func saveClientNotOwningAuthenticationMode(ctx context.Context, database clientsDatabase, client *record.Client, settings *clientSettingsSave) (clientRename, error) {
	// Taken before the transaction: the body overwrites client.IsPublic with the row's mode, and a
	// rerun after a deadlock must still decide against the mode the request loaded.
	loadedPublic := client.IsPublic

	// Opened through RunInTransaction, so a deadlock reruns the acquisition, the re-read and the
	// write together (#301). Safe to rerun: the two columns are copied from the row re-read under
	// this attempt's own lock, ApplyPublicClientInvariants is idempotent on the result, and the
	// identifier and Remember consent are decided again from that row and written as fixed values.
	// The settings save's transaction is opened through revocation.RevokeClientGrantsTx, which also
	// reruns it once after a unique violation: a family record lost to a containment, or an
	// identifier another client took between this save's check and its write, which the rerun's
	// check then refuses as in use.
	if settings == nil {
		return clientRename{}, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			_, err := writeClientNotOwningAuthenticationMode(ctx, database, tx, client, nil, loadedPublic)
			return err
		})
	}

	var rename clientRename
	result, err := revocation.RevokeClientGrantsTx(ctx, database, client.ID, revocation.ReasonClientIdentifierChanged,
		func(tx *sql.Tx) (bool, error) {
			renamed, err := writeClientNotOwningAuthenticationMode(ctx, database, tx, client, settings, loadedPublic)
			rename.renamed = renamed
			return renamed, err
		})
	if err != nil {
		return clientRename{}, err
	}
	rename.result = result
	return rename, nil
}

// writeClientNotOwningAuthenticationMode is the body of updateClientNotOwningAuthenticationMode's
// transaction, on tx. It answers whether the settings save's identifier write changed the
// identifier, false for every other save.
func writeClientNotOwningAuthenticationMode(ctx context.Context, database clientsDatabase, tx *sql.Tx,
	client *record.Client, settings *clientSettingsSave, loadedPublic bool) (bool, error) {
	if err := database.AcquireClientRow(ctx, tx, client.ID); err != nil {
		return false, err
	}

	current, err := database.GetClientByID(ctx, tx, client.ID)
	if err != nil {
		return false, err
	}
	if current == nil {
		return false, errs.New("client no longer exists")
	}

	if settings != nil && settings.identifier != current.ClientIdentifier {
		if err = checkClientIdentifierChange(ctx, database, tx, settings.identifierValidator, settings.identifier, client.ID); err != nil {
			return false, err
		}
	}

	// UpdateClient never writes the identifier, and the answer takes the row's, as it does the
	// mode: a rename committed since the load is what the client is now called (#710 decision 4).
	client.ClientIdentifier = current.ClientIdentifier
	client.IsPublic = current.IsPublic
	client.ClientSecretEncrypted = current.ClientSecretEncrypted
	// UpdateClient never writes Remember consent, so none of these saves can write back the
	// value it loaded. The copy it answers with takes the row's value too, so a save loaded
	// while the client was confidential cannot answer on for a client made public since
	// (#711 decision 5).
	client.RememberConsent = current.RememberConsent
	// UpdateClient never writes the token_endpoint_auth_method a self-registered client is
	// held to either, and a switch to public committed since the load cleared it: the answer
	// takes the row's value, as it does the mode (#708 decision 5).
	client.TokenEndpointAuthMethod = current.TokenEndpointAuthMethod

	client.ApplyPublicClientInvariants()

	// The settings save's narrow writes go ahead of the whole-row save. Each sets updated_at, and
	// the whole-row save's is the one the answer carries, so it is the last to set it and the row
	// holds the timestamp the save answers.
	renamed := false
	if settings != nil {
		// The write decides, under the row's lock, whether the identifier changes, and so whether
		// the client's grants are revoked; either way the row now holds the one submitted.
		renamed, err = database.SetClientIdentifier(ctx, tx, client.ID, settings.identifier)
		if err != nil {
			return false, err
		}
		client.ClientIdentifier = settings.identifier

		if err = writeSettingsRememberConsent(ctx, database, tx, client, settings, current.IsPublic, loadedPublic); err != nil {
			return false, err
		}
	}

	if err = database.UpdateClient(ctx, tx, client); err != nil {
		return false, err
	}
	return renamed, nil
}

// writeSettingsRememberConsent writes the settings save's Remember consent, decided against the
// mode the row holds under the lock and the mode the request loaded, and leaves it alone for a save
// without it.
func writeSettingsRememberConsent(ctx context.Context, database clientsDatabase, tx *sql.Tx,
	client *record.Client, settings *clientSettingsSave, rowPublic, loadedPublic bool) error {
	if settings.rememberConsent == nil {
		return nil
	}
	var remember bool
	switch {
	case !rowPublic:
		remember = true
	case loadedPublic:
		remember = *settings.rememberConsent
	default:
		return nil
	}
	if err := database.SetClientRememberConsent(ctx, tx, client.ID, remember); err != nil {
		return err
	}
	client.RememberConsent = remember
	return nil
}

// checkClientIdentifierChange holds an identifier the client is being renamed to to the identifier
// format, refuses one another client holds, and one a resource holds (#151), reading on tx. A
// refusal is the *i18n.LocalizedError the save answers; a failed lookup is an error, never read as
// "no clash".
func checkClientIdentifierChange(ctx context.Context, database clientsDatabase, tx *sql.Tx,
	validator *inputvalidation.IdentifierValidator, identifier string, clientID int64) error {

	if err := validator.Validate(identifier, true); err != nil {
		return err
	}

	existingClient, err := database.GetClientByClientIdentifier(ctx, tx, identifier)
	if err != nil {
		return errs.Wrap(err, "database error checking client existence by identifier for update")
	}
	if existingClient != nil && existingClient.ID != clientID {
		return i18n.NewLocalizedError(i18n.ErrCodeClientIdentifierInUse, nil)
	}

	clashingResource, err := database.GetResourceByResourceIdentifier(ctx, tx, identifier)
	if err != nil {
		return errs.Wrap(err, "database error checking resource by client identifier for update")
	}
	if clashingResource != nil {
		return i18n.NewLocalizedError(i18n.ErrCodeClientIdentifierNamesResource, nil)
	}
	return nil
}

// HandleClientsGet - GET /api/v1/admin/clients
func HandleClientsGet(
	database clientsDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		clients, err := database.GetAllClients(r.Context(), nil)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting all clients"))
			return
		}

		// Load the redirect URIs, sign-out redirect URIs and web origins of each client
		for i := range clients {
			err = database.ClientLoadRedirectURIs(r.Context(), nil, &clients[i])
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs"), "client_id", clients[i].ID)
				return
			}

			err = database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, &clients[i])
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs"), "client_id", clients[i].ID)
				return
			}

			err = database.ClientLoadWebOrigins(r.Context(), nil, &clients[i])
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins"), "client_id", clients[i].ID)
				return
			}
		}

		clientResponses := apimapping.ToClientResponses(clients)

		response := api.GetClientsResponse{
			Clients: clientResponses,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleClientGet - GET /api/v1/admin/clients/{id}
//
// The client's secret is not in this response: it is read from HandleClientSecretGet, which
// admin-read cannot reach and which records the read (#402 decision 8, #403).
func HandleClientGet(
	database clientsDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("id")
		if len(idStr) == 0 {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID"), "client_id", id)
			return
		}

		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Load the redirect URIs, sign-out redirect URIs and web origins
		err = database.ClientLoadRedirectURIs(r.Context(), nil, client)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs"), "client_id", client.ID)
			return
		}

		err = database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs"), "client_id", client.ID)
			return
		}

		err = database.ClientLoadWebOrigins(r.Context(), nil, client)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins"), "client_id", client.ID)
			return
		}

		// Do not include permissions in this endpoint for consistency with users/groups

		clientResponse := apimapping.ToClientResponse(client)

		response := api.GetClientResponse{
			Client: *clientResponse,
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleClientSecretGet - GET /api/v1/admin/clients/{id}/secret
//
// The one route that answers a client's secret, decrypted, and only to manage-clients or manage:
// admin-read, which reads every client, reaches no credential. A read that discloses a secret is
// recorded as viewed_client_secret; a client holding none is answered an empty one and records
// nothing, since nothing was disclosed (#402 decision 8, #403).
func HandleClientSecretGet(
	database clientsDatabase,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Only authserver:manage reads an administrator client's secret, which is signing in as it
		// (#402 decisions 1 and 8), or the secret of a client listed for the authserver resource's
		// tokens (#676 decision 14).
		if !clientCredentialsCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		response := api.GetClientSecretResponse{}
		if client.ClientSecretEncrypted != nil {
			response.ClientSecret, err = dataCipher.Decrypt(client.ClientSecretEncrypted)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "unable to decrypt client secret"), "client_id", client.ID)
				return
			}
			auditLogger.Log(r.Context(), audit.EventViewedClientSecret, map[string]interface{}{
				"client_id":         client.ID,
				"client_identifier": client.ClientIdentifier,
				"logged_in_user":    callerSubject(r),
			})
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleClientDelete - DELETE /api/v1/admin/clients/{id}
func HandleClientDelete(
	database clientsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for deletion"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		if client.IsSystemLevelClient() {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientSystemLevelDeleteNotAllowed, nil))
			return
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		if err := database.DeleteClient(r.Context(), nil, client.ID); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error deleting client"), "client_id", client.ID, "client_identifier", client.ClientIdentifier)
			return
		}

		auditLogger.Log(r.Context(), audit.EventDeletedClient, map[string]interface{}{
			"client_id":         client.ID,
			"client_identifier": client.ClientIdentifier,
			"logged_in_user":    callerSubject(r),
		})

		resp := api.SuccessResponse{Success: true}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleClientCreatePost - POST /api/v1/admin/clients
func HandleClientCreatePost(
	database clientsDatabase,
	identifierValidator *inputvalidation.IdentifierValidator,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var req api.CreateClientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate client identifier present
		if strings.TrimSpace(req.ClientIdentifier) == "" {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientIdentifierRequired, nil))
			return
		}

		// Validate description length
		const maxLengthDescription = 100
		if inputvalidation.TextLength(req.Description) > maxLengthDescription {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientDescriptionTooLong, map[string]any{"max": maxLengthDescription}))
			return
		}

		if err := accountvalidation.ValidateNoAngleBrackets(req.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate display name
		trimmedDisplayName := strings.TrimSpace(req.DisplayName)
		const maxLengthDisplayName = 100
		if inputvalidation.TextLength(trimmedDisplayName) > maxLengthDisplayName {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientDisplayNameTooLong, map[string]any{"max": maxLengthDisplayName}))
			return
		}

		if err := accountvalidation.ValidateNoAngleBrackets(trimmedDisplayName, i18n.ErrCodeDisplayNameAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Validate identifier format
		if err := identifierValidator.Validate(req.ClientIdentifier, true); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Check uniqueness
		existingClient, err := database.GetClientByClientIdentifier(r.Context(), nil, req.ClientIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking client existence by identifier"), "client_identifier", req.ClientIdentifier)
			return
		}
		if existingClient != nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientIdentifierInUse, nil))
			return
		}

		// A client identifier may not name a resource either. The two namespaces are separate
		// tables with separate uniqueness checks, and a string held by both makes an access
		// token's aud resolvable as a client, which is how a session-bound access token passed
		// every ID-token-hint check in #109's logout (#151). Under concurrency the check is
		// advisory: no index spans the two tables, so this create and a resource create naming
		// the same string, overlapping, can both commit; the startup warning reports such a pair.
		clashingResource, err := database.GetResourceByResourceIdentifier(r.Context(), nil, req.ClientIdentifier)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error checking resource by client identifier"), "client_identifier", req.ClientIdentifier)
			return
		}
		if clashingResource != nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientIdentifierNamesResource, nil))
			return
		}

		// Generate and encrypt client secret
		clientSecret := securerandom.String(60)
		clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "failed to encrypt client secret"))
			return
		}

		// Create client model mimicking current implementation defaults
		client := &record.Client{
			ClientIdentifier:      strings.TrimSpace(req.ClientIdentifier),
			Description:           strings.TrimSpace(req.Description),
			DisplayName:           trimmedDisplayName,
			ShowDisplayName:       trimmedDisplayName != "",
			ClientSecretEncrypted: clientSecretEncrypted,
			IsPublic:              false,
			ConsentRequired:       false,
			// The create request makes a confidential client, and a confidential client always
			// remembers consent (#711 decision 4).
			RememberConsent:                         true,
			Enabled:                                 true,
			DefaultACRLevel:                         record.ACRLevel2Optional,
			AuthorizationCodeEnabled:                req.AuthorizationCodeEnabled,
			ClientCredentialsEnabled:                req.ClientCredentialsEnabled,
			IncludeOpenIDConnectClaimsInAccessToken: record.ThreeStateSettingDefault.String(),
			IncludeOpenIDConnectClaimsInIDToken:     record.ThreeStateSettingDefault.String(),
		}

		if err := database.CreateClient(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error creating client"))
			return
		}

		// Audit log
		auditLogger.Log(r.Context(), audit.EventCreatedClient, map[string]interface{}{
			"client_id":         client.ID,
			"client_identifier": client.ClientIdentifier,
			"logged_in_user":    callerSubject(r),
		})

		// Load related fields for response consistency (fail if these operations fail)
		if err := database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after create"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after create"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after create"), "client_id", client.ID)
			return
		}

		resp := api.CreateClientResponse{
			Client: *apimapping.ToClientResponse(client),
		}

		writeJSON(w, r, http.StatusCreated, resp)
	}
}

// HandleClientUpdatePut - PUT /api/v1/admin/clients/{id}
func HandleClientUpdatePut(
	database clientsDatabase,
	identifierValidator *inputvalidation.IdentifierValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var updateReq api.UpdateClientSettingsRequest
		if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate client identifier
		if strings.TrimSpace(updateReq.ClientIdentifier) == "" {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientIdentifierRequired, nil))
			return
		}

		// Validate description length
		const maxLengthDescription = 100
		if inputvalidation.TextLength(updateReq.Description) > maxLengthDescription {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientDescriptionTooLong, map[string]any{"max": maxLengthDescription}))
			return
		}

		if err := accountvalidation.ValidateNoAngleBrackets(updateReq.Description, i18n.ErrCodeDescriptionAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Prepare the new identifier value
		trimmedClientIdentifier := strings.TrimSpace(updateReq.ClientIdentifier)

		// The two clients whose identifier may not change are refused for that reason before the new
		// identifier's format and uniqueness are checked: a rename that can never succeed is not
		// answered as though another identifier might (#522).
		//
		// System-level client protection: block identifier changes
		if client.IsSystemLevelClient() && trimmedClientIdentifier != client.ClientIdentifier {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientSystemLevelIdentifierFixed, nil))
			return
		}

		// Self-registered client protection: block identifier changes too. Until the created_via_dcr
		// column existed, the dcr_ identifier prefix was the only record that a client had
		// registered itself, so renaming one here erased that fact permanently: migration 000029
		// backfills from the prefix, and a client renamed before the upgrade is left unmarked, with
		// consent off, still issuing codes with no consent screen. The column makes new renames
		// harmless to the backfill, and blocking the rename keeps the prefix and the column saying
		// the same thing for anything that still reads a client identifier, a log line or an
		// operator's eye included (#108, decision 16).
		//
		// It blocks the rename and nothing else. Every other setting on a self-registered client
		// stays editable, Consent required above all: unticking it for one reviewed client is the
		// escape hatch this whole change rests on, so a guard that refused the update outright
		// would take away the remedy along with the risk.
		if client.CreatedViaDCR && trimmedClientIdentifier != client.ClientIdentifier {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientSelfRegisteredIdentifierFixed, nil))
			return
		}

		// The identifier's format, uniqueness and resource-name checks are not made here, against the
		// copy just loaded, but in the save's transaction, against the row as read under its lock,
		// and only when the identifier submitted differs from the row's: see
		// updateClientNotOwningAuthenticationMode (#710 decision 4).
		//
		// Skipping them for an unchanged identifier is load bearing rather than an optimisation. A
		// client that registered itself is given "dcr_" plus a UUID, which is 40 characters, and
		// IdentifierValidator.Validate caps an identifier at 38: re-checking an unchanged value
		// therefore rejected every update to every self-registered client, whatever the request was
		// trying to change. That made the escape hatch this change depends on unusable, since
		// turning consent off for one reviewed client is done on the same form (#108, decision 17).
		//
		// Compared byte for byte against what is stored, deliberately, rather than against the
		// trimmed value. "  same-identifier  " has always been refused as an invalid format and
		// still is; only a request submitting exactly what is already there skips the checks, which
		// makes the skip provably safe: an identifier that is already stored passed the same checks,
		// and the write leaves the bytes that are already in the row. The uniqueness query excludes
		// the client itself, so an unchanged identifier could only ever match its own row; and the
		// resource-name check, skipped with it, keeps a row that already holds a collision, from
		// before that check existed, editable everywhere else on this form (#151).

		// ACR level validation depending on AuthorizationCodeEnabled
		if !client.AuthorizationCodeEnabled && strings.TrimSpace(updateReq.DefaultACRLevel) != "" {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientDefaultACRNotApplicable, nil))
			return
		}

		// The three optional URLs take one rule: http or https, at most 256 characters. The privacy
		// policy and terms of service URLs are linked from the consent screen whenever set, and an
		// administrator's are not held to the redirect URIs' hosts as a registration's are (#622
		// decision 12).
		websiteURL, refusal := validateOptionalClientURL(updateReq.WebsiteURL, clientWebsiteURLRefusals)
		if refusal != nil {
			writeValidationError(w, r, refusal)
			return
		}
		privacyPolicyURL, refusal := validateOptionalClientURL(updateReq.PrivacyPolicyURL, clientPrivacyPolicyURLRefusals)
		if refusal != nil {
			writeValidationError(w, r, refusal)
			return
		}
		termsOfServiceURL, refusal := validateOptionalClientURL(updateReq.TermsOfServiceURL, clientTermsOfServiceURLRefusals)
		if refusal != nil {
			writeValidationError(w, r, refusal)
			return
		}

		client.Description = strings.TrimSpace(updateReq.Description)
		client.WebsiteURL = websiteURL
		client.PrivacyPolicyURL = privacyPolicyURL
		client.TermsOfServiceURL = termsOfServiceURL
		client.DisplayName = strings.TrimSpace(updateReq.DisplayName)

		// Validate display name length
		const maxLengthDisplayName = 100
		if inputvalidation.TextLength(client.DisplayName) > maxLengthDisplayName {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientDisplayNameTooLong, map[string]any{"max": maxLengthDisplayName}))
			return
		}

		if err := accountvalidation.ValidateNoAngleBrackets(client.DisplayName, i18n.ErrCodeDisplayNameAngleBrackets); err != nil {
			writeValidationError(w, r, err)
			return
		}

		client.Enabled = updateReq.Enabled
		client.ConsentRequired = updateReq.ConsentRequired
		client.ShowLogo = updateReq.ShowLogo
		client.ShowDisplayName = updateReq.ShowDisplayName
		client.ShowDescription = updateReq.ShowDescription
		client.ShowWebsiteURL = updateReq.ShowWebsiteURL

		if client.AuthorizationCodeEnabled && strings.TrimSpace(updateReq.DefaultACRLevel) != "" {
			acrLevel, err := record.ACRLevelFromString(updateReq.DefaultACRLevel)
			if err != nil {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientDefaultACRInvalid, nil))
				return
			}
			client.DefaultACRLevel = acrLevel
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		settings := &clientSettingsSave{
			identifier:          updateReq.ClientIdentifier,
			identifierValidator: identifierValidator,
			rememberConsent:     updateReq.RememberConsent,
		}
		rename, saveErr := saveClientNotOwningAuthenticationMode(r.Context(), database, client, settings)
		if saveErr != nil {
			var refusal *i18n.LocalizedError
			if errors.As(saveErr, &refusal) {
				writeValidationError(w, r, refusal)
				return
			}
			writeInternalServerError(w, r, errs.Wrap(saveErr, "database error updating client"), "client_id", client.ID, "client_identifier", client.ClientIdentifier)
			return
		}

		// The write's transaction has committed: it is recorded now, before the reads building the
		// answer, whose failure answers 500 but does not undo the change. A rename revoked the
		// client's grants in that transaction, and is recorded so for every rename, also one that
		// found nothing to revoke (#710 decision 5).
		if rename.renamed {
			revocation.LogRevokedClientGrants(r.Context(), auditLogger, client.ID,
				revocation.ReasonClientIdentifierChanged, callerSubject(r), rename.result)
		}
		auditLogger.Log(r.Context(), audit.EventUpdatedClientSettings, map[string]interface{}{
			"client_id":      client.ID,
			"logged_in_user": callerSubject(r),
		})

		// Load related fields for response consistency
		if err := database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after update"), "client_id", client.ID)
			return
		}

		response := api.UpdateClientResponse{
			Client: *apimapping.ToClientResponse(client),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleClientAuthenticationPut - PUT /api/v1/admin/clients/{id}/authentication
// Changes client's public/confidential mode and client secret.
func HandleClientAuthenticationPut(
	database clientsDatabase,
	auditLogger AuditLogger,
	dataCipher *encryption.DataCipher,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for authentication update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var req api.UpdateClientAuthenticationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		if req.IsPublic {
			// Switching to public: remove secret and disable client credentials
			client.IsPublic = true
			client.ClientSecretEncrypted = nil
			// Client credentials off and PKCE required, from the one definition every writer
			// that can persist those two columns shares (#245).
			client.ApplyPublicClientInvariants()
		} else {
			// Confidential: require strong secret
			if err := validateClientSecret(req.ClientSecret); err != nil {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientSecretInvalid, nil))
				return
			}

			enc, err := dataCipher.Encrypt(req.ClientSecret)
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "failed to encrypt client secret"), "client_id", client.ID)
				return
			}
			client.IsPublic = false
			client.ClientSecretEncrypted = enc
			// Preserve ClientCredentialsEnabled as-is
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1), or sets the
		// secret of a client listed for the authserver resource's tokens (#676 decision 14). Making
		// such a client public clears that list, which the ceiling reads off the client as written.
		if !clientCredentialsCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		// The confidential-to-public transition is the one that REMOVES the requirement for the
		// client to authenticate, so it is the one that revokes: every grant this client holds
		// was issued on the understanding that redeeming it took a secret, and after this write
		// nothing is presented at all. The reverse transition closes a window rather than opening
		// one, and rotating a confidential client's secret leaves the requirement in place;
		// revoking on either would sign real users out to protect against nothing (#245).
		//
		// The client write and the revocation share one transaction so the secret cannot be
		// destroyed while the grants it was protecting survive. The audit event is emitted after
		// the commit, because a logged revocation that then rolled back would be a false record.
		//
		// WHICH TRANSITION THIS IS, IS DECIDED BY THE WRITE ITSELF, not by comparing against a
		// copy of the client. The two are not the same row: a concurrent request can make this
		// client confidential and issue it a grant between any read and the write that follows
		// it, and a classification taken from the stale side then reads "already public", skips
		// the revocation, and commits a public client holding grants that were issued while a
		// secret was required. SetClientPublic answers it with the statements that perform the
		// change, which is the only way the answer and the change cannot disagree (#245, final
		// review finding 1, decision 17).
		if req.IsPublic {
			var becamePublic bool
			result, err := revocation.RevokeClientGrantsTx(r.Context(), database, client.ID, revocation.ReasonClientBecamePublic, func(tx *sql.Tx) (bool, error) {
				var err error
				becamePublic, err = database.SetClientPublic(r.Context(), tx, client.ID)
				if err != nil {
					return false, err
				}
				// A public client never introspects, so its introspection resources go in the
				// same transaction, under the row SetClientPublic took: a save adding to the list
				// reads the client under that row, so none can leave a public client holding one
				// (#676 decision 14). Run on every save to public, as the list of a client already
				// public is empty, and clearing an empty list writes nothing.
				if err := database.DeleteClientIntrospectionResourcesByClientID(r.Context(), tx, client.ID); err != nil {
					return false, err
				}
				if err := database.UpdateClient(r.Context(), tx, client); err != nil {
					return false, err
				}
				// SetClientPublic turned Remember consent off if it made the client public, and
				// left it as it was otherwise; UpdateClient never writes it. The answer reads it
				// from the row under the lock rather than from the copy loaded at the top of the
				// request, which may predate another save's switch (#711 decision 5). The same holds
				// for the token_endpoint_auth_method a self-registered client is held to, which
				// SetClientPublic cleared and UpdateClient never writes (#708 decision 5).
				current, readErr := database.GetClientByID(r.Context(), tx, client.ID)
				if readErr != nil {
					return false, readErr
				}
				if current == nil {
					return false, errs.New("client no longer exists")
				}
				client.RememberConsent = current.RememberConsent
				client.TokenEndpointAuthMethod = current.TokenEndpointAuthMethod
				// This save never writes the identifier, and a rename committed since the load is
				// what the client is now called (#710 decision 4).
				client.ClientIdentifier = current.ClientIdentifier
				return becamePublic, nil
			})
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error updating client authentication"), "client_id", client.ID)
				return
			}
			// Only a write that really performed the transition gets the event. A save of an
			// already-public client revoked nothing and must not claim to.
			if becamePublic {
				revocation.LogRevokedClientGrants(r.Context(), auditLogger, client.ID,
					revocation.ReasonClientBecamePublic, callerSubject(r), result)
			}
		} else {
			// A confidential client always remembers consent, so the switch to confidential, and
			// a confidential save, writes Remember consent on. In the transaction that writes the
			// mode, because UpdateClient leaves the column out: written apart, a switch to public
			// committed between the two would be left with Remember consent on (#711 decision 4).
			// Safe to rerun after a deadlock: both writes set fixed values, and the read after them
			// is taken again under the attempt's own row lock.
			err := database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
				if err := database.UpdateClient(r.Context(), tx, client); err != nil {
					return err
				}
				if err := database.SetClientRememberConsent(r.Context(), tx, client.ID, true); err != nil {
					return err
				}
				// UpdateClient never writes the token_endpoint_auth_method a self-registered client
				// is held to, and a switch to public committed after the load at the top of the
				// request cleared it. The answer reads it from the row the writes above hold rather
				// than from that copy (#708 decision 5).
				current, err := database.GetClientByID(r.Context(), tx, client.ID)
				if err != nil {
					return err
				}
				if current == nil {
					return errs.New("client no longer exists")
				}
				client.TokenEndpointAuthMethod = current.TokenEndpointAuthMethod
				// Nor does it write the identifier: the answer takes the row's (#710 decision 4).
				client.ClientIdentifier = current.ClientIdentifier
				return nil
			})
			if err != nil {
				writeInternalServerError(w, r, errs.Wrap(err, "database error updating client authentication"), "client_id", client.ID)
				return
			}
			client.RememberConsent = true
		}

		// Either branch has committed its write by here: it is recorded now, before the reads
		// building the answer, whose failure answers 500 but does not undo the change.
		auditLogger.Log(r.Context(), audit.EventUpdatedClientAuthentication, map[string]interface{}{
			"client_id":      client.ID,
			"logged_in_user": callerSubject(r),
		})

		// Load related fields for response consistency
		if err := database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after auth update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after auth update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after auth update"), "client_id", client.ID)
			return
		}

		resp := api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleClientAdministrativeScopesPut - PUT /api/v1/admin/clients/{id}/administrative-scopes
//
// Switches whether the client may request the administrative authserver scopes on a user's behalf,
// and answers the client as it now is. The route admits the clients scopes, and the handler reserves
// the switch to authserver:manage, either way and on any client, because an allowed client is an
// administrator client (#499 decisions 4 and 5).
//
// The admin console's client is always allowed, whatever its row holds, so switching it off is
// refused 400, as renaming it is, rather than stored as a value the server would not apply. The
// request's own 400s and 404 are answered before the ceiling, and the switch is recorded as
// updated_client_administrative_scopes as soon as it is written, before the reads answering it can
// fail (#499 decision 9).
func HandleClientAdministrativeScopesPut(
	database clientsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for administrative scopes update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var req api.UpdateClientAdministrativeScopesRequest
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}
		// Absent or null is refused rather than read as false: a body that says nothing must not
		// switch the allowance off.
		if req.Allowed == nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientAdministrativeScopesAllowedRequired, nil))
			return
		}
		allowed := *req.Allowed

		if client.IsSystemLevelClient() && !allowed {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientAdministrativeScopesConsoleAlwaysAllowed, nil))
			return
		}

		// Only authserver:manage switches the allowance (#499 decision 4).
		if !allowanceCeilingAllows(w, r, auditLogger, client) {
			return
		}

		if err = database.SetClientAdministrativeScopesAllowed(r.Context(), nil, client.ID, allowed); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error updating client administrative scopes allowance"), "client_id", client.ID)
			return
		}

		// The write ran outside any transaction, so it has committed: it is recorded now, before the
		// reads building the answer, whose failure answers 500 but does not undo the switch.
		auditLogger.Log(r.Context(), audit.EventUpdatedClientAdministrativeScopes, map[string]interface{}{
			"client_id":         client.ID,
			"client_identifier": client.ClientIdentifier,
			"allowed":           allowed,
			"logged_in_user":    callerSubject(r),
		})

		// The answer is the row as stored, read back after the write.
		client, err = database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client after administrative scopes update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}
		if err = database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after administrative scopes update"), "client_id", client.ID)
			return
		}
		if err = database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after administrative scopes update"), "client_id", client.ID)
			return
		}
		if err = database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after administrative scopes update"), "client_id", client.ID)
			return
		}

		writeJSON(w, r, http.StatusOK, api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)})
	}
}

// validateClientSecret enforces a strong secret suitable for confidential clients.
func validateClientSecret(secret string) error {
	// Length policy: min 60, max 255
	if len(secret) < 60 || len(secret) > 255 {
		return errs.Errorf("invalid length")
	}
	// Allowed charset: 0-9 a-z A-Z - _ .
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c == '.' {
			continue
		}
		return errs.Errorf("invalid character")
	}
	return nil
}

// HandleClientOAuth2FlowsPut - PUT /api/v1/admin/clients/{id}/oauth2-flows
// Updates which OAuth2 flows are enabled for the client.
func HandleClientOAuth2FlowsPut(
	database clientsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for oauth2 flows update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var req api.UpdateClientOAuth2FlowsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Apply changes with current business rules
		client.AuthorizationCodeEnabled = req.AuthorizationCodeEnabled
		client.ClientCredentialsEnabled = req.ClientCredentialsEnabled
		client.PKCERequired = req.PKCERequired
		client.ImplicitGrantEnabled = req.ImplicitGrantEnabled
		client.ResourceOwnerPasswordCredentialsEnabled = req.ResourceOwnerPasswordCredentialsEnabled

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		// The two public-client rules are applied by the writer below, inside the write's
		// transaction and against the is_public the row really carries. They cannot run out
		// here: this endpoint reloads the client at the top of the request, and a client that
		// became public in between would have its two rules skipped and be saved with client
		// credentials on and PKCE off, which is the state this whole change exists to make
		// unreachable (#245, final review finding 1).
		if err := updateClientNotOwningAuthenticationMode(r.Context(), database, client, nil); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error updating client OAuth2 flows"), "client_id", client.ID)
			return
		}

		// The write's transaction has committed: it is recorded now, before the reads building the
		// answer, whose failure answers 500 but does not undo the change.
		auditLogger.Log(r.Context(), audit.EventUpdatedClientOAuth2Flows, map[string]interface{}{
			"client_id":      client.ID,
			"logged_in_user": callerSubject(r),
		})

		// Load related fields for response consistency
		if err := database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after oauth2 flows update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after oauth2 flows update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after oauth2 flows update"), "client_id", client.ID)
			return
		}

		resp := api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleClientRedirectURIsPut - PUT /api/v1/admin/clients/{id}/redirect-uris
// Replaces the full set of redirect URIs for the client, in one transaction, from a request
// validated and bounded before anything is written, and returns the updated client.
func HandleClientRedirectURIsPut(
	database clientsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for redirect URIs update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// A redirect URI belongs to whichever redirect-based flow the client uses, and implicit
		// is one of them. RFC 6749 section 3.1.2.2 makes registration a MUST for a confidential
		// client using the implicit grant, and RFC 9700 section 4.1.2 notes that control of the
		// redirect URI matters more for implicit rather than less, since the response carries the
		// access token in the fragment. Gating on the authorization code flow alone left an
		// administrator of an implicit-only client unable to add, rotate or urgently remove the
		// one setting that makes it work, without first enabling a flow the client does not use
		// (#250).
		//
		// These two flags are the complete enumeration of redirect-based flows here:
		// protocolvalidation.ResponseTypeInfo.IsImplicitFlow treats any response type containing
		// "code" as not implicit, so nothing outside the pair can produce a redirect.
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		if !client.AuthorizationCodeEnabled && !client.IsImplicitGrantEnabled(settings.ImplicitFlowEnabled) {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientRedirectURIsNoRedirectFlow, nil))
			return
		}

		var req api.UpdateClientRedirectURIsRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// The list as the caller loaded it, required so that no save can silently undo another's
		// change: absent or null decodes to nil and is refused, [] decodes to an empty non-nil
		// slice and means the caller read an empty list (#428).
		if req.ExpectedRedirectURIs == nil {
			writeJSONError(w, "expectedRedirectURIs is required: send the redirect URIs as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}
		expected := expectedURIList(req.ExpectedRedirectURIs)

		normalized, refusal := normalizeURIList(req.RedirectURIs, redirectURIRefusals)
		if refusal != nil {
			writeValidationError(w, r, refusal)
			return
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		redirectURIKey := func(ru record.RedirectURI) string { return strings.TrimSpace(ru.URI) }
		redirectURIID := func(ru record.RedirectURI) int64 { return ru.ID }

		// One transaction, so a failure part way through commits nothing and the 500 is true: an
		// administrator removing a compromised callback and adding its replacement ends with both
		// changes or neither. Written autocommitted, as this was, a failed insert left the
		// removals committed under the error (#264).
		//
		// No row lock: two overlapping saves of one list merge item by item, and a duplicate row
		// the overlap leaves is removed with its original by the next save, since replaceSet
		// deletes every copy of a key. Opened through RunInTransaction, so a deadlock victim is
		// rerun whole (#301). The body is safe to rerun: it reads the stored rows on the
		// transaction and plans from them on every attempt, and writes nothing to the response
		// (#428).
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			if loadErr := database.ClientLoadRedirectURIs(r.Context(), tx, client); loadErr != nil {
				return errs.Wrap(loadErr, "database error loading client redirect URIs before update")
			}
			if !sameSet(client.RedirectURIs, redirectURIKey, expected) {
				return errListChanged
			}

			insert, remove := replaceSet(client.RedirectURIs, redirectURIKey, redirectURIID, normalized)
			for _, rid := range remove {
				if deleteErr := database.DeleteRedirectURI(r.Context(), tx, rid); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting redirect URI %d", rid)
				}
			}
			for _, uri := range insert {
				if createErr := database.CreateRedirectURI(r.Context(), tx, &record.RedirectURI{ClientID: client.ID, URI: uri}); createErr != nil {
					return errs.Wrap(createErr, "database error creating redirect URI")
				}
			}
			return nil
		})
		if err != nil {
			writeListSaveFailure(w, r, err, "client_id", client.ID)
			return
		}

		// Audit, once the save has committed.
		auditLogger.Log(r.Context(), audit.EventUpdatedRedirectURIs, map[string]interface{}{
			"client_id":      client.ID,
			"logged_in_user": callerSubject(r),
		})

		// Reload related fields for response consistency
		if err := database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after redirect URIs update"), "client_id", client.ID)
			return
		}

		resp := api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleClientWebOriginsPut - PUT /api/v1/admin/clients/{id}/web-origins
// Replaces the full set of web origins for the client, in one transaction. Each value is
// canonicalized to the exact string a browser sends in an Origin header, or refused, so a stored
// origin is always one CORS can match.
func HandleClientWebOriginsPut(
	database clientsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for web origins update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// There is deliberately no flow gate here, and the Redirect URIs endpoint next door
		// deliberately has one. The criterion for needing a web origin is "this client's app is
		// JavaScript running in a browser", which no flow flag expresses: an ROPC client calling
		// /auth/token from the browser needs one and enables no redirect-based flow at all.
		// Gating this on the authorization code flow, as it was, refused a legitimate
		// configuration the rest of the server permits, and a registered origin is inert until
		// middleware.CORS reads it, so the gate protected nothing. Restoring consistency with the
		// page next door reintroduces this bug (#250).

		var req api.UpdateClientWebOriginsRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// The list as the caller loaded it, required as it is for redirect URIs: absent or null
		// decodes to nil and is refused, [] means the caller read an empty list (#428).
		if req.ExpectedWebOrigins == nil {
			writeJSONError(w, "expectedWebOrigins is required: send the web origins as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Validate list and entries: non-empty, canonical origin, within the column, no duplicates.
		//
		// urlmatch.CanonicalOrigin is what makes a saved value one CORS can ever match.
		// middleware.CORS compares the stored string to the browser's Origin header byte for
		// byte, and the validation this replaced accepted anything url.ParseRequestURI parsed
		// with an http or https scheme, then stored it verbatim in lower case. Six of ten
		// realistic inputs were accepted and permanently dead, including
		// "https://app.example.com/", which is what copying a URL out of a browser bar
		// produces: 200, the value in the list, and CORS failing with nothing explaining why.
		// Deduplication runs on the canonical form for the same reason, so "https://a.com" and
		// "https://a.com/" collide in one request rather than both being stored (#250).
		seen := make(map[string]struct{})
		normalized := make([]string, 0, len(req.WebOrigins))
		for _, raw := range req.WebOrigins {
			val := strings.TrimSpace(raw)
			if val == "" {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientWebOriginEmpty, nil))
				return
			}
			origin, ok := urlmatch.CanonicalOrigin(val)
			if !ok {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientWebOriginInvalid, map[string]any{"origin": val}))
				return
			}
			// The column's width, record.WebOriginMaxBytes; its comment says why the bound is
			// here rather than in CanonicalOrigin.
			if len(origin) > record.WebOriginMaxBytes {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientWebOriginTooLong, map[string]any{"length": len(origin), "max": record.WebOriginMaxBytes, "origin": origin}))
				return
			}
			if _, exists := seen[origin]; exists {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientWebOriginsDuplicate, nil))
				return
			}
			seen[origin] = struct{}{}
			normalized = append(normalized, origin)
		}

		// The loaded list is compared in the form the rows are stored in, so each value is
		// canonicalized as a wanted one is; one that does not canonicalize can match no stored
		// row and is refused rather than read as an outdated list (#428).
		expected := make([]string, 0, len(req.ExpectedWebOrigins))
		for _, raw := range req.ExpectedWebOrigins {
			origin, ok := urlmatch.CanonicalOrigin(strings.TrimSpace(raw))
			if !ok {
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientWebOriginsExpectedInvalid, map[string]any{"origin": raw}))
				return
			}
			expected = append(expected, origin)
		}

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		// The stored value is already canonical, migration 000034 having repaired the rows
		// written before this endpoint canonicalized, so it is keyed as it stands (#250).
		webOriginKey := func(wo record.WebOrigin) string { return wo.Origin }
		webOriginID := func(wo record.WebOrigin) int64 { return wo.ID }

		// One transaction, so a failure part way through commits nothing and the 500 is true: an
		// administrator removing a compromised origin and adding its replacement ends with both
		// changes or neither (#250).
		//
		// No row lock, as for every list save: two overlapping saves of one list merge item by
		// item. web_origins carries a unique key on (origin, client_id), so when both add the same
		// origin the engine refuses the second insert, its whole save rolls back, and
		// writeListSaveFailure answers it 409 CONCURRENT_UPDATE. This save took AcquireClientRow
		// before its read until #428, which serialized the two instead; the twin redirect-URI save
		// never did, and one pattern for both is the point. Opened through RunInTransaction, so a
		// deadlock victim is rerun whole (#301). The body is safe to rerun: it reads the stored rows
		// on the transaction and plans from them on every attempt, and writes nothing to the
		// response (#428).
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			if loadErr := database.ClientLoadWebOrigins(r.Context(), tx, client); loadErr != nil {
				return errs.Wrap(loadErr, "database error loading client web origins before update")
			}
			if !sameSet(client.WebOrigins, webOriginKey, expected) {
				return errListChanged
			}

			insert, remove := replaceSet(client.WebOrigins, webOriginKey, webOriginID, normalized)
			for _, wid := range remove {
				if deleteErr := database.DeleteWebOrigin(r.Context(), tx, wid); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting web origin %d", wid)
				}
			}
			for _, origin := range insert {
				if createErr := database.CreateWebOrigin(r.Context(), tx, &record.WebOrigin{ClientID: client.ID, Origin: origin}); createErr != nil {
					return errs.Wrapf(createErr, "database error creating web origin %s", origin)
				}
			}
			return nil
		})
		if err != nil {
			writeListSaveFailure(w, r, err, "client_id", client.ID)
			return
		}

		// Audit, once the save has committed.
		auditLogger.Log(r.Context(), audit.EventUpdatedWebOrigins, map[string]interface{}{
			"client_id":      client.ID,
			"logged_in_user": callerSubject(r),
		})

		// Reload related fields for response consistency
		if err := database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after web origins update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after web origins update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after update"), "client_id", client.ID)
			return
		}

		resp := api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// HandleClientTokensPut - PUT /api/v1/admin/clients/{id}/tokens
// Updates token-related settings for a client.
func HandleClientTokensPut(
	database clientsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		if idStr == "" {
			writeJSONError(w, "Client ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid client ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		client, err := database.GetClientByID(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting client by ID for tokens update"), "client_id", id)
			return
		}
		if client == nil {
			writeJSONError(w, "Client not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		var req api.UpdateClientTokensRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate numbers: >= 0 and <= 160000000
		const maxValue = 160000000
		if req.TokenExpirationInSeconds < 0 || req.TokenExpirationInSeconds > maxValue {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientTokensTokenExpirationOutOfRange, map[string]any{"max": maxValue}))
			return
		}
		if req.RefreshTokenOfflineIdleTimeoutInSeconds < 0 || req.RefreshTokenOfflineIdleTimeoutInSeconds > maxValue {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientTokensOfflineIdleTimeoutOutOfRange, map[string]any{"max": maxValue}))
			return
		}
		if req.RefreshTokenOfflineMaxLifetimeInSeconds < 0 || req.RefreshTokenOfflineMaxLifetimeInSeconds > maxValue {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientTokensOfflineMaxLifetimeOutOfRange, map[string]any{"max": maxValue}))
			return
		}
		if req.RefreshTokenOfflineIdleTimeoutInSeconds > req.RefreshTokenOfflineMaxLifetimeInSeconds {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientTokensOfflineIdleTimeoutAboveMaxLifetime, nil))
			return
		}

		// Validate three-state settings. The parsed values are what the columns are written from
		// below, rather than a second independent trim of the same request field: a string that
		// parsed is one of the three the type declares, so String() gives back exactly what was
		// trimmed, and the stored value can no longer drift from the value that was validated
		// (#385).
		includeClaimsInAccessToken, err := record.ThreeStateSettingFromString(strings.TrimSpace(req.IncludeOpenIDConnectClaimsInAccessToken))
		if err != nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientTokensIncludeClaimsInAccessTokenInvalid, nil))
			return
		}
		includeClaimsInIDToken, err := record.ThreeStateSettingFromString(strings.TrimSpace(req.IncludeOpenIDConnectClaimsInIDToken))
		if err != nil {
			writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeClientTokensIncludeClaimsInIDTokenInvalid, nil))
			return
		}

		// Apply updates
		client.TokenExpirationInSeconds = req.TokenExpirationInSeconds
		client.RefreshTokenOfflineIdleTimeoutInSeconds = req.RefreshTokenOfflineIdleTimeoutInSeconds
		client.RefreshTokenOfflineMaxLifetimeInSeconds = req.RefreshTokenOfflineMaxLifetimeInSeconds
		client.IncludeOpenIDConnectClaimsInAccessToken = includeClaimsInAccessToken.String()
		client.IncludeOpenIDConnectClaimsInIDToken = includeClaimsInIDToken.String()

		// Only authserver:manage writes to an administrator client (#402 decision 1).
		if !clientTargetCeilingAllows(w, r, database, auditLogger, client) {
			return
		}

		if err := updateClientNotOwningAuthenticationMode(r.Context(), database, client, nil); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error updating client tokens"), "client_id", client.ID)
			return
		}

		// The write's transaction has committed: it is recorded now, before the reads building the
		// answer, whose failure answers 500 but does not undo the change.
		auditLogger.Log(r.Context(), audit.EventUpdatedClientTokens, map[string]interface{}{
			"client_id":      client.ID,
			"logged_in_user": callerSubject(r),
		})

		// Reload related fields for response consistency
		if err := database.ClientLoadRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client redirect URIs after tokens update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadPostLogoutRedirectURIs(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client sign-out redirect URIs after tokens update"), "client_id", client.ID)
			return
		}
		if err := database.ClientLoadWebOrigins(r.Context(), nil, client); err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading client web origins after tokens update"), "client_id", client.ID)
			return
		}

		resp := api.UpdateClientResponse{Client: *apimapping.ToClientResponse(client)}
		writeJSON(w, r, http.StatusOK, resp)
	}
}

// clientURLRefusals names the refusals of one of a client's optional URLs, so each answers with its
// own field's catalog key, which the console reads the field off (#617).
type clientURLRefusals struct {
	tooLong, invalid, schemeInvalid string
}

var (
	clientWebsiteURLRefusals = clientURLRefusals{i18n.ErrCodeClientWebsiteURLTooLong,
		i18n.ErrCodeClientWebsiteURLInvalid, i18n.ErrCodeClientWebsiteURLSchemeInvalid}
	clientPrivacyPolicyURLRefusals = clientURLRefusals{i18n.ErrCodeClientPrivacyPolicyURLTooLong,
		i18n.ErrCodeClientPrivacyPolicyURLInvalid, i18n.ErrCodeClientPrivacyPolicyURLSchemeInvalid}
	clientTermsOfServiceURLRefusals = clientURLRefusals{i18n.ErrCodeClientTermsOfServiceURLTooLong,
		i18n.ErrCodeClientTermsOfServiceURLInvalid, i18n.ErrCodeClientTermsOfServiceURLSchemeInvalid}
)

// clientURLMaxLength is the bound of a client's website, privacy policy and terms of service URLs,
// in inputvalidation.TextLength's characters: their columns' width.
const clientURLMaxLength = 256

// validateOptionalClientURL trims one of a client's optional URLs and returns it, empty when none was
// sent, or the refusal of a value longer than clientURLMaxLength, one that does not parse, or one
// whose scheme is not http or https.
func validateOptionalClientURL(value string, refusals clientURLRefusals) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", nil
	}
	if inputvalidation.TextLength(trimmed) > clientURLMaxLength {
		return "", i18n.NewLocalizedError(refusals.tooLong, map[string]any{"max": clientURLMaxLength})
	}
	parsed, err := url.ParseRequestURI(trimmed)
	if err != nil {
		return "", i18n.NewLocalizedError(refusals.invalid, nil)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", i18n.NewLocalizedError(refusals.schemeInvalid, nil)
	}
	return trimmed, nil
}
