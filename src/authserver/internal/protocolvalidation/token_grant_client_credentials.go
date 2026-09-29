package protocolvalidation

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/oidc"
	"github.com/leodip/goiabada/authserver/internal/permissions"
	"github.com/leodip/goiabada/core/customerrors"
)

// ClientCredentialsGrant is a validated client credentials request: the authenticated client and
// the scope it is granted, which is every permission it holds when the request named none.
type ClientCredentialsGrant struct {
	Client *models.Client
	Scope  string
}

func (*ClientCredentialsGrant) GrantType() oidc.GrantType { return oidc.GrantTypeClientCredentials }

// validateClientCredentialsGrant validates a client credentials request (RFC 6749 section 4.4.2)
// for a client ValidateTokenRequest has already found and found enabled.
func (val *TokenValidator) validateClientCredentialsGrant(ctx context.Context, client *models.Client,
	input *ValidateTokenRequestInput) (*ClientCredentialsGrant, error) {
	if !client.ClientCredentialsEnabled {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
			"The client associated with the provided client_id does not support client credentials flow.",
			http.StatusBadRequest)
	}

	if client.IsPublic {
		return nil, customerrors.NewErrorDetailWithHttpStatusCode("unauthorized_client",
			"A public client is not eligible for the client credentials flow. Please review the client configuration.",
			http.StatusBadRequest)
	}

	err := val.authenticateClient(client, input.ClientSecret, input.UsedBasicAuth, wrongClientSecretShortErrorMsg)
	if err != nil {
		return nil, err
	}

	err = val.database.ClientLoadPermissions(ctx, nil, client)
	if err != nil {
		return nil, err
	}

	err = val.database.PermissionsLoadResources(ctx, nil, client.Permissions)
	if err != nil {
		return nil, err
	}

	if len(input.Scope) == 0 {
		// No scope was passed, so grant every permission the client holds.
		//
		// perm.Resource is already populated: PermissionsLoadResources ran immediately above.
		// This used to call GetResourceByResourceIdentifier(nil, perm.Resource.ResourceIdentifier)
		// and then use res.ResourceIdentifier, the very string it had just passed in, which was
		// one database round-trip per granted permission per request for a value already in hand.
		//
		// No empty-identifier guard on perm.Resource, deliberately, and NOT because the state is
		// unreachable. Resource is a value field, so there is no nil to check; a map miss in
		// PermissionsLoadResources silently leaves it zero-valued, with ResourceIdentifier == "".
		//
		// That state IS reachable. The two loads above are separate non-transactional queries,
		// so a resource deleted between them leaves this loop holding permission rows that the
		// database has already cascade-deleted, and GetResourcesByIds finds nothing for them.
		// ON DELETE CASCADE does not help: the cascade happens in the database while these rows
		// are already in memory.
		//
		// No guard is needed because the path fails closed. A zero-valued resource yields the
		// scope ":<permission>", which validateClientCredentialsScopes below rejects with
		// invalid_scope, "Could not find a resource with identifier ''". Verified by executing
		// that fixture: a 400 naming the problem, which is the right outcome for a request whose
		// grant vanished mid-flight.
		//
		// The old code did NOT fail closed here: it passed that empty identifier to
		// GetResourceByResourceIdentifier, got nil back, and dereferenced it. Also verified by
		// execution, which panics with a nil pointer dereference. Removing the round-trip removed
		// a latent panic in that race, not merely a wasted query.
		//
		// Note the scopes built here are resource-qualified, which matters more since the
		// ownership check became resource-scoped: a client holding "read" on two resources gets
		// both "a:read" and "b:read", not one of them twice.
		for _, perm := range client.Permissions {
			input.Scope = input.Scope + " " + perm.Resource.ResourceIdentifier + ":" + perm.PermissionIdentifier
		}
		input.Scope = strings.TrimSpace(input.Scope)
	}

	err = val.validateClientCredentialsScopes(ctx, input.Scope, client)
	if err != nil {
		return nil, err
	}

	return &ClientCredentialsGrant{
		Client: client,
		Scope:  input.Scope,
	}, nil
}

func (val *TokenValidator) validateClientCredentialsScopes(ctx context.Context, scope string, client *models.Client) error {

	if len(scope) == 0 {
		return nil
	}

	for _, scopeStr := range oidc.SplitScope(scope) {

		if oidc.IsClaimScope(scopeStr) || oidc.IsOfflineAccessScope(scopeStr) {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_request",
				fmt.Sprintf("Id token scopes (such as '%v') are not supported in the client credentials flow. Please use scopes in the format 'resource:permission' (e.g., 'backendA:read'). Multiple scopes can be specified, separated by spaces.", scopeStr),
				http.StatusBadRequest)
		}

		resolution, err := permissions.ResolveScope(ctx, val.database, scopeStr)
		if err != nil {
			return err
		}

		switch resolution.Outcome {
		case permissions.ScopeMalformed:
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope format: '%v'. Scopes must adhere to the resource-identifier:permission-identifier format. For instance: backend-service:create-product.", scopeStr),
				http.StatusBadRequest)
		case permissions.ScopeResourceUnknown:
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Invalid scope: '%v'. Could not find a resource with identifier '%v'.", scopeStr, resolution.ResourceIdentifier),
				http.StatusBadRequest)
		case permissions.ScopePermissionUnknown:
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Scope '%v' is not recognized. The resource identified by '%v' doesn't grant the '%v' permission.", scopeStr, resolution.ResourceIdentifier, resolution.PermissionIdentifier),
				http.StatusBadRequest)
		}

		// Ownership is decided here and not by the resolver: permissions.ResolveScope answers
		// whether the permission exists on the requested resource, "is it this client's?" is this
		// grant's own rule and ROPC answers the same question against the user instead.
		//
		// Compare the resource-scoped permission id, never the bare identifier.
		// client.Permissions is loaded by ClientLoadPermissions across EVERY resource, so a
		// bare identifier comparison here matched any permission the client held anywhere: a
		// client granted "billing-api:read" was handed "reports-api:read", and one granted
		// "<custom>:manage" was handed "authserver:manage" and with it the whole Admin
		// API (#104).
		clientHasPermission := false
		for _, perm := range client.Permissions {
			if perm.Id == resolution.Permission.Id {
				clientHasPermission = true
				break
			}
		}

		if !clientHasPermission {
			return customerrors.NewErrorDetailWithHttpStatusCode("invalid_scope",
				fmt.Sprintf("Permission to access scope '%v' is not granted to the client.", scopeStr),
				http.StatusBadRequest)
		}
	}
	return nil
}
