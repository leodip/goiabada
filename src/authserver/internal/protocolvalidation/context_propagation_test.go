package protocolvalidation

import (
	"context"
	"testing"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the two protocol validators, and thin for the reason section 5 gives: what a
// consumer can show is only that the context it handed its port was its CALLER's. The engine
// behaviour belongs to the data tier and the retry loop to the scripted driver.
//
// These two validators are not handlers, so there is no r.Context() to compare against. The
// caller's context carries a chi request id instead, which is on this context and on no other, so
// a validator that resolved a scope under context.Background() matches nothing and the strict mock
// reports an unexpected call.
//
// The shape is worth a case of its own because permissions.ResolveScope is where the context has
// furthest to travel from this package: ValidateScopes takes it, hands it to the resolver it shares
// with the token endpoint, and that function makes two reads.

const propagatedRequestId = "goiabada/req-validation-propagation-1"

func aCallersContext() context.Context {
	return context.WithValue(context.Background(), chimiddleware.RequestIDKey, propagatedRequestId)
}

func theCallersContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return chimiddleware.GetReqID(ctx) == propagatedRequestId
	})
}

// The accept arm: both of permissions.ResolveScope's reads -- the resource and the permissions on
// it -- are issued on behalf of the caller that asked for the validation.
func TestValidateScopes_ResolvesUnderTheCallersContext(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	mockDB.On("GetResourceByResourceIdentifier", theCallersContext(), mock.Anything, "billing-api").
		Return(&models.Resource{Id: 9, ResourceIdentifier: "billing-api"}, nil).Once()
	mockDB.On("GetPermissionsByResourceId", theCallersContext(), mock.Anything, int64(9)).
		Return([]models.Permission{{Id: 21, PermissionIdentifier: "read", ResourceId: 9}}, nil).Once()

	err := NewAuthorizeValidator(mockDB).ValidateScopes(aCallersContext(), "billing-api:read")

	require.NoError(t, err)
	mockDB.AssertExpectations(t)
}

// The reject arm: a scope that is not in resource:permission form is refused by the shape check
// inside permissions.ResolveScope, before either read, so no database port is reached at all and
// there is no context to get wrong.
func TestValidateScopes_AMalformedScopeReachesNoDatabasePort(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	err := NewAuthorizeValidator(mockDB).ValidateScopes(aCallersContext(), "not-a-qualified-scope")

	require.Error(t, err)
	mockDB.AssertNotCalled(t, "GetResourceByResourceIdentifier", mock.Anything, mock.Anything, mock.Anything)
	mockDB.AssertNotCalled(t, "GetPermissionsByResourceId", mock.Anything, mock.Anything, mock.Anything)
}

// The client half of the same claim, and the loader is the part worth pinning: the client read is
// one hop, but ClientLoadRedirectURIs reaches the database a second time inside commondb, which is
// the shape that would keep compiling with a context.Background() under it.
func TestValidateClientAndRedirectURI_ReadsTheClientUnderTheCallersContext(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	client := &models.Client{Id: 5, ClientIdentifier: "portal", Enabled: true, AuthorizationCodeEnabled: true}

	mockDB.On("GetClientByClientIdentifier", theCallersContext(), mock.Anything, "portal").
		Return(client, nil).Once()
	mockDB.On("ClientLoadRedirectURIs", theCallersContext(), mock.Anything, client).
		Run(func(args mock.Arguments) {
			args.Get(2).(*models.Client).RedirectURIs = []models.RedirectURI{{URI: "https://example.com/callback"}}
		}).Return(nil).Once()

	err := NewAuthorizeValidator(mockDB).ValidateClientAndRedirectURI(aCallersContext(),
		&ValidateClientAndRedirectURIInput{
			ClientId:    "portal",
			RedirectURI: "https://example.com/callback",
		})

	require.NoError(t, err)
	mockDB.AssertExpectations(t)
}

// The reject arm for the client half: an empty client_id is refused before the lookup, so the
// client port is never reached.
func TestValidateClientAndRedirectURI_AnEmptyClientIdReachesNoClientPort(t *testing.T) {
	mockDB := mocks_data.NewDatabase(t)

	err := NewAuthorizeValidator(mockDB).ValidateClientAndRedirectURI(aCallersContext(),
		&ValidateClientAndRedirectURIInput{
			ClientId:    "",
			RedirectURI: "https://example.com/callback",
		})

	require.Error(t, err)
	mockDB.AssertNotCalled(t, "GetClientByClientIdentifier", mock.Anything, mock.Anything, mock.Anything)
	mockDB.AssertNotCalled(t, "ClientLoadRedirectURIs", mock.Anything, mock.Anything, mock.Anything)
}
