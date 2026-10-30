package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A client listed for the authserver resource's tokens introspects every sign-in, which only
// authserver:manage may hand a client (#676 decision 14). Reading its secret or setting a new one
// is authenticating as it, so the credentials ceiling holds both to authserver:manage too, and
// leaves every other write to it with authserver:manage-clients.

// otherIntrospectedResourceId is a resource other than authserver a client may be listed for.
const otherIntrospectedResourceId = int64(77)

// expectIntrospectionResources registers the credentials ceiling's read of the target client's
// introspection resources, outside any transaction, and of the authserver resource when the list
// is not empty.
func expectIntrospectionResources(database *datamocks.Database, resourceIds ...int64) {
	links := make([]record.ClientIntrospectionResource, 0, len(resourceIds))
	for _, resourceId := range resourceIds {
		links = append(links, record.ClientIntrospectionResource{ClientId: targetClientId, ResourceId: resourceId})
	}
	database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, (*sql.Tx)(nil), targetClientId).
		Return(links, nil).Once()
	if len(links) > 0 {
		database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "authserver").
			Return(&record.Resource{Id: ceilingResourceId, ResourceIdentifier: "authserver"}, nil).Once()
	}
}

func credentialsWrites() []clientTargetWrite {
	var writes []clientTargetWrite
	for _, write := range clientTargetWrites {
		if write.credentials {
			writes = append(writes, write)
		}
	}
	return writes
}

func TestClientCredentialsCeiling_AGranularTokenIsRefusedTheSecretOfAnAuthServerIntrospector(t *testing.T) {
	writes := credentialsWrites()
	require.Len(t, writes, 2, "the secret read and the secret rotation")
	for _, write := range writes {
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			expectIntrospectionResources(database, otherIntrospectedResourceId, ceilingResourceId)

			rr, records := serveClientCase(t, clientTargetCase{write, ordinaryClient}, granularScopeOfClients, database, auditLogger)

			status := rr.Code
			assert.NotContains(t, rr.Body.String(), targetClientSecret, "the refusal discloses no secret")
			code, description := decodeErrorEnvelope(t, rr)
			assertManageScopeRequired(t, rr, status, code, description)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, write.writes...)

			require.Len(t, *records, 1, "one record per refused request, and no viewed_client_secret")
			refusal := (*records)[0]
			assert.Equal(t, audit.EventAdministratorChangeRefused, refusal.event)
			assert.Equal(t, grantCaller, refusal.details["logged_in_user"])
			assert.Equal(t, "target", refusal.details["ceiling"])
			assert.Equal(t, "client", refusal.details["target_kind"])
			assert.Equal(t, targetClientId, refusal.details["target_id"])
		})
	}
}

// A client listed only for other resources' tokens introspects nothing of the auth server's, so its
// secret stays authserver:manage-clients'.
func TestClientCredentialsCeiling_AnotherResourcesIntrospectorProceeds(t *testing.T) {
	for _, write := range credentialsWrites() {
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			if write.expectFirstWrite != nil {
				write.expectFirstWrite(database)
			}
			expectIntrospectionResources(database, otherIntrospectedResourceId)

			rr, records := serveClientCase(t, clientTargetCase{write, ordinaryClient}, granularScopeOfClients, database, auditLogger)

			assertReachedPastTheCeiling(t, write, rr, records)
			database.AssertExpectations(t)
		})
	}
}

// Only the secret is held. Every other write to an authserver introspector stays with
// authserver:manage-clients, and so does making it public, which clears its list, so that a granular
// token can still take the reach away as it can remove authserver from the list. None of them reads
// the list: the strict mock refuses the read.
func TestClientCredentialsCeiling_EveryOtherWriteToAnAuthServerIntrospectorProceeds(t *testing.T) {
	for _, write := range clientTargetWrites {
		if write.credentials {
			continue
		}
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			if write.expectFirstWrite != nil {
				write.expectFirstWrite(database)
			}

			rr, records := serveClientCase(t, clientTargetCase{write, ordinaryClient}, granularScopeOfClients, database, auditLogger)

			assertReachedPastTheCeiling(t, write, rr, records)
			database.AssertExpectations(t)
		})
	}
}

// An authserver:manage caller reads and sets an authserver introspector's secret, reading nothing
// for the ceiling.
func TestClientCredentialsCeiling_AManageTokenReadsNothingForIt(t *testing.T) {
	for _, write := range credentialsWrites() {
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			if write.expectFirstWrite != nil {
				write.expectFirstWrite(database)
			}

			rr, records := serveClientCase(t, clientTargetCase{write, clientHolding{name: "manage", identifier: "target-client", readsNothing: true}},
				"authserver:manage", database, auditLogger)

			assertReachedPastTheCeiling(t, write, rr, records)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, "GetClientIntrospectionResourcesByClientId")
		})
	}
}

// A ceiling that could not read the list is one 500, with no write, no secret and no record.
func TestClientCredentialsCeiling_AFailedListReadIsOneFiveHundred(t *testing.T) {
	for _, write := range credentialsWrites() {
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			client := targetClient(t, ordinaryClient)
			expectTheTargetClient(client)(database)
			expectClientHolding(database, ordinaryClient)
			database.On("GetClientIntrospectionResourcesByClientId", mock.Anything, (*sql.Tx)(nil), targetClientId).
				Return(nil, errors.New("the read failed")).Once()

			rr := write.serve(t, database, auditLogger, granularScopeOfClients, client)

			assert.Equal(t, http.StatusInternalServerError, rr.Code)
			assert.Equal(t, 1, strings.Count(rr.Body.String(), "INTERNAL_SERVER_ERROR"), "exactly one error response")
			assert.NotContains(t, rr.Body.String(), targetClientSecret)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, write.writes...)
			auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
		})
	}
}
