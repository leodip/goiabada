package apihandlers

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/inputvalidation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The target ceiling on clients: a client holding an administrative permission is an administrator,
// and so is the admin console's own client, whatever it holds. Only an authserver:manage token
// writes to one in any way, or reads its secret. A granular token is refused 403
// MANAGE_SCOPE_REQUIRED after the request's own 400 and 404 answers and before any write, with one
// administrator_change_refused record under ceiling "target" naming the client, and keeps full
// control of every client that is not an administrator (#402 decisions 1, 2, 4, 5 and 8).

const (
	targetClientId = int64(58)
	// targetClientSecret is the plaintext the target client's sealed secret opens to.
	targetClientSecret = "the-target-client-secret"
)

// clientHolding is what a target client is, as the policy reads it: its identifier and its grants.
type clientHolding struct {
	name       string
	identifier string
	grants     []int64
	// administrator is what the holding makes the client, written out rather than derived.
	administrator bool
	// readsNothing says the policy decides this client without reading its grants.
	readsNothing bool
}

var (
	clientHoldingManage = clientHolding{
		name:          "a client holding manage",
		identifier:    "target-client",
		grants:        []int64{6, permManage},
		administrator: true,
	}
	clientHoldingBrowserSessions = clientHolding{
		name:          "a client holding browser-sessions",
		identifier:    "target-client",
		grants:        []int64{permCustomOnAuthServer, permBrowserSessions},
		administrator: true,
	}
	// The admin console's own client is an administrator by what it is: it is the client every
	// administrator signs in through, so holding nothing makes it no less one.
	theConsoleClient = clientHolding{
		name:          "the admin console's own client holding nothing",
		identifier:    "admin-console-client",
		administrator: true,
		readsNothing:  true,
	}
	ordinaryClient = clientHolding{
		name:       "an ordinary client",
		identifier: "target-client",
		grants:     []int64{6, permManageAccount, permCustomOnAuthServer},
	}
)

// targetClient is the client GetClientById answers for a holding: confidential, with the code and
// client credentials flows on, so that every write's own validation lets it through.
func targetClient(t *testing.T, holding clientHolding) *record.Client {
	t.Helper()
	sealed, err := testDataCipher.Encrypt(targetClientSecret)
	require.NoError(t, err)
	return &record.Client{
		Id:                       targetClientId,
		ClientIdentifier:         holding.identifier,
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ClientCredentialsEnabled: true,
		ClientSecretEncrypted:    sealed,
	}
}

// expectClientHolding registers the policy's reads of what the target client holds, outside any
// transaction: its grants and, when it holds any, the administrative set.
func expectClientHolding(database *datamocks.Database, holding clientHolding) {
	if holding.readsNothing {
		return
	}
	var grants []record.ClientPermission
	for _, permissionId := range holding.grants {
		grants = append(grants, record.ClientPermission{ClientId: targetClientId, PermissionId: permissionId})
	}
	database.On("GetClientPermissionsByClientId", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(grants, nil).Once()
	if len(grants) > 0 {
		expectAuthServerPermissions(database)
	}
}

// clientTargetWrite is one of the client routes the target ceiling guards.
type clientTargetWrite struct {
	name string
	// serve runs the route against client, as a caller holding scope, or no validated token when
	// scope is empty.
	serve func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder
	// expectReads registers the reads the route makes before the target ceiling judges it,
	// including what the grant ceiling reads ahead of it.
	expectReads func(database *datamocks.Database)
	// writes is every write the route makes, none of which a refusal may reach.
	writes []string
	// expectFirstWrite registers the route's first write past the ceiling, failing, so a route the
	// ceiling lets through ends in one 500 there. Nil for the secret read, which writes nothing.
	expectFirstWrite func(database *datamocks.Database)
	// refusedEarlierForTheConsoleClient says the route answers the admin console's own client 400
	// before the ceiling, as deleting a system-level client does.
	refusedEarlierForTheConsoleClient bool
}

// clientRequest builds a request for one of the routes, with chi's id parameter set.
func clientRequest(method, target, body, scope string) *http.Request {
	return membershipRequest(method, target, body, scope, map[string]string{"id": "58"})
}

func expectTheTargetClient(client *record.Client) func(database *datamocks.Database) {
	return func(database *datamocks.Database) {
		database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(client, nil).Once()
	}
}

var clientTargetWrites = []clientTargetWrite{
	{
		name: "PUT /clients/{id}",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58",
				`{"clientIdentifier":"`+client.ClientIdentifier+`","description":"changed","enabled":true}`, scope)
			rr := httptest.NewRecorder()
			HandleClientUpdatePut(database, inputvalidation.NewIdentifierValidator(), auditLogger).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"RunInTransaction", "UpdateClient"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /clients/{id}/authentication",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/authentication", `{"isPublic":true}`, scope)
			rr := httptest.NewRecorder()
			HandleClientAuthenticationPut(database, auditLogger, testDataCipher).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"RunInTransaction", "SetClientPublic", "UpdateClient"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /clients/{id}/authentication rotating the secret",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/authentication",
				`{"isPublic":false,"clientSecret":"`+strings.Repeat("s", 60)+`"}`, scope)
			rr := httptest.NewRecorder()
			HandleClientAuthenticationPut(database, auditLogger, testDataCipher).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"RunInTransaction", "SetClientPublic", "UpdateClient"},
		expectFirstWrite: failingWrite("UpdateClient", mock.Anything, (*sql.Tx)(nil), mock.Anything),
	},
	{
		name: "PUT /clients/{id}/oauth2-flows",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/oauth2-flows",
				`{"authorizationCodeEnabled":true,"clientCredentialsEnabled":true}`, scope)
			rr := httptest.NewRecorder()
			HandleClientOAuth2FlowsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"RunInTransaction", "UpdateClient"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /clients/{id}/redirect-uris",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/redirect-uris",
				`{"redirectURIs":["https://attacker.example/cb"],"expectedRedirectURIs":[]}`, scope)
			r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{}))
			rr := httptest.NewRecorder()
			HandleClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"RunInTransaction", "CreateRedirectURI", "DeleteRedirectURI"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /clients/{id}/web-origins",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/web-origins",
				`{"webOrigins":["https://attacker.example"],"expectedWebOrigins":[]}`, scope)
			rr := httptest.NewRecorder()
			HandleClientWebOriginsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"RunInTransaction", "CreateWebOrigin", "DeleteWebOrigin"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /clients/{id}/tokens",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/tokens",
				`{"tokenExpirationInSeconds":160000000,"includeOpenIDConnectClaimsInAccessToken":"on","includeOpenIDConnectClaimsInIdToken":"default"}`, scope)
			rr := httptest.NewRecorder()
			HandleClientTokensPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"RunInTransaction", "UpdateClient"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "PUT /clients/{id}/permissions",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/permissions", `{"permissionIds":[],"expectedPermissionIds":[]}`, scope)
			rr := httptest.NewRecorder()
			HandleClientPermissionsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"RunInTransaction", "CreateClientPermission", "DeleteClientPermission"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		// The grant ceiling lets an ordinary permission through; the target ceiling judges whom it
		// is granted to.
		name: "PUT /clients/{id}/permissions granting an ordinary permission",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/permissions", `{"permissionIds":[5],"expectedPermissionIds":[]}`, scope)
			rr := httptest.NewRecorder()
			HandleClientPermissionsPut(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		expectReads: func(database *datamocks.Database) {
			expectPermissionsExist(database, 5)
			expectAuthServerPermissions(database)
		},
		writes:           []string{"RunInTransaction", "CreateClientPermission", "DeleteClientPermission"},
		expectFirstWrite: failingWrite("RunInTransaction", mock.Anything, mock.Anything),
	},
	{
		name: "DELETE /clients/{id}",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodDelete, "/api/v1/admin/clients/58", "", scope)
			rr := httptest.NewRecorder()
			HandleClientDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		writes:                            []string{"DeleteClient"},
		expectFirstWrite:                  failingWrite("DeleteClient", mock.Anything, (*sql.Tx)(nil), targetClientId),
		refusedEarlierForTheConsoleClient: true,
	},
	{
		name: "POST /clients/{id}/logo",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r, err := createMultipartRequest(http.MethodPost, "/api/v1/admin/clients/58/logo", "picture", createTestPNG(100, 100))
			require.NoError(t, err)
			r = setChiURLParam(r, "id", "58")
			if scope != "" {
				r = setTokenContextWithClaims(r, map[string]interface{}{"scope": scope, "sub": grantCaller})
			}
			rr := httptest.NewRecorder()
			HandleClientLogoPost(database, auditLogger, testBaseURL, testMaxUploadBytes).ServeHTTP(rr, r)
			return rr
		},
		writes: []string{"CreateClientLogo", "UpdateClientLogo"},
		expectFirstWrite: func(database *datamocks.Database) {
			database.On("GetClientLogoByClientId", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(nil, nil).Once()
			database.On("CreateClientLogo", mock.Anything, (*sql.Tx)(nil), mock.Anything).Return(errFirstWriteFails).Once()
		},
	},
	{
		name: "DELETE /clients/{id}/logo",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodDelete, "/api/v1/admin/clients/58/logo", "", scope)
			rr := httptest.NewRecorder()
			HandleClientLogoDelete(database, auditLogger).ServeHTTP(rr, r)
			return rr
		},
		writes:           []string{"DeleteClientLogo"},
		expectFirstWrite: failingWrite("DeleteClientLogo", mock.Anything, (*sql.Tx)(nil), targetClientId),
	},
	{
		// Reading an administrator client's secret is signing in as it (#402 decision 8).
		name: "GET /clients/{id}/secret",
		serve: func(t *testing.T, database *datamocks.Database, auditLogger *handlersmocks.AuditLogger, scope string, client *record.Client) *httptest.ResponseRecorder {
			r := clientRequest(http.MethodGet, "/api/v1/admin/clients/58/secret", "", scope)
			rr := httptest.NewRecorder()
			HandleClientSecretGet(database, auditLogger, testDataCipher).ServeHTTP(rr, r)
			return rr
		},
	},
}

// clientTargetCase is one route against one holding of its target.
type clientTargetCase struct {
	write   clientTargetWrite
	holding clientHolding
}

func (c clientTargetCase) name() string { return c.write.name + "/" + c.holding.name }

// administratorClientTargets is every route against each administrator holding, but for a route
// answering the admin console's own client before the ceiling.
func administratorClientTargets() []clientTargetCase {
	var cases []clientTargetCase
	for _, write := range clientTargetWrites {
		for _, holding := range []clientHolding{clientHoldingManage, clientHoldingBrowserSessions, theConsoleClient} {
			if holding.readsNothing && write.refusedEarlierForTheConsoleClient {
				continue
			}
			cases = append(cases, clientTargetCase{write, holding})
		}
	}
	return cases
}

// granularScopeOfClients is the granular write scope every client route admits.
const granularScopeOfClients = "authserver:manage-clients"

// serveClientCase runs one case's route with its reads registered, and the records it logged, if
// any: a route that fails past the ceiling logs none.
func serveClientCase(t *testing.T, c clientTargetCase, scope string, database *datamocks.Database,
	auditLogger *handlersmocks.AuditLogger) (*httptest.ResponseRecorder, *[]loggedEvent) {
	t.Helper()
	client := targetClient(t, c.holding)
	expectTheTargetClient(client)(database)
	if c.write.expectReads != nil {
		c.write.expectReads(database)
	}
	expectClientHolding(database, c.holding)
	records := &[]loggedEvent{}
	auditLogger.On("Log", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			*records = append(*records, loggedEvent{event: args.String(1), details: args.Get(2).(map[string]interface{})})
		}).Return().Maybe()
	return c.write.serve(t, database, auditLogger, scope, client), records
}

func TestClientTargetCeiling_AGranularTokenWritingToAnAdministratorClientIsRefused(t *testing.T) {
	for _, c := range administratorClientTargets() {
		t.Run(c.name(), func(t *testing.T) {
			require.True(t, c.holding.administrator)
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)

			rr, records := serveClientCase(t, c, granularScopeOfClients, database, auditLogger)

			status := rr.Code
			assert.NotContains(t, rr.Body.String(), targetClientSecret, "the refusal discloses no secret")
			code, description := decodeErrorEnvelope(t, rr)
			assertManageScopeRequired(t, rr, status, code, description)
			database.AssertExpectations(t)
			assertNotAttemptedOnClientDatabase(t, database, c.write.writes...)

			require.Len(t, *records, 1, "one record per refused request, and no viewed_client_secret")
			refusal := (*records)[0]
			assert.Equal(t, audit.EventAdministratorChangeRefused, refusal.event)
			assert.Equal(t, grantCaller, refusal.details["loggedInUser"])
			assert.Contains(t, refusal.details, "method")
			assert.Contains(t, refusal.details, "route")
			assert.Equal(t, "target", refusal.details["ceiling"])
			assert.Equal(t, "client", refusal.details["targetKind"])
			assert.Equal(t, targetClientId, refusal.details["targetId"])
			assert.NotContains(t, refusal.details, "permissionIds", "a target refusal names the target, not permissions")
		})
	}
}

// Every token below authserver:manage is held to the ceiling, and so is a request that reached the
// handler with no validated token at all: the policy fails closed.
func TestClientTargetCeiling_EveryOtherCallerIsHeldToIt(t *testing.T) {
	callers := []struct {
		name  string
		scope string
	}{
		{name: "admin-read", scope: "authserver:admin-read"},
		{name: "every granular scope", scope: "authserver:manage-users authserver:manage-clients authserver:manage-settings authserver:browser-sessions"},
		{name: "a scope that only resembles manage", scope: "authserver:manage-account other:manage"},
		{name: "no validated token", scope: ""},
	}

	for _, c := range administratorClientTargets() {
		for _, caller := range callers {
			t.Run(c.name()+"/"+caller.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)

				rr, records := serveClientCase(t, c, caller.scope, database, auditLogger)

				status := rr.Code
				code, description := decodeErrorEnvelope(t, rr)
				assertManageScopeRequired(t, rr, status, code, description)
				assertNotAttemptedOnClientDatabase(t, database, c.write.writes...)
				require.Len(t, *records, 1)
				assert.Equal(t, audit.EventAdministratorChangeRefused, (*records)[0].event)
				assert.Equal(t, "target", (*records)[0].details["ceiling"])
			})
		}
	}
}

// assertReachedPastTheCeiling holds a response to the route having gone on past the ceiling: a
// write's failing first write answered 500, and the secret read answered the secret.
func assertReachedPastTheCeiling(t *testing.T, write clientTargetWrite, rr *httptest.ResponseRecorder, records *[]loggedEvent) {
	t.Helper()
	assert.Empty(t, rr.Header().Get("WWW-Authenticate"))
	for _, logged := range *records {
		assert.NotEqual(t, audit.EventAdministratorChangeRefused, logged.event)
	}
	if write.expectFirstWrite == nil {
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		assert.JSONEq(t, `{"clientSecret":"`+targetClientSecret+`"}`, rr.Body.String())
		require.Len(t, *records, 1)
		assert.Equal(t, audit.EventViewedClientSecret, (*records)[0].event)
		return
	}
	assert.Equal(t, http.StatusInternalServerError, rr.Code, "the write past the ceiling was reached: %s", rr.Body.String())
}

// A granular token keeps writing to every client that is not an administrator, and reading its
// secret: holding manage-account, a custom authserver permission and a permission of another
// resource makes no client an administrator.
func TestClientTargetCeiling_AGranularTokenWritingToAnOrdinaryClientProceeds(t *testing.T) {
	for _, write := range clientTargetWrites {
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

// An authserver:manage caller writes to administrator clients, the admin console's own included,
// and reads nothing for the target ceiling: whatever the client holds, its token already carries
// every authority.
func TestClientTargetCeiling_AManageTokenWritesToAdministratorClientsAndReadsNothingForIt(t *testing.T) {
	for _, write := range clientTargetWrites {
		for _, holding := range []clientHolding{clientHoldingManage, theConsoleClient} {
			if holding.readsNothing && write.refusedEarlierForTheConsoleClient {
				continue
			}
			t.Run(write.name+"/"+holding.name, func(t *testing.T) {
				database := datamocks.NewDatabase(t)
				auditLogger := handlersmocks.NewAuditLogger(t)
				if write.expectFirstWrite != nil {
					write.expectFirstWrite(database)
				}

				rr, records := serveClientCase(t, clientTargetCase{write, clientHolding{name: holding.name, identifier: holding.identifier, readsNothing: true}},
					"authserver:manage", database, auditLogger)

				assertReachedPastTheCeiling(t, write, rr, records)
				database.AssertExpectations(t)
				for _, call := range database.Calls {
					if call.Method == "GetClientPermissionsByClientId" && call.Arguments.Get(1) == (*sql.Tx)(nil) {
						t.Errorf("the client's permissions were read for the target ceiling")
					}
				}
			})
		}
	}
}

// The policy failing to read what the client holds is one 500, with no write, no secret and no
// record: a route the policy could not judge is not let through.
func TestClientTargetCeiling_AFailedPolicyReadIsOneFiveHundred(t *testing.T) {
	for _, write := range clientTargetWrites {
		t.Run(write.name, func(t *testing.T) {
			database := datamocks.NewDatabase(t)
			auditLogger := handlersmocks.NewAuditLogger(t)
			client := targetClient(t, ordinaryClient)
			expectTheTargetClient(client)(database)
			if write.expectReads != nil {
				write.expectReads(database)
			}
			database.On("GetClientPermissionsByClientId", mock.Anything, (*sql.Tx)(nil), targetClientId).
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

// The refusal comes after the request's 404 and 400 answers: a client that does not exist and a body
// the route refuses are answered as before, with nothing read for the policy and nothing audited.
func TestClientTargetCeiling_TheRoutesAnswerTheirOwnFourHundredsFirst(t *testing.T) {
	assertNoClientPolicyRead := func(t *testing.T, database *datamocks.Database) {
		t.Helper()
		assertNotAttemptedOnClientDatabase(t, database, "GetClientPermissionsByClientId",
			"GetResourceByResourceIdentifier", "GetPermissionsByResourceId")
	}

	t.Run("a client that does not exist", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), targetClientId).Return(nil, nil).Once()

		rr := httptest.NewRecorder()
		HandleClientSecretGet(database, auditLogger, testDataCipher).ServeHTTP(rr,
			clientRequest(http.MethodGet, "/api/v1/admin/clients/58/secret", "", granularScopeOfClients))

		assert.Equal(t, http.StatusNotFound, rr.Code)
		assertNoClientPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a redirect URI that is not absolute", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectTheTargetClient(targetClient(t, clientHoldingManage))(database)

		r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/redirect-uris",
			`{"redirectURIs":["/relative/cb"],"expectedRedirectURIs":[]}`, granularScopeOfClients)
		r = r.WithContext(reqctx.WithSettings(r.Context(), &record.Settings{}))
		rr := httptest.NewRecorder()
		HandleClientRedirectURIsPut(database, auditLogger).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assertNoClientPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a client secret too short", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectTheTargetClient(targetClient(t, clientHoldingManage))(database)

		r := clientRequest(http.MethodPut, "/api/v1/admin/clients/58/authentication", `{"isPublic":false,"clientSecret":"short"}`, granularScopeOfClients)
		rr := httptest.NewRecorder()
		HandleClientAuthenticationPut(database, auditLogger, testDataCipher).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assertNoClientPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("a logo that is no image", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectTheTargetClient(targetClient(t, clientHoldingManage))(database)

		r, err := createMultipartRequest(http.MethodPost, "/api/v1/admin/clients/58/logo", "picture", []byte("not an image"))
		require.NoError(t, err)
		r = setChiURLParam(r, "id", "58")
		r = setTokenContextWithClaims(r, map[string]interface{}{"scope": granularScopeOfClients, "sub": grantCaller})
		rr := httptest.NewRecorder()
		HandleClientLogoPost(database, auditLogger, testBaseURL, testMaxUploadBytes).ServeHTTP(rr, r)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assertNoClientPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("deleting the admin console's own client", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		auditLogger := handlersmocks.NewAuditLogger(t)
		expectTheTargetClient(targetClient(t, theConsoleClient))(database)

		rr := httptest.NewRecorder()
		HandleClientDelete(database, auditLogger).ServeHTTP(rr, clientRequest(http.MethodDelete, "/api/v1/admin/clients/58", "", granularScopeOfClients))

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		assertNoClientPolicyRead(t, database)
		auditLogger.AssertNotCalled(t, "Log", mock.Anything, mock.Anything, mock.Anything)
	})
}
