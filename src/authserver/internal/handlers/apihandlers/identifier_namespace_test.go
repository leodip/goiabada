package apihandlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	handlersmocks "github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// TestIdentifierNamespaces_AFailedLookupInTheOtherNamespaceWritesNothing pins that each of the four
// lookups across the client and resource namespaces fails closed (#151): a database error from it
// is a 500, never read as "no clash". The strict mock registers no CreateClient, UpdateClient,
// CreateResource or UpdateResource, so a handler that wrote the row anyway fails the case. The client
// create is given a real data cipher, so a handler going on past the lookup reaches its write rather
// than stopping at the client secret's encryption.
func TestIdentifierNamespaces_AFailedLookupInTheOtherNamespaceWritesNothing(t *testing.T) {
	boom := errs.New("boom")
	dataCipher, err := encryption.NewDataCipher([]byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)
	cases := []struct {
		name  string
		serve func(t *testing.T, database *datamocks.Database) *httptest.ResponseRecorder
	}{
		{
			name: "client create",
			serve: func(t *testing.T, database *datamocks.Database) *httptest.ResponseRecorder {
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "a-client").Return(nil, nil).Once()
				database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "a-client").Return(nil, boom).Once()
				rr := httptest.NewRecorder()
				HandleClientCreatePost(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t), dataCipher).
					ServeHTTP(rr, clientRefusalRequest(http.MethodPost, "/api/v1/admin/clients", `{"clientIdentifier":"a-client"}`, ""))
				return rr
			},
		},
		{
			name: "client update with a changed identifier",
			serve: func(t *testing.T, database *datamocks.Database) *httptest.ResponseRecorder {
				database.On("GetClientById", mock.Anything, (*sql.Tx)(nil), int64(7)).
					Return(&record.Client{Id: 7, ClientIdentifier: "a-client", AuthorizationCodeEnabled: true}, nil).Once()
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "renamed").Return(nil, nil).Once()
				database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "renamed").Return(nil, boom).Once()
				rr := httptest.NewRecorder()
				HandleClientUpdatePut(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).
					ServeHTTP(rr, clientRefusalRequest(http.MethodPut, "/api/v1/admin/clients/7", `{"clientIdentifier":"renamed"}`, ""))
				return rr
			},
		},
		{
			name: "resource create",
			serve: func(t *testing.T, database *datamocks.Database) *httptest.ResponseRecorder {
				database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "a-resource").Return(nil, nil).Once()
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "a-resource").Return(nil, boom).Once()
				rr := httptest.NewRecorder()
				HandleResourceCreatePost(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).
					ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/admin/resources",
						strings.NewReader(`{"resourceIdentifier":"a-resource","description":"d"}`)))
				return rr
			},
		},
		{
			name: "resource update with a changed identifier",
			serve: func(t *testing.T, database *datamocks.Database) *httptest.ResponseRecorder {
				database.On("GetResourceById", mock.Anything, (*sql.Tx)(nil), int64(5)).
					Return(&record.Resource{Id: 5, ResourceIdentifier: "a-resource", Description: "A resource"}, nil).Once()
				database.On("GetResourceByResourceIdentifier", mock.Anything, (*sql.Tx)(nil), "renamed").Return(nil, nil).Once()
				database.On("GetClientByClientIdentifier", mock.Anything, (*sql.Tx)(nil), "renamed").Return(nil, boom).Once()
				r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/resources/5",
					strings.NewReader(`{"resourceIdentifier":"renamed","description":"d"}`))
				rr := httptest.NewRecorder()
				HandleResourceUpdatePut(database, inputvalidation.NewIdentifierValidator(), handlersmocks.NewAuditLogger(t)).
					ServeHTTP(rr, withPathValue(r, "id", "5"))
				return rr
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := tc.serve(t, datamocks.NewDatabase(t))

			assert.Equal(t, http.StatusInternalServerError, rr.Code, rr.Body.String())
		})
	}
}
