package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandleCertsGet(t *testing.T) {
	t.Run("Successfully returns JWKS", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)

		handler := HandleCertsGet(jsonWriter, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		nextKey := record.KeyPair{
			State:        record.KeyStateNext.String(),
			PublicKeyJWK: []byte(`{"kid":"next-kid","kty":"RSA","alg":"RS256","use":"sig","n":"next-n","e":"AQAB"}`),
		}
		currentKey := record.KeyPair{
			State:        record.KeyStateCurrent.String(),
			PublicKeyJWK: []byte(`{"kid":"current-kid","kty":"RSA","alg":"RS256","use":"sig","n":"current-n","e":"AQAB"}`),
		}
		previousKey := record.KeyPair{
			State:        record.KeyStatePrevious.String(),
			PublicKeyJWK: []byte(`{"kid":"previous-kid","kty":"RSA","alg":"RS256","use":"sig","n":"previous-n","e":"AQAB"}`),
		}

		allKeys := []record.KeyPair{nextKey, currentKey, previousKey}

		database.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return(allKeys, nil)

		jsonWriter.On("EncodeJSON", rr, req, mock.AnythingOfType("oauth.Jwks")).Run(func(args mock.Arguments) {
			jwks := args.Get(2).(oauth.Jwks)
			assert.Len(t, jwks.Keys, 3)
			assert.Equal(t, "next-kid", jwks.Keys[0].Kid)
			assert.Equal(t, "current-kid", jwks.Keys[1].Kid)
			assert.Equal(t, "previous-kid", jwks.Keys[2].Kid)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		database.AssertExpectations(t)
		jsonWriter.AssertExpectations(t)
	})

	t.Run("Successfully returns JWKS with only current key", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)

		handler := HandleCertsGet(jsonWriter, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		currentKey := record.KeyPair{
			State:        record.KeyStateCurrent.String(),
			PublicKeyJWK: []byte(`{"kid":"current-kid","kty":"RSA","alg":"RS256","use":"sig","n":"current-n","e":"AQAB"}`),
		}

		allKeys := []record.KeyPair{currentKey}

		database.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return(allKeys, nil)

		jsonWriter.On("EncodeJSON", rr, req, mock.AnythingOfType("oauth.Jwks")).Run(func(args mock.Arguments) {
			jwks := args.Get(2).(oauth.Jwks)
			assert.Len(t, jwks.Keys, 1)
			assert.Equal(t, "current-kid", jwks.Keys[0].Kid)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		database.AssertExpectations(t)
		jsonWriter.AssertExpectations(t)
	})

	t.Run("Database error", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)

		handler := HandleCertsGet(jsonWriter, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		database.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return(nil, errors.New("database error"))

		jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		database.AssertExpectations(t)
		jsonWriter.AssertExpectations(t)
	})

	t.Run("Invalid key state", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)

		handler := HandleCertsGet(jsonWriter, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		invalidKey := record.KeyPair{
			State:        "invalid",
			PublicKeyJWK: []byte(`{"kid":"invalid-kid","kty":"RSA","alg":"RS256","use":"sig","n":"invalid-n","e":"AQAB"}`),
		}

		allKeys := []record.KeyPair{invalidKey}

		database.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return(allKeys, nil)

		jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "invalid key state invalid"
		})).Return()

		handler.ServeHTTP(rr, req)

		database.AssertExpectations(t)
		jsonWriter.AssertExpectations(t)
	})

	t.Run("Invalid JSON in PublicKeyJWK", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)

		handler := HandleCertsGet(jsonWriter, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		invalidJSONKey := record.KeyPair{
			State:        record.KeyStateCurrent.String(),
			PublicKeyJWK: []byte(`invalid json`),
		}

		allKeys := []record.KeyPair{invalidJSONKey}

		database.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return(allKeys, nil)

		jsonWriter.On("JSONError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "invalid character 'i' looking for beginning of value"
		})).Return()

		handler.ServeHTTP(rr, req)

		database.AssertExpectations(t)
		jsonWriter.AssertExpectations(t)
	})

	t.Run("No keys found", func(t *testing.T) {
		jsonWriter := handlersmocks.NewJSONWriter(t)
		database := datamocks.NewDatabase(t)

		handler := HandleCertsGet(jsonWriter, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		database.On("GetAllSigningKeys", mock.Anything, mock.Anything).Return([]record.KeyPair{}, nil)

		jsonWriter.On("EncodeJSON", rr, req, mock.MatchedBy(func(jwks oauth.Jwks) bool {
			return len(jwks.Keys) == 0
		})).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		database.AssertExpectations(t)
		jsonWriter.AssertExpectations(t)
	})
}
