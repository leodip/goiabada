package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"

	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleCertsGet(t *testing.T) {
	t.Run("Successfully returns JWKS", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleCertsGet(httpHelper, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		nextKey := models.KeyPair{
			State:        enums.KeyStateNext.String(),
			PublicKeyJWK: []byte(`{"kid":"next-kid","kty":"RSA","alg":"RS256","use":"sig","n":"next-n","e":"AQAB"}`),
		}
		currentKey := models.KeyPair{
			State:        enums.KeyStateCurrent.String(),
			PublicKeyJWK: []byte(`{"kid":"current-kid","kty":"RSA","alg":"RS256","use":"sig","n":"current-n","e":"AQAB"}`),
		}
		previousKey := models.KeyPair{
			State:        enums.KeyStatePrevious.String(),
			PublicKeyJWK: []byte(`{"kid":"previous-kid","kty":"RSA","alg":"RS256","use":"sig","n":"previous-n","e":"AQAB"}`),
		}

		allKeys := []models.KeyPair{nextKey, currentKey, previousKey}

		database.On("GetAllSigningKeys", mock.Anything).Return(allKeys, nil)

		httpHelper.On("EncodeJson", rr, req, mock.AnythingOfType("oauth.Jwks")).Run(func(args mock.Arguments) {
			jwks := args.Get(2).(oauth.Jwks)
			assert.Len(t, jwks.Keys, 3)
			assert.Equal(t, "next-kid", jwks.Keys[0].Kid)
			assert.Equal(t, "current-kid", jwks.Keys[1].Kid)
			assert.Equal(t, "previous-kid", jwks.Keys[2].Kid)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Successfully returns JWKS with only current key", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleCertsGet(httpHelper, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		currentKey := models.KeyPair{
			State:        enums.KeyStateCurrent.String(),
			PublicKeyJWK: []byte(`{"kid":"current-kid","kty":"RSA","alg":"RS256","use":"sig","n":"current-n","e":"AQAB"}`),
		}

		allKeys := []models.KeyPair{currentKey}

		database.On("GetAllSigningKeys", mock.Anything).Return(allKeys, nil)

		httpHelper.On("EncodeJson", rr, req, mock.AnythingOfType("oauth.Jwks")).Run(func(args mock.Arguments) {
			jwks := args.Get(2).(oauth.Jwks)
			assert.Len(t, jwks.Keys, 1)
			assert.Equal(t, "current-kid", jwks.Keys[0].Kid)
		}).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Database error", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleCertsGet(httpHelper, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		database.On("GetAllSigningKeys", mock.Anything).Return(nil, errors.New("database error"))

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Return()

		handler.ServeHTTP(rr, req)

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Invalid key state", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleCertsGet(httpHelper, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		invalidKey := models.KeyPair{
			State:        "invalid",
			PublicKeyJWK: []byte(`{"kid":"invalid-kid","kty":"RSA","alg":"RS256","use":"sig","n":"invalid-n","e":"AQAB"}`),
		}

		allKeys := []models.KeyPair{invalidKey}

		database.On("GetAllSigningKeys", mock.Anything).Return(allKeys, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "invalid key state invalid"
		})).Return()

		handler.ServeHTTP(rr, req)

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("Invalid JSON in PublicKeyJWK", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleCertsGet(httpHelper, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		invalidJSONKey := models.KeyPair{
			State:        enums.KeyStateCurrent.String(),
			PublicKeyJWK: []byte(`invalid json`),
		}

		allKeys := []models.KeyPair{invalidJSONKey}

		database.On("GetAllSigningKeys", mock.Anything).Return(allKeys, nil)

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "invalid character 'i' looking for beginning of value"
		})).Return()

		handler.ServeHTTP(rr, req)

		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})

	t.Run("No keys found", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)

		handler := HandleCertsGet(httpHelper, database)

		req, err := http.NewRequest("GET", "/certs", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		database.On("GetAllSigningKeys", mock.Anything).Return([]models.KeyPair{}, nil)

		httpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(jwks oauth.Jwks) bool {
			return len(jwks.Keys) == 0
		})).Return()

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		database.AssertExpectations(t)
		httpHelper.AssertExpectations(t)
	})
}
