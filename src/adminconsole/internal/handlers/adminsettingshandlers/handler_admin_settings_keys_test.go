package adminsettingshandlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"
)

func TestHandleAdminSettingsKeysGet(t *testing.T) {

	t.Run("Successful retrieval of signing keys", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)

		handler := HandleAdminSettingsKeysGet(mockHttpHelper, mockDatabase)

		req, err := http.NewRequest("GET", "/admin/settings/keys", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockSigningKeys := []models.KeyPair{
			{
				Id:                1,
				CreatedAt:         sql.NullTime{Time: time.Now().Add(-48 * time.Hour), Valid: true},
				State:             enums.KeyStatePrevious.String(),
				KeyIdentifier:     "key1",
				Type:              "RSA",
				Algorithm:         "RS256",
				PublicKeyASN1_DER: []byte("public_key_asn1"),
				PublicKeyPEM:      []byte("public_key_pem"),
				PublicKeyJWK:      []byte("public_key_jwk"),
			},
			{
				Id:                2,
				CreatedAt:         sql.NullTime{Time: time.Now().Add(-24 * time.Hour), Valid: true},
				State:             enums.KeyStateCurrent.String(),
				KeyIdentifier:     "key2",
				Type:              "RSA",
				Algorithm:         "RS256",
				PublicKeyASN1_DER: []byte("public_key_asn2"),
				PublicKeyPEM:      []byte("public_key_pem2"),
				PublicKeyJWK:      []byte("public_key_jwk2"),
			},
			{
				Id:                3,
				CreatedAt:         sql.NullTime{Time: time.Now(), Valid: true},
				State:             enums.KeyStateNext.String(),
				KeyIdentifier:     "key3",
				Type:              "RSA",
				Algorithm:         "RS256",
				PublicKeyASN1_DER: []byte("public_key_asn3"),
				PublicKeyPEM:      []byte("public_key_pem3"),
				PublicKeyJWK:      []byte("public_key_jwk3"),
			},
		}

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return(mockSigningKeys, nil)

		expectedKeys := []SettingsKey{
			{
				Id:               3,
				CreatedAt:        mockSigningKeys[2].CreatedAt.Time.Format("02 Jan 2006 15:04:05 MST"),
				State:            enums.KeyStateNext.String(),
				KeyIdentifier:    "key3",
				Type:             "RSA",
				Algorithm:        "RS256",
				PublicKeyASN1DER: base64.StdEncoding.EncodeToString([]byte("public_key_asn3")),
				PublicKeyPEM:     string([]byte("public_key_pem3")),
				PublicKeyJWK:     string([]byte("public_key_jwk3")),
			},
			{
				Id:               2,
				CreatedAt:        mockSigningKeys[1].CreatedAt.Time.Format("02 Jan 2006 15:04:05 MST"),
				State:            enums.KeyStateCurrent.String(),
				KeyIdentifier:    "key2",
				Type:             "RSA",
				Algorithm:        "RS256",
				PublicKeyASN1DER: base64.StdEncoding.EncodeToString([]byte("public_key_asn2")),
				PublicKeyPEM:     string([]byte("public_key_pem2")),
				PublicKeyJWK:     string([]byte("public_key_jwk2")),
			},
			{
				Id:               1,
				CreatedAt:        mockSigningKeys[0].CreatedAt.Time.Format("02 Jan 2006 15:04:05 MST"),
				State:            enums.KeyStatePrevious.String(),
				KeyIdentifier:    "key1",
				Type:             "RSA",
				Algorithm:        "RS256",
				PublicKeyASN1DER: base64.StdEncoding.EncodeToString([]byte("public_key_asn1")),
				PublicKeyPEM:     string([]byte("public_key_pem")),
				PublicKeyJWK:     string([]byte("public_key_jwk")),
			},
		}

		mockHttpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/menu_layout.html",
			"/admin_settings_keys.html",
			mock.MatchedBy(func(data map[string]interface{}) bool {
				keys, ok := data["keys"].([]SettingsKey)
				if !ok {
					return false
				}
				if len(keys) != 3 {
					return false
				}
				// Check order: Next, Current, Previous
				return keys[0].State == enums.KeyStateNext.String() &&
					keys[1].State == enums.KeyStateCurrent.String() &&
					keys[2].State == enums.KeyStatePrevious.String() &&
					assert.Equal(t, expectedKeys, keys)
			}),
		).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		mockDatabase.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Database error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)

		handler := HandleAdminSettingsKeysGet(mockHttpHelper, mockDatabase)

		req, err := http.NewRequest("GET", "/admin/settings/keys", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return(nil, fmt.Errorf("database error"))

		mockHttpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "database error")
			}),
		).Once()

		handler.ServeHTTP(rr, req)

		mockDatabase.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Render template error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)

		handler := HandleAdminSettingsKeysGet(mockHttpHelper, mockDatabase)

		req, err := http.NewRequest("GET", "/admin/settings/keys", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockSigningKeys := []models.KeyPair{
			{
				Id:                1,
				CreatedAt:         sql.NullTime{Time: time.Now(), Valid: true},
				State:             enums.KeyStateNext.String(),
				KeyIdentifier:     "key1",
				Type:              "RSA",
				Algorithm:         "RS256",
				PublicKeyASN1_DER: []byte("public_key_asn1"),
				PublicKeyPEM:      []byte("public_key_pem"),
				PublicKeyJWK:      []byte("public_key_jwk"),
			},
		}

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return(mockSigningKeys, nil)

		mockHttpHelper.On("RenderTemplate",
			mock.Anything,
			mock.Anything,
			"/layouts/menu_layout.html",
			"/admin_settings_keys.html",
			mock.Anything,
		).Return(fmt.Errorf("render error"))

		mockHttpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return err != nil && strings.Contains(err.Error(), "render error")
			}),
		).Once()

		handler.ServeHTTP(rr, req)

		mockDatabase.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

func TestHandleAdminSettingsKeysRotatePost(t *testing.T) {
	t.Run("Successful key rotation", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminSettingsKeysRotatePost(mockHttpHelper, mockAuthHelper, mockDatabase, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/settings/keys/rotate", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return([]models.KeyPair{
			{Id: 1, State: enums.KeyStatePrevious.String()},
			{Id: 2, State: enums.KeyStateCurrent.String()},
			{Id: 3, State: enums.KeyStateNext.String()},
		}, nil)

		mockDatabase.On("DeleteKeyPair", (*sql.Tx)(nil), int64(1)).Return(nil)

		var updatedCurrentKey, updatedPreviousKey *models.KeyPair

		mockDatabase.On("UpdateKeyPair", (*sql.Tx)(nil), mock.MatchedBy(func(kp *models.KeyPair) bool {
			if kp.Id == 2 && kp.State == enums.KeyStatePrevious.String() {
				updatedPreviousKey = kp
				return true
			}
			return false
		})).Return(nil).Once()

		mockDatabase.On("UpdateKeyPair", (*sql.Tx)(nil), mock.MatchedBy(func(kp *models.KeyPair) bool {
			if kp.Id == 3 && kp.State == enums.KeyStateCurrent.String() {
				updatedCurrentKey = kp
				return true
			}
			return false
		})).Return(nil).Once()

		mockDatabase.On("CreateKeyPair", (*sql.Tx)(nil), mock.MatchedBy(func(kp *models.KeyPair) bool {
			return kp.State == enums.KeyStateNext.String() &&
				kp.Type == "RSA" &&
				kp.Algorithm == "RS256" &&
				len(kp.PrivateKeyPEM) > 0 &&
				len(kp.PublicKeyPEM) > 0 &&
				len(kp.PublicKeyASN1_DER) > 0 &&
				len(kp.PublicKeyJWK) > 0
		})).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")

		mockAuditLogger.On("Log", constants.AuditRotatedKeys, mock.MatchedBy(func(details map[string]interface{}) bool {
			loggedInUser, ok := details["loggedInUser"].(string)
			return ok && loggedInUser == "admin-user"
		})).Return(nil)

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.AnythingOfType("struct { Success bool }")).Run(func(args mock.Arguments) {
			w := args.Get(0).(http.ResponseWriter)
			data := args.Get(2).(struct{ Success bool })
			err := json.NewEncoder(w).Encode(data)
			assert.NoError(t, err)
		}).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response struct {
			Success bool `json:"success"`
		}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response.Success)

		assert.NotNil(t, updatedCurrentKey, "Next key should have been updated to current")
		assert.Equal(t, int64(3), updatedCurrentKey.Id, "Key with ID 3 should have become the current key")
		assert.Equal(t, enums.KeyStateCurrent.String(), updatedCurrentKey.State, "Next key should have been updated to current state")

		assert.NotNil(t, updatedPreviousKey, "Current key should have been updated to previous")
		assert.Equal(t, int64(2), updatedPreviousKey.Id, "Key with ID 2 should have become the previous key")
		assert.Equal(t, enums.KeyStatePrevious.String(), updatedPreviousKey.State, "Current key should have been updated to previous state")

		mockDatabase.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Error getting signing keys", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminSettingsKeysRotatePost(mockHttpHelper, mockAuthHelper, mockDatabase, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/settings/keys/rotate", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		expectedError := fmt.Errorf("database error")
		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return(nil, expectedError)

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == expectedError.Error()
		})).Once()

		handler.ServeHTTP(rr, req)

		mockDatabase.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("No current key found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminSettingsKeysRotatePost(mockHttpHelper, mockAuthHelper, mockDatabase, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/settings/keys/rotate", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return([]models.KeyPair{
			{Id: 1, State: enums.KeyStatePrevious.String()},
			{Id: 3, State: enums.KeyStateNext.String()},
		}, nil)

		mockDatabase.On("DeleteKeyPair", (*sql.Tx)(nil), int64(1)).Return(nil)

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "no current key found"
		})).Once()

		handler.ServeHTTP(rr, req)

		mockDatabase.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("No next key found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminSettingsKeysRotatePost(mockHttpHelper, mockAuthHelper, mockDatabase, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/settings/keys/rotate", nil)
		assert.NoError(t, err)

		rr := httptest.NewRecorder()

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return([]models.KeyPair{
			{Id: 1, State: enums.KeyStatePrevious.String()},
			{Id: 2, State: enums.KeyStateCurrent.String()},
		}, nil)

		mockDatabase.On("DeleteKeyPair", (*sql.Tx)(nil), int64(1)).Return(nil)

		mockHttpHelper.On("JsonError",
			mock.AnythingOfType("*httptest.ResponseRecorder"),
			mock.AnythingOfType("*http.Request"),
			mock.MatchedBy(func(err error) bool {
				return strings.Contains(err.Error(), "no next key found")
			}),
		).Once()

		handler.ServeHTTP(rr, req)

		mockDatabase.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}

func TestHandleAdminSettingsKeysRevokePost(t *testing.T) {
	t.Run("Successful key revocation", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminSettingsKeysRevokePost(mockHttpHelper, mockAuthHelper, mockDatabase, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/settings/keys/revoke", strings.NewReader(`{"id": 1}`))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return([]models.KeyPair{
			{Id: 1, State: enums.KeyStatePrevious.String(), KeyIdentifier: "key1"},
			{Id: 2, State: enums.KeyStateCurrent.String()},
			{Id: 3, State: enums.KeyStateNext.String()},
		}, nil)

		mockDatabase.On("DeleteKeyPair", (*sql.Tx)(nil), int64(1)).Return(nil)

		mockAuthHelper.On("GetLoggedInSubject", mock.Anything).Return("admin-user")

		mockAuditLogger.On("Log", constants.AuditRevokedKey, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["loggedInUser"] == "admin-user" && details["keyId"] == "key1"
		})).Return(nil)

		mockHttpHelper.On("EncodeJson", mock.Anything, mock.Anything, mock.AnythingOfType("struct { Success bool }")).Run(func(args mock.Arguments) {
			w := args.Get(0).(http.ResponseWriter)
			data := args.Get(2).(struct{ Success bool })
			err := json.NewEncoder(w).Encode(data)
			assert.NoError(t, err)
		}).Return(nil)

		handler.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var response struct {
			Success bool `json:"success"`
		}
		err = json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response.Success)

		mockDatabase.AssertExpectations(t)
		mockAuditLogger.AssertExpectations(t)
		mockAuthHelper.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("No previous key found", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminSettingsKeysRevokePost(mockHttpHelper, mockAuthHelper, mockDatabase, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/settings/keys/revoke", strings.NewReader(`{"id": 1}`))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return([]models.KeyPair{
			{Id: 2, State: enums.KeyStateCurrent.String()},
			{Id: 3, State: enums.KeyStateNext.String()},
		}, nil)

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "no previous key found"
		})).Once()

		handler.ServeHTTP(rr, req)

		mockDatabase.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Invalid JSON input", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminSettingsKeysRevokePost(mockHttpHelper, mockAuthHelper, mockDatabase, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/settings/keys/revoke", strings.NewReader(`invalid json`))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return strings.Contains(err.Error(), "invalid character")
		})).Once()

		handler.ServeHTTP(rr, req)

		mockHttpHelper.AssertExpectations(t)
	})

	t.Run("Database error", func(t *testing.T) {
		mockHttpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		mockAuthHelper := mocks_handlerhelpers.NewAuthHelper(t)
		mockDatabase := mocks_data.NewDatabase(t)
		mockAuditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleAdminSettingsKeysRevokePost(mockHttpHelper, mockAuthHelper, mockDatabase, mockAuditLogger)

		req, err := http.NewRequest("POST", "/admin/settings/keys/revoke", strings.NewReader(`{"id": 1}`))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()

		mockDatabase.On("GetAllSigningKeys", (*sql.Tx)(nil)).Return(nil, fmt.Errorf("database error"))

		mockHttpHelper.On("JsonError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
			return err.Error() == "database error"
		})).Once()

		handler.ServeHTTP(rr, req)

		mockDatabase.AssertExpectations(t)
		mockHttpHelper.AssertExpectations(t)
	})
}
