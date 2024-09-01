package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/core/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleUserInfoGetPost(t *testing.T) {
	t.Run("no bearer token in the context", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		rr := httptest.NewRecorder()

		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.(*customerrors.ErrorDetail).GetCode() == "invalid_token"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("could not type assert ContextKeyBearerToken to oauth.JwtToken", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, "invalid_type")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		httpHelper.On("InternalServerError", rr, req, mock.AnythingOfType("*errors.withStack")).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("user not authorized", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		jwtToken := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":   "user123",
				"scope": "some_other_scope", // This scope doesn't include the required userinfo permission
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, jwtToken)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			errorDetail, ok := err.(*customerrors.ErrorDetail)
			return ok &&
				errorDetail.GetCode() == "insufficient_scope" &&
				errorDetail.GetDescription() == "The access token is not authorized to access this resource. Ensure to include a valid OpenID Connect scope in your authorization request and try again." &&
				errorDetail.GetHttpStatusCode() == http.StatusForbidden
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("jwtToken without sub claim", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		jwtToken := oauth.JwtToken{
			Claims: map[string]interface{}{
				"scope": constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier,
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, jwtToken)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		httpHelper.On("InternalServerError",
			mock.Anything,
			mock.Anything,
			mock.MatchedBy(func(err error) bool {
				return err.Error() == "unable to get the sub claim from the access token"
			}),
		).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("GetUserBySubject returns nil", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		jwtToken := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":   "user123",
				"scope": constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier,
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, jwtToken)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		database.On("GetUserBySubject", (*sql.Tx)(nil), "user123").Return(nil, nil)

		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.(*customerrors.ErrorDetail).GetCode() == "server_error" &&
				err.(*customerrors.ErrorDetail).GetDescription() == "The user could not be found."
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("user is not enabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		sub := uuid.New()

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		jwtToken := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":   sub.String(),
				"scope": constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier,
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, jwtToken)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		user := &models.User{Id: 1, Subject: sub, Enabled: false}
		database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == user.Id
		})).Return()

		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.(*customerrors.ErrorDetail).GetCode() == "server_error" &&
				err.(*customerrors.ErrorDetail).GetDescription() == "The user account is disabled."
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("success path with all claims", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		sub := uuid.New()
		req, _ := http.NewRequest("GET", "/userinfo", nil)
		jwtToken := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":   sub.String(),
				"scope": constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier + " profile email address phone groups attributes",
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyBearerToken, jwtToken)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		birthDate := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)

		group1 := models.Group{Id: 1, GroupIdentifier: "group1", IncludeInIdToken: true}
		groupAttr := models.GroupAttribute{Key: "groupAttr", Value: "groupValue", IncludeInIdToken: true}
		group1.Attributes = []models.GroupAttribute{groupAttr}

		group2 := models.Group{Id: 2, GroupIdentifier: "group2", IncludeInIdToken: true}

		userAttr := models.UserAttribute{Key: "userAttr", Value: "userValue", IncludeInIdToken: true}

		user := &models.User{
			Id:                  1,
			Subject:             sub,
			Enabled:             true,
			Username:            "testuser",
			Email:               "test@example.com",
			EmailVerified:       true,
			GivenName:           "Test",
			MiddleName:          "Middle",
			FamilyName:          "User",
			Nickname:            "Testy",
			Website:             "https://example.com",
			Gender:              "male",
			BirthDate:           sql.NullTime{Time: birthDate, Valid: true},
			ZoneInfo:            "Europe/London",
			ZoneInfoCountryName: "United Kingdom",
			Locale:              "en-GB",
			PhoneNumber:         "+1234567890",
			PhoneNumberVerified: true,
			AddressLine1:        "123 Test St",
			AddressLine2:        "Apt 4",
			AddressLocality:     "Test City",
			AddressRegion:       "Test Region",
			AddressPostalCode:   "12345",
			AddressCountry:      "Test Country",
			UpdatedAt:           sql.NullTime{Time: time.Now(), Valid: true},
			Groups:              []models.Group{group1, group2},
			Attributes:          []models.UserAttribute{userAttr},
		}

		database.On("GetUserBySubject", (*sql.Tx)(nil), sub.String()).Return(user, nil)
		database.On("UserLoadGroups", (*sql.Tx)(nil), user).Return(nil)
		database.On("GroupsLoadAttributes", (*sql.Tx)(nil), user.Groups).Return(nil)
		database.On("UserLoadAttributes", (*sql.Tx)(nil), user).Return(nil)

		httpHelper.On("EncodeJson", rr, req, mock.MatchedBy(func(claims map[string]interface{}) bool {
			assert.Equal(t, sub, claims["sub"])
			assert.Equal(t, user.Username, claims["preferred_username"])
			assert.Equal(t, user.Email, claims["email"])
			assert.Equal(t, user.EmailVerified, claims["email_verified"])
			assert.Equal(t, user.GivenName, claims["given_name"])
			assert.Equal(t, user.MiddleName, claims["middle_name"])
			assert.Equal(t, user.FamilyName, claims["family_name"])
			assert.Equal(t, user.Nickname, claims["nickname"])
			assert.Equal(t, user.Website, claims["website"])
			assert.Equal(t, user.Gender, claims["gender"])
			assert.Equal(t, user.GetDateOfBirthFormatted(), claims["birthdate"])
			assert.Equal(t, user.ZoneInfo, claims["zoneinfo"])
			assert.Equal(t, user.Locale, claims["locale"])
			assert.Equal(t, user.PhoneNumber, claims["phone_number"])
			assert.Equal(t, user.PhoneNumberVerified, claims["phone_number_verified"])
			assert.Equal(t, user.GetFullName(), claims["name"])

			addressClaim := user.GetAddressClaim()
			assert.Equal(t, addressClaim, claims["address"])

			assert.Equal(t, user.UpdatedAt.Time.UTC().Unix(), claims["updated_at"])
			assert.ElementsMatch(t, []string{"group1", "group2"}, claims["groups"])
			attributes := claims["attributes"].(map[string]string)
			assert.Equal(t, "userValue", attributes["userAttr"])
			assert.Equal(t, "groupValue", attributes["groupAttr"])
			return true
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})
}
