package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mocks_audit "github.com/leodip/goiabada/authserver/internal/audit/mocks"
	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	mocks_handlerhelpers "github.com/leodip/goiabada/core/handlerhelpers/mocks"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestHandleUserInfoGetPost(t *testing.T) {
	t.Run("No validated token in the context", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		rr := httptest.NewRecorder()

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "unable to get validated token from context"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	t.Run("Could not type assert ContextKeyValidatedToken to oauth.JwtToken", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, "invalid_type")
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		httpHelper.On("InternalServerError", rr, req, mock.MatchedBy(func(err error) bool {
			return err.Error() == "unable to get validated token from context"
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
	})

	// Note: "User not authorized" test case is removed because authorization is now handled by middleware

	t.Run("JwtToken without sub claim", func(t *testing.T) {
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
		ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, jwtToken)
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
		ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, jwtToken)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		database.On("GetUserBySubject", (*sql.Tx)(nil), "user123").Return(nil, nil)

		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return isUserInfoInvalidToken(err, "The user could not be found.")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
	})

	t.Run("User is not enabled", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		sub := fake.UUID()

		req, _ := http.NewRequest("GET", "/userinfo", nil)
		jwtToken := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":   sub,
				"scope": constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier,
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, jwtToken)
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()

		user := &models.User{Id: 1, Subject: sub, Enabled: false}
		database.On("GetUserBySubject", (*sql.Tx)(nil), sub).Return(user, nil)

		auditLogger.On("Log", constants.AuditUserDisabled, mock.MatchedBy(func(details map[string]interface{}) bool {
			return details["userId"] == user.Id
		})).Return()

		httpHelper.On("JsonError", rr, req, mock.MatchedBy(func(err error) bool {
			return isUserInfoInvalidToken(err, "The user account is disabled.")
		})).Return()

		handler.ServeHTTP(rr, req)

		httpHelper.AssertExpectations(t)
		database.AssertExpectations(t)
		auditLogger.AssertExpectations(t)
	})

	t.Run("Success path with all claims", func(t *testing.T) {
		httpHelper := mocks_handlerhelpers.NewHttpHelper(t)
		database := mocks_data.NewDatabase(t)
		auditLogger := mocks_audit.NewAuditLogger(t)

		handler := HandleUserInfoGetPost(httpHelper, database, auditLogger)

		sub := fake.UUID()
		req, _ := http.NewRequest("GET", "/userinfo", nil)
		jwtToken := oauth.JwtToken{
			Claims: map[string]interface{}{
				"sub":   sub,
				"scope": constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier + " profile email address phone groups attributes",
			},
		}
		ctx := context.WithValue(req.Context(), constants.ContextKeyValidatedToken, jwtToken)
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

		database.On("GetUserBySubject", (*sql.Tx)(nil), sub).Return(user, nil)
		database.On("UserLoadGroups", (*sql.Tx)(nil), user).Return(nil)
		database.On("GroupsLoadAttributes", (*sql.Tx)(nil), user.Groups).Return(nil)
		database.On("UserLoadAttributes", (*sql.Tx)(nil), user).Return(nil)
		database.On("UserHasProfilePicture", (*sql.Tx)(nil), user.Id).Return(false, nil)

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

// isUserInfoInvalidToken is what both refusal branches of /userinfo now carry: RFC 6750 section
// 3.1's invalid_token, 401, and the challenge that tells the client which error it is.
//
// errors.As rather than the bare assertion these cases used, so a wrap on the way to JsonError
// could not turn the whole expectation into a panic in a mock matcher (#279 decision 6).
func isUserInfoInvalidToken(err error, description string) bool {
	var detail *customerrors.ErrorDetail
	if !errors.As(err, &detail) {
		return false
	}
	return detail.GetCode() == "invalid_token" &&
		detail.GetDescription() == description &&
		detail.GetHttpStatusCode() == http.StatusUnauthorized &&
		detail.GetWWWAuthenticate() == `Bearer error="invalid_token"`
}

// The two cases above assert on the value handed to a mocked writer, which cannot say what a
// client receives. This drives the real HttpHelper, so the status line and the challenge header
// are asserted where the client reads them.
//
// It is the seam decision 14 actually moved: before it, both branches answered 500 server_error
// with no challenge at all, so a client had nothing to distinguish "your token is no good" from
// "this server is broken" and no instruction to obtain a new one (#279 decision 14, seam 8).
func TestHandleUserInfoGetPost_RefusalsAreInvalidTokenOnTheWire(t *testing.T) {
	tests := []struct {
		name        string
		user        *models.User
		description string
	}{
		{
			name:        "the subject has no row",
			user:        nil,
			description: "The user could not be found.",
		},
		{
			name:        "the account is disabled",
			user:        &models.User{Id: 1, Subject: "user123", Enabled: false},
			description: "The user account is disabled.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			auditLogger := mocks_audit.NewAuditLogger(t)

			// templateFS is nil because JsonError renders no template; a 500 through the
			// page writer would panic here, which is the fail-loud direction.
			handler := HandleUserInfoGetPost(handlerhelpers.NewHttpHelper(nil), database, auditLogger)

			req, _ := http.NewRequest("GET", "/userinfo", nil)
			jwtToken := oauth.JwtToken{
				Claims: map[string]interface{}{
					"sub":   "user123",
					"scope": constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier,
				},
			}
			req = req.WithContext(context.WithValue(req.Context(), constants.ContextKeyValidatedToken, jwtToken))
			rr := httptest.NewRecorder()

			database.On("GetUserBySubject", (*sql.Tx)(nil), "user123").Return(test.user, nil)
			if test.user != nil {
				auditLogger.On("Log", constants.AuditUserDisabled, mock.Anything).Return()
			}

			handler.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusUnauthorized, rr.Code)
			assert.Equal(t, `Bearer error="invalid_token"`, rr.Header().Get("WWW-Authenticate"))

			var body map[string]interface{}
			require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
			assert.Equal(t, "invalid_token", body["error"])
			assert.Equal(t, test.description, body["error_description"])
		})
	}
}
