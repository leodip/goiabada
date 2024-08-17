package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/customerrors"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/oauth"
)

func HandleUserInfoGetPost(
	httpHelper HttpHelper,
	database data.Database,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtToken oauth.JwtToken
		var ok bool
		if r.Context().Value(constants.ContextKeyBearerToken) != nil {
			jwtToken, ok = r.Context().Value(constants.ContextKeyBearerToken).(oauth.JwtToken)
			if !ok {
				httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("unable to cast the context value to JwtToken")))
				return
			}
		} else {
			httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode(
				"invalid_token", "Access to this resource is denied. Please provide a valid access token in the Authorization header and try again.",
				http.StatusUnauthorized))
			return
		}

		isAuthorized := jwtToken.HasScope(constants.AuthServerResourceIdentifier + ":" + constants.UserinfoPermissionIdentifier)

		if !isAuthorized {
			httpHelper.JsonError(w, r, customerrors.NewErrorDetailWithHttpStatusCode("insufficient_scope",
				"The access token is not authorized to access this resource. Ensure to include a valid OpenID Connect scope in your authorization request and try again.",
				http.StatusForbidden))
			return
		}

		sub := jwtToken.GetStringClaim("sub")
		if len(sub) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("unable to get the sub claim from the access token")))
			return
		}

		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user == nil {
			httpHelper.JsonError(w, r, customerrors.NewErrorDetail("server_error",
				"The user could not be found."))
			return
		}

		if !user.Enabled {
			auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})

			httpHelper.JsonError(w, r, customerrors.NewErrorDetail("server_error", "The user account is disabled."))
			return
		}

		err = database.UserLoadGroups(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.GroupsLoadAttributes(nil, user.Groups)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.UserLoadAttributes(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		claims := make(jwt.MapClaims)
		claims["sub"] = user.Subject

		addClaimIfNotEmpty := func(claims jwt.MapClaims, claimName string, claimValue string) {
			if len(strings.TrimSpace(claimValue)) > 0 {
				claims[claimName] = claimValue
			}
		}

		if jwtToken.HasScope("profile") {
			addClaimIfNotEmpty(claims, "name", user.GetFullName())
			addClaimIfNotEmpty(claims, "given_name", user.GivenName)
			addClaimIfNotEmpty(claims, "middle_name", user.MiddleName)
			addClaimIfNotEmpty(claims, "family_name", user.FamilyName)
			addClaimIfNotEmpty(claims, "nickname", user.Nickname)
			addClaimIfNotEmpty(claims, "preferred_username", user.Username)
			claims["profile"] = fmt.Sprintf("%v/account/profile", config.AdminConsoleBaseUrl)
			addClaimIfNotEmpty(claims, "website", user.Website)
			addClaimIfNotEmpty(claims, "gender", user.Gender)
			if user.BirthDate.Valid {
				claims["birthdate"] = user.BirthDate.Time.Format("2006-01-02")
			}
			addClaimIfNotEmpty(claims, "zoneinfo", user.ZoneInfo)
			addClaimIfNotEmpty(claims, "locale", user.Locale)
			claims["updated_at"] = user.UpdatedAt.Time.UTC().Unix()
		}

		if jwtToken.HasScope("email") {
			addClaimIfNotEmpty(claims, "email", user.Email)
			claims["email_verified"] = user.EmailVerified
		}

		if jwtToken.HasScope("address") && user.HasAddress() {
			claims["address"] = user.GetAddressClaim()
		}

		if jwtToken.HasScope("phone") {
			addClaimIfNotEmpty(claims, "phone_number", user.PhoneNumber)
			claims["phone_number_verified"] = user.PhoneNumberVerified
		}

		if jwtToken.HasScope("groups") {
			groups := []string{}
			for _, group := range user.Groups {
				if group.IncludeInIdToken {
					groups = append(groups, group.GroupIdentifier)
				}
			}
			if len(groups) > 0 {
				claims["groups"] = groups
			}
		}

		if jwtToken.HasScope("attributes") {
			attributes := map[string]string{}
			for _, attribute := range user.Attributes {
				if attribute.IncludeInIdToken {
					attributes[attribute.Key] = attribute.Value
				}
			}

			for _, group := range user.Groups {
				for _, attribute := range group.Attributes {
					if attribute.IncludeInIdToken {
						attributes[attribute.Key] = attribute.Value
					}
				}
			}
			if len(attributes) > 0 {
				claims["attributes"] = attributes
			}
		}
		httpHelper.EncodeJson(w, r, claims)
	}
}
