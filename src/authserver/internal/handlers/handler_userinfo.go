package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/apiresponse"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/userclaims"
	"github.com/leodip/goiabada/core/errs"
)

// userinfoDatabase is what the userinfo endpoint needs: the caller's user row and the claims
// hanging off it.
type userinfoDatabase interface {
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	GroupsLoadAttributes(ctx context.Context, tx *sql.Tx, groups []models.Group) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)
	UserLoadAttributes(ctx context.Context, tx *sql.Tx, user *models.User) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *models.User) error
}

func HandleUserInfoGetPost(
	httpHelper HttpHelper,
	database userinfoDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			httpHelper.InternalServerError(w, r, errs.New("unable to get validated token from context"))
			return
		}

		sub := jwtToken.GetStringClaim("sub")
		if len(sub) == 0 {
			httpHelper.InternalServerError(w, r, errs.New("unable to get the sub claim from the access token"))
			return
		}

		user, err := database.GetUserBySubject(r.Context(), nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user == nil {
			// 401 invalid_token rather than 500. RFC 6750 section 3.1: a token that is
			// "invalid for other reasons" SHOULD be answered with 401 invalid_token, and a
			// token naming a subject that no longer has a row is exactly that. OIDC Core
			// 5.3.3 sends this endpoint's error responses through RFC 6750. 500 was
			// permitted but told the client to retry a request that can only fail again,
			// where 401 tells it to obtain a new token, which is the whole point of the
			// distinction (#279 decision 14).
			httpHelper.JsonError(w, r, apiresponse.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate(
				"invalid_token", "The user could not be found.", http.StatusUnauthorized,
				`Bearer error="invalid_token"`))
			return
		}

		if !user.Enabled {
			auditLogger.Log(r.Context(), audit.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})

			// 401 invalid_token, for the reason the not-found branch above gives: the
			// token is no longer valid for this account and the client's remedy is a new
			// one, not a retry (#279 decision 14).
			httpHelper.JsonError(w, r, apiresponse.NewErrorDetailWithHttpStatusCodeAndWWWAuthenticate(
				"invalid_token", "The user account is disabled.", http.StatusUnauthorized,
				`Bearer error="invalid_token"`))
			return
		}

		err = database.UserLoadGroups(r.Context(), nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.GroupsLoadAttributes(r.Context(), nil, user.Groups)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.UserLoadAttributes(r.Context(), nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		claims := make(jwt.MapClaims)
		claims["sub"] = user.Subject

		// The same split JwtToken.HasScope performs internally, done once: a missing or
		// non-string scope claim yields one empty element, which matches nothing, exactly as
		// HasScope answers false for everything in that case.
		scopes := strings.Split(jwtToken.GetStringClaim("scope"), " ")

		// The two fields after the port are this endpoint's side of the two divergences
		// userclaims keeps as inputs: the base URL is read from the global configuration here
		// and injected in issuance, and all three filter sites read the ID token's include flag
		// (#387 decision 5). updated_at was a third until it turned out to be a defect rather
		// than a difference: it now rides with the profile scope at every site, which is what
		// this endpoint already did.
		mapper := userclaims.Mapper{
			Database:  database,
			BaseURL:   config.GetAuthServer().BaseURL,
			Inclusion: userclaims.InclusionIdToken,
		}
		mapper.AddOpenIdConnectClaims(r.Context(), claims, user, scopes)
		mapper.AddGroupClaims(claims, user, scopes)
		mapper.AddAttributeClaims(claims, user, scopes)

		httpHelper.EncodeJson(w, r, claims)
	}
}
