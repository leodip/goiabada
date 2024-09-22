package handlers

import (
	"net/http"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/oauth"
)

func HandleIndexGet(
	authHelper AuthHelper,
	httpHelper HttpHelper,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bind := map[string]interface{}{}

		bind["AuthServerBaseUrl"] = config.GetAuthServer().BaseURL

		isAuthenticated := false
		loggedInUser := ""
		logoutLink := ""

		var jwtInfo oauth.JwtInfo
		var ok bool
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
			if ok {
				isAuthenticated = authHelper.IsAuthenticated(jwtInfo)
				if isAuthenticated {
					loggedInUser = jwtInfo.IdToken.GetStringClaim("email")
					logoutLink = "/auth/logout"
				}
			}
		}

		bind["IsAuthenticated"] = isAuthenticated
		bind["LoggedInUser"] = loggedInUser
		bind["LogoutLink"] = logoutLink

		err := httpHelper.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/index.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}
