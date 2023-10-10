package server

import (
	"net/http"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminClientsGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		allowedScopes := []string{"authserver:admin-website"}
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, allowedScopes) {
			s.redirToAuthorize(w, r, "admin-website", lib.GetBaseUrl()+r.RequestURI, "openid authserver:admin-website")
			return
		}

		bind := map[string]interface{}{}

		err := s.renderTemplate(w, r, "/layouts/admin_layout.html", "/admin_clients.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
