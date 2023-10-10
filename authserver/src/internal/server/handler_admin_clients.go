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
			if s.isLoggedIn(jwtInfo) {
				http.Redirect(w, r, lib.GetBaseUrl()+"/unauthorized", http.StatusFound)
				return
			} else {
				s.redirToAuthorize(w, r, "admin-website", lib.GetBaseUrl()+r.RequestURI, "openid authserver:admin-website")
				return
			}
		}

		clients, err := s.database.GetClients()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		clients[1].Enabled = false
		clients[1].Description = "It is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout."

		bind := map[string]interface{}{
			"clients": clients,
		}

		err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/admin_clients.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}
