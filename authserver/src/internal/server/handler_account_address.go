package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/biter777/countries"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/spf13/viper"
)

func (s *Server) handleAccountAddressGet() http.HandlerFunc {

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

	return func(w http.ResponseWriter, r *http.Request) {

		requiresAuth := true

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)

			if jwtInfo.IsIdTokenPresentAndValid() {
				requiresAuth = false
			}
		}

		if requiresAuth {
			s.redirToAuthorize(w, r, "account-management", r.RequestURI)
			return
		}

		sub, err := jwtInfo.IdTokenClaims.GetSubject()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		user, err := s.database.GetUserBySubject(sub)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		accountAddress := dtos.AccountAddressFromUser(user)

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		addressSavedSuccessfully := sess.Flashes("addressSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"accountAddress":           accountAddress,
			"countries":                countries,
			"addressSavedSuccessfully": len(addressSavedSuccessfully) > 0,
			"csrfField":                csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/account_address.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountAddressPost(addressValidator addressValidator) http.HandlerFunc {

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

	return func(w http.ResponseWriter, r *http.Request) {

		requiresAuth := true

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)

			if jwtInfo.IsIdTokenPresentAndValid() {
				requiresAuth = false
			}
		}

		if requiresAuth {
			s.redirToAuthorize(w, r, "account-management", r.RequestURI)
			return
		}

		sub, err := jwtInfo.IdTokenClaims.GetSubject()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		accountAddress := &dtos.AccountAddress{
			AddressLine1:      strings.TrimSpace(r.FormValue("addressLine1")),
			AddressLine2:      strings.TrimSpace(r.FormValue("addressLine2")),
			AddressLocality:   strings.TrimSpace(r.FormValue("addressLocality")),
			AddressRegion:     strings.TrimSpace(r.FormValue("addressRegion")),
			AddressPostalCode: strings.TrimSpace(r.FormValue("addressPostalCode")),
			AddressCountry:    strings.TrimSpace(r.FormValue("addressCountry")),
		}

		err = addressValidator.ValidateAddress(r.Context(), accountAddress)
		if err != nil {
			bind := map[string]interface{}{
				"accountAddress": accountAddress,
				"countries":      countries,
				"csrfField":      csrf.TemplateField(r),
				"error":          err,
			}

			err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/account_address.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}
			return
		}

		user, err := s.database.GetUserBySubject(sub)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if len(accountAddress.AddressLine1) > 0 {
			user.AddressLine1 = accountAddress.AddressLine1
		} else {
			user.AddressLine1 = ""
		}

		if len(accountAddress.AddressLine2) > 0 {
			user.AddressLine2 = accountAddress.AddressLine2
		} else {
			user.AddressLine2 = ""
		}

		if len(accountAddress.AddressLocality) > 0 {
			user.AddressLocality = accountAddress.AddressLocality
		} else {
			user.AddressLocality = ""
		}

		if len(accountAddress.AddressRegion) > 0 {
			user.AddressRegion = accountAddress.AddressRegion
		} else {
			user.AddressRegion = ""
		}

		if len(accountAddress.AddressPostalCode) > 0 {
			user.AddressPostalCode = accountAddress.AddressPostalCode
		} else {
			user.AddressPostalCode = ""
		}

		if len(accountAddress.AddressCountry) > 0 {
			user.AddressCountry = accountAddress.AddressCountry
		} else {
			user.AddressCountry = ""
		}

		_, err = s.database.UpdateUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		sess.AddFlash("true", "addressSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, viper.GetString("BaseUrl")+"/account/address", http.StatusFound)
	}
}
