package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/biter777/countries"
	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAccountAddressGet() http.HandlerFunc {

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, []string{"authserver:account"}) {
			s.redirToAuthorize(w, r, "system-website", lib.GetBaseUrl()+r.RequestURI)
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

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_address.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountAddressPost(addressValidator addressValidator,
	inputSanitizer inputSanitizer) http.HandlerFunc {

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessResource(jwtInfo, []string{"authserver:account"}) {
			s.redirToAuthorize(w, r, "system-website", lib.GetBaseUrl()+r.RequestURI)
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
			if valError, ok := err.(*customerrors.ValidationError); ok {
				bind := map[string]interface{}{
					"accountAddress": accountAddress,
					"countries":      countries,
					"csrfField":      csrf.TemplateField(r),
					"error":          valError.Description,
				}

				err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_address.html", bind)
				if err != nil {
					s.internalServerError(w, r, err)
					return
				}
				return
			} else {
				s.internalServerError(w, r, err)
				return
			}
		}

		user, err := s.database.GetUserBySubject(sub)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if len(accountAddress.AddressLine1) > 0 {
			user.AddressLine1 = strings.TrimSpace(inputSanitizer.Sanitize(accountAddress.AddressLine1))
		} else {
			user.AddressLine1 = ""
		}

		if len(accountAddress.AddressLine2) > 0 {
			user.AddressLine2 = strings.TrimSpace(inputSanitizer.Sanitize(accountAddress.AddressLine2))
		} else {
			user.AddressLine2 = ""
		}

		if len(accountAddress.AddressLocality) > 0 {
			user.AddressLocality = strings.TrimSpace(inputSanitizer.Sanitize(accountAddress.AddressLocality))
		} else {
			user.AddressLocality = ""
		}

		if len(accountAddress.AddressRegion) > 0 {
			user.AddressRegion = strings.TrimSpace(inputSanitizer.Sanitize(accountAddress.AddressRegion))
		} else {
			user.AddressRegion = ""
		}

		if len(accountAddress.AddressPostalCode) > 0 {
			user.AddressPostalCode = strings.TrimSpace(inputSanitizer.Sanitize(accountAddress.AddressPostalCode))
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

		http.Redirect(w, r, lib.GetBaseUrl()+"/account/address", http.StatusFound)
	}
}
