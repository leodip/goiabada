package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	core "github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAccountEmailGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessAccountPages(jwtInfo) {
			s.redirToAuthorize(w, r, "account-management", lib.GetBaseUrl()+r.RequestURI)
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

		accountEmail := dtos.AccountEmailFromUser(user)

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		emailSavedSuccessfully := sess.Flashes("emailSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"emailSavedSuccessfully": len(emailSavedSuccessfully) > 0,
			"accountEmail":           accountEmail,
			"csrfField":              csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountEmailSendVerificationPost(emailSender emailSender) http.HandlerFunc {

	type sendVerificationResult struct {
		RequiresAuth          bool
		EmailVerified         bool
		EmailVerificationSent bool
		EmailDestination      string
		TooManyRequests       bool
		WaitInSeconds         int
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := sendVerificationResult{
			RequiresAuth: true,
		}

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if s.isAuthorizedToAccessAccountPages(jwtInfo) {
			result.RequiresAuth = false
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		sub, err := jwtInfo.IdTokenClaims.GetSubject()
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		user, err := s.database.GetUserBySubject(sub)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if len(user.EmailVerificationCodeEncrypted) > 0 && user.EmailVerificationCodeIssuedAt != nil {
			const waitTime = 90 * time.Second
			remainingTime := int(user.EmailVerificationCodeIssuedAt.Add(waitTime).Sub(time.Now().UTC()).Seconds())
			if remainingTime > 0 {
				result.TooManyRequests = true
				result.WaitInSeconds = remainingTime

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
				return
			}
		}

		if user.EmailVerified {
			result.EmailVerified = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		verificationCode := lib.GenerateSecureRandomString(32)
		emailVerificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user.EmailVerificationCodeEncrypted = emailVerificationCodeEncrypted
		utcNow := time.Now().UTC()
		user.EmailVerificationCodeIssuedAt = &utcNow
		user, err = s.database.UpdateUser(user)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"name": user.GetFullName(),
			"link": lib.GetBaseUrl() + "/account/email-verify?code=" + verificationCode,
		}
		buf, err := s.renderTemplateToBuffer(r, "/layouts/email_layout.html", "/emails/email_verification.html", bind)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		input := &core.SendEmailInput{
			To:       user.Email,
			Subject:  "Email verification",
			HtmlBody: buf.String(),
		}
		err = emailSender.SendEmail(r.Context(), input)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result.EmailVerificationSent = true
		result.EmailDestination = user.Email
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAccountEmailVerifyGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessAccountPages(jwtInfo) {
			s.redirToAuthorize(w, r, "account-management", lib.GetBaseUrl()+r.RequestURI)
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

		code := r.URL.Query().Get("code")
		if len(code) == 0 {
			s.internalServerError(w, r, errors.New("expecting code to verify the email, but it's empty"))
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		emailVerificationCode, err := lib.DecryptText(user.EmailVerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, errors.New("unable to decrypt email verification code"))
			return
		}

		if emailVerificationCode != code || user.EmailVerificationCodeIssuedAt.Add(5*time.Minute).Before(time.Now().UTC()) {
			bind := map[string]interface{}{}

			err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_email_verification.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
			return
		}

		user.EmailVerified = true
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = nil
		_, err = s.database.UpdateUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, lib.GetBaseUrl()+"/account/email", http.StatusFound)
	}
}

func (s *Server) handleAccountEmailPost(emailValidator emailValidator, emailSender emailSender) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
		}

		if !s.isAuthorizedToAccessAccountPages(jwtInfo) {
			s.redirToAuthorize(w, r, "account-management", lib.GetBaseUrl()+r.RequestURI)
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

		accountEmail := &dtos.AccountEmail{
			Email:             strings.ToLower(strings.TrimSpace(r.FormValue("email"))),
			EmailConfirmation: strings.ToLower(strings.TrimSpace(r.FormValue("emailConfirmation"))),
			EmailVerified:     user.EmailVerified,
			Subject:           sub,
		}
		err = emailValidator.ValidateEmailUpdate(r.Context(), accountEmail)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				bind := map[string]interface{}{
					"accountEmail": accountEmail,
					"csrfField":    csrf.TemplateField(r),
					"error":        valError.Description,
				}

				err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_email.html", bind)
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

		if len(accountEmail.Email) > 0 {
			user.Email = accountEmail.Email

		} else {
			user.Email = ""
		}
		user.EmailVerified = false
		user.EmailVerificationCodeEncrypted = nil
		user.EmailVerificationCodeIssuedAt = nil

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
		sess.AddFlash("true", "emailSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, lib.GetBaseUrl()+"/account/email", http.StatusFound)
	}
}
