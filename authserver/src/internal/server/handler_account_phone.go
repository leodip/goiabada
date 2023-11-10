package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	core_senders "github.com/leodip/goiabada/internal/core/senders"
	core_validators "github.com/leodip/goiabada/internal/core/validators"
	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAccountPhoneGet() http.HandlerFunc {

	phoneCountries := lib.GetPhoneCountries()

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
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

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		phoneNumberCountry := ""
		phoneNumber := ""

		if len(user.PhoneNumber) > 0 {
			parts := strings.SplitN(user.PhoneNumber, " ", 2)
			if len(parts) == 2 {
				phoneNumberCountry = parts[0]
				phoneNumber = parts[1]
			}
		}

		bind := map[string]interface{}{
			"phoneNumberCountry":  phoneNumberCountry,
			"phoneNumber":         phoneNumber,
			"phoneNumberVerified": user.PhoneNumberVerified,
			"phoneCountries":      phoneCountries,
			"savedSuccessfully":   len(savedSuccessfully) > 0,
			"smsEnabled":          settings.SMSEnabled,
			"csrfField":           csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountPhoneVerifyGet() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
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

		if user.PhoneNumberVerified {
			s.internalServerError(w, r, errors.New("trying to access phone verification page but phone is already verified"))
			return
		}

		if len(user.PhoneNumberVerificationCodeEncrypted) == 0 || user.PhoneNumberVerificationCodeIssuedAt == nil {
			s.internalServerError(w, r, errors.New("trying to access phone verification page but phone verification info is not present"))
			return
		}

		bind := map[string]interface{}{
			"error":     nil,
			"csrfField": csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone_verify.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountPhoneVerifyPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
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

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone_verify.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
		}

		if user.PhoneNumberVerificationHit > 5 {
			renderError("Apologies, but it seems you've entered an excessive number of incorrect codes. To proceed, please request a new verification code and attempt the process again.")
			return
		}

		invalidCodeMessage := "The verification code provided is either invalid or has expired. To proceed, kindly request a new verification code and try again."
		if len(user.PhoneNumberVerificationCodeEncrypted) == 0 || user.PhoneNumberVerificationCodeIssuedAt == nil {
			renderError(invalidCodeMessage)
			return
		}

		code := r.FormValue("code")

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		phoneNumberVerificationCode, err := lib.DecryptText(user.PhoneNumberVerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if phoneNumberVerificationCode != code ||
			user.PhoneNumberVerificationCodeIssuedAt.Add(5*time.Minute).Before(time.Now().UTC()) {

			user.PhoneNumberVerificationHit = user.PhoneNumberVerificationHit + 1
			_, err = s.database.SaveUser(user)
			if err != nil {
				s.internalServerError(w, r, err)
				return
			}

			renderError(invalidCodeMessage)
			return
		}

		user.PhoneNumberVerificationCodeEncrypted = nil
		user.PhoneNumberVerificationCodeIssuedAt = nil
		user.PhoneNumberVerified = true
		user.PhoneNumberVerificationHit = 0

		_, err = s.database.SaveUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, lib.GetBaseUrl()+"/account/phone", http.StatusFound)
	}
}

func (s *Server) handleAccountPhoneSendVerificationPost(smsSender smsSender) http.HandlerFunc {

	type sendVerificationResult struct {
		PhoneVerified         bool
		PhoneVerificationSent bool
		TooManyRequests       bool
		WaitInSeconds         int
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := sendVerificationResult{}

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
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

		if len(user.PhoneNumberVerificationCodeEncrypted) > 0 && user.PhoneNumberVerificationCodeIssuedAt != nil {
			const waitTime = 90 * time.Second
			remainingTime := int(user.PhoneNumberVerificationCodeIssuedAt.Add(waitTime).Sub(time.Now().UTC()).Seconds())
			if remainingTime > 0 {
				result.TooManyRequests = true
				result.WaitInSeconds = remainingTime

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(result)
				return
			}
		}

		if user.PhoneNumberVerified {
			result.PhoneVerified = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		verificationCode := lib.GenerateRandomNumbers(6)
		phoneNumberVerificationCodeEncrypted, err := lib.EncryptText(verificationCode, settings.AESEncryptionKey)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		user.PhoneNumberVerificationCodeEncrypted = phoneNumberVerificationCodeEncrypted
		utcNow := time.Now().UTC()
		user.PhoneNumberVerificationCodeIssuedAt = &utcNow
		user.PhoneNumberVerificationHit = 0
		user, err = s.database.SaveUser(user)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		input := &core_senders.SendSMSInput{
			To:   user.PhoneNumber,
			Body: fmt.Sprintf("Your verification code is %v", verificationCode),
		}
		err = smsSender.SendSMS(r.Context(), input)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result.PhoneVerificationSent = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAccountPhonePost(phoneValidator phoneValidator) http.HandlerFunc {

	phoneCountries := lib.GetPhoneCountries()

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)
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

		input := &core_validators.ValidatePhoneInput{
			PhoneNumberCountry: r.FormValue("phoneCountry"),
			PhoneNumber:        strings.TrimSpace(r.FormValue("phoneNumber")),
		}

		err = phoneValidator.ValidatePhone(r.Context(), input)
		if err != nil {
			if valError, ok := err.(*customerrors.ValidationError); ok {
				bind := map[string]interface{}{
					"phoneNumberCountry":  input.PhoneNumberCountry,
					"phoneNumber":         input.PhoneNumber,
					"phoneNumberVerified": user.PhoneNumberVerified,
					"phoneCountries":      phoneCountries,
					"csrfField":           csrf.TemplateField(r),
					"smsEnabled":          settings.SMSEnabled,
					"error":               valError.Description,
				}

				err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind)
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

		user.PhoneNumber = strings.TrimSpace(fmt.Sprintf("%v %v", input.PhoneNumberCountry, input.PhoneNumber))
		user.PhoneNumberVerified = false

		_, err = s.database.SaveUser(user)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, lib.GetBaseUrl()+"/account/phone", http.StatusFound)
	}
}
