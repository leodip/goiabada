package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	core "github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/dtos"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/spf13/viper"
)

func (s *Server) handleAccountPhoneGet() http.HandlerFunc {

	phoneCountries := lib.GetPhoneCountries()

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)

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

		accountPhone := dtos.AccountPhoneFromUser(user)

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		phoneSavedSuccessfully := sess.Flashes("phoneSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"accountPhone":           accountPhone,
			"phoneCountries":         phoneCountries,
			"phoneSavedSuccessfully": len(phoneSavedSuccessfully) > 0,
			"smsVerificationEnabled": settings.SMSVerificationEnabled,
			"csrfField":              csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/account_phone.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAccountPhoneVerifyPost() http.HandlerFunc {

	type verifyInput struct {
		Code string `json:"code"`
	}

	type verifyResult struct {
		RequiresAuth             bool
		InvalidCode              bool
		VerifiedPhone            bool
		TooManyIncorrectAttempts bool
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := verifyResult{
			RequiresAuth: true,
		}

		var jwtInfo dtos.JwtInfo
		if r.Context().Value(common.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(common.ContextKeyJwtInfo).(dtos.JwtInfo)

			if jwtInfo.IsIdTokenPresentAndValid() {
				result.RequiresAuth = false
			}
		}

		if result.RequiresAuth {
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

		if user.PhoneNumberVerificationHit > 5 {
			result.TooManyIncorrectAttempts = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		if len(user.PhoneNumberVerificationCodeEncrypted) == 0 || user.PhoneNumberVerificationCodeIssuedAt == nil {
			result.InvalidCode = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}
		var verifyInput verifyInput
		if err := json.Unmarshal(body, &verifyInput); err != nil {
			s.jsonError(w, r, err)
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		phoneNumberVerificationCode, err := lib.DecryptText(user.PhoneNumberVerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		if phoneNumberVerificationCode != verifyInput.Code ||
			user.PhoneNumberVerificationCodeIssuedAt.Add(5*time.Minute).Before(time.Now().UTC()) {

			user.PhoneNumberVerificationHit = user.PhoneNumberVerificationHit + 1
			_, err = s.database.UpdateUser(user)
			if err != nil {
				s.jsonError(w, r, err)
				return
			}

			result.InvalidCode = true
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		user.PhoneNumberVerificationCodeEncrypted = nil
		user.PhoneNumberVerificationCodeIssuedAt = nil
		user.PhoneNumberVerified = true
		user.PhoneNumberVerificationHit = 0

		_, err = s.database.UpdateUser(user)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		result.VerifiedPhone = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}
}

func (s *Server) handleAccountPhoneSendVerificationPost(smsSender smsSender) http.HandlerFunc {

	type sendVerificationResult struct {
		RequiresAuth          bool
		PhoneVerified         bool
		PhoneVerificationSent bool
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

			if jwtInfo.IsIdTokenPresentAndValid() {
				result.RequiresAuth = false
			}
		}

		if result.RequiresAuth {
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
		user, err = s.database.UpdateUser(user)
		if err != nil {
			s.jsonError(w, r, err)
			return
		}

		input := &core.SendSMSInput{
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

		accountPhone := &dtos.AccountPhone{
			PhoneNumberCountry: r.FormValue("phoneCountry"),
			PhoneNumber:        strings.TrimSpace(r.FormValue("phoneNumber")),
		}

		err = phoneValidator.ValidatePhone(r.Context(), accountPhone)
		if err != nil {
			bind := map[string]interface{}{
				"accountPhone":           accountPhone,
				"phoneCountries":         phoneCountries,
				"csrfField":              csrf.TemplateField(r),
				"smsVerificationEnabled": settings.SMSVerificationEnabled,
				"error":                  err,
			}

			err = s.renderTemplate(w, r, "/layouts/admin_layout.html", "/account_phone.html", bind)
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

		space := regexp.MustCompile(`\s+`)
		accountPhone.PhoneNumber = space.ReplaceAllString(accountPhone.PhoneNumber, "")
		user.PhoneNumber = fmt.Sprintf("%v %v", accountPhone.PhoneNumberCountry, accountPhone.PhoneNumber)
		user.PhoneNumberVerified = false

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
		sess.AddFlash("true", "phoneSavedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		http.Redirect(w, r, viper.GetString("BaseUrl")+"/account/phone", http.StatusFound)
	}
}
