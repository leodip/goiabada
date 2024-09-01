package accounthandlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/csrf"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/adminconsole/internal/handlers"
	"github.com/leodip/goiabada/core/communication"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/phonecountries"
	"github.com/leodip/goiabada/core/stringutil"
	"github.com/leodip/goiabada/core/validators"
)

func HandleAccountPhoneGet(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	database data.Database,
) http.HandlerFunc {

	phoneCountries := phonecountries.Get()

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		if savedSuccessfully != nil {
			err = sess.Save(r, w)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		bind := map[string]interface{}{
			"selectedPhoneCountryUniqueId": user.PhoneNumberCountryUniqueId,
			"phoneNumber":                  user.PhoneNumber,
			"phoneNumberVerified":          user.PhoneNumberVerified,
			"phoneCountries":               phoneCountries,
			"savedSuccessfully":            len(savedSuccessfully) > 0,
			"smsEnabled":                   len(settings.SMSProvider) > 0,
			"csrfField":                    csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountPhoneVerifyGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if user.PhoneNumberVerified {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("trying to access phone verification page but phone is already verified")))
			return
		}

		if len(user.PhoneNumberVerificationCodeEncrypted) == 0 || !user.PhoneNumberVerificationCodeIssuedAt.Valid {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("trying to access phone verification page but phone verification info is not present")))
			return
		}

		bind := map[string]interface{}{
			"error":     nil,
			"csrfField": csrf.TemplateField(r),
		}

		err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone_verify.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
	}
}

func HandleAccountPhoneVerifyPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error":     message,
				"csrfField": csrf.TemplateField(r),
			}

			err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone_verify.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		invalidCodeMessage := "The verification code provided is either invalid or has expired. To proceed, kindly request a new verification code and try again."
		if len(user.PhoneNumberVerificationCodeEncrypted) == 0 || !user.PhoneNumberVerificationCodeIssuedAt.Valid {
			renderError(invalidCodeMessage)
			return
		}

		code := r.FormValue("code")

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		phoneNumberVerificationCode, err := encryption.DecryptText(user.PhoneNumberVerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if phoneNumberVerificationCode != code ||
			user.PhoneNumberVerificationCodeIssuedAt.Time.Add(2*time.Minute).Before(time.Now().UTC()) {

			renderError(invalidCodeMessage)
			return
		}

		user.PhoneNumberVerificationCodeEncrypted = nil
		user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Valid: false}
		user.PhoneNumberVerified = true

		err = database.UpdateUser(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditVerifiedPhone, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.Get().BaseURL+"/account/phone", http.StatusFound)
	}
}

func HandleAccountPhoneSendVerificationPost(
	httpHelper handlers.HttpHelper,
	authHelper handlers.AuthHelper,
	database data.Database,
	smsSender handlers.SmsSender,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	type sendVerificationResult struct {
		PhoneVerified         bool
		PhoneVerificationSent bool
		TooManyRequests       bool
		WaitInSeconds         int
	}

	return func(w http.ResponseWriter, r *http.Request) {

		result := sendVerificationResult{}

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		if len(user.PhoneNumberVerificationCodeEncrypted) > 0 && user.PhoneNumberVerificationCodeIssuedAt.Valid {
			const waitTime = 90 * time.Second
			remainingTime := int(user.PhoneNumberVerificationCodeIssuedAt.Time.Add(waitTime).Sub(time.Now().UTC()).Seconds())
			if remainingTime > 0 {
				result.TooManyRequests = true
				result.WaitInSeconds = remainingTime

				httpHelper.EncodeJson(w, r, result)
				return
			}
		}

		if user.PhoneNumberVerified {
			result.PhoneVerified = true
			httpHelper.EncodeJson(w, r, result)
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		verificationCode := stringutil.GenerateRandomNumbers(6)
		phoneNumberVerificationCodeEncrypted, err := encryption.EncryptText(verificationCode, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}
		user.PhoneNumberVerificationCodeEncrypted = phoneNumberVerificationCodeEncrypted
		utcNow := time.Now().UTC()
		user.PhoneNumberVerificationCodeIssuedAt = sql.NullTime{Time: utcNow, Valid: true}
		err = database.UpdateUser(nil, user)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		input := &communication.SendSMSInput{
			To:   user.PhoneNumber,
			Body: fmt.Sprintf("Your verification code is %v", verificationCode),
		}
		err = smsSender.SendSMS(r.Context(), input)
		if err != nil {
			httpHelper.JsonError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditSentPhoneVerificationMessage, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		result.PhoneVerificationSent = true
		httpHelper.EncodeJson(w, r, result)
	}
}

func HandleAccountPhonePost(
	httpHelper handlers.HttpHelper,
	httpSession sessions.Store,
	authHelper handlers.AuthHelper,
	database data.Database,
	phoneValidator handlers.PhoneValidator,
	inputSanitizer handlers.InputSanitizer,
	auditLogger handlers.AuditLogger,
) http.HandlerFunc {

	phoneCountries := phonecountries.Get()

	return func(w http.ResponseWriter, r *http.Request) {

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)

		var jwtInfo oauth.JwtInfo
		if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
			jwtInfo = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		}

		sub, err := jwtInfo.IdToken.Claims.GetSubject()
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserBySubject(nil, sub)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		input := &validators.ValidatePhoneInput{
			PhoneCountryUniqueId: r.FormValue("phoneCountryUniqueId"),
			PhoneNumber:          strings.TrimSpace(r.FormValue("phoneNumber")),
		}

		err = phoneValidator.ValidatePhone(r.Context(), input)
		if err != nil {
			if valError, ok := err.(*customerrors.ErrorDetail); ok {
				bind := map[string]interface{}{
					"selectedPhoneCountryUniqueId": input.PhoneCountryUniqueId,
					"phoneNumber":                  input.PhoneNumber,
					"phoneNumberVerified":          user.PhoneNumberVerified,
					"phoneCountries":               phoneCountries,
					"csrfField":                    csrf.TemplateField(r),
					"smsEnabled":                   len(settings.SMSProvider) > 0,
					"error":                        valError.GetDescription(),
				}

				err = httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/account_phone.html", bind)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				return
			} else {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		var phoneCountry phonecountries.PhoneCountry
		found := false
		for _, c := range phoneCountries {
			if c.UniqueId == input.PhoneCountryUniqueId {
				found = true
				phoneCountry = c
				break
			}
		}

		if !found && len(input.PhoneCountryUniqueId) > 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("Phone country is invalid: "+input.PhoneCountryUniqueId)))
			return
		}

		user.PhoneNumberCountryUniqueId = input.PhoneCountryUniqueId
		user.PhoneNumberCountryCallingCode = phoneCountry.CallingCode
		user.PhoneNumber = inputSanitizer.Sanitize(input.PhoneNumber)
		user.PhoneNumberVerified = false

		err = database.UpdateUser(nil, user)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		sess, err := httpSession.Get(r, constants.SessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		sess.AddFlash("true", "savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		auditLogger.Log(constants.AuditUpdatedUserPhone, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": authHelper.GetLoggedInSubject(r),
		})

		http.Redirect(w, r, config.Get().BaseURL+"/account/phone", http.StatusFound)
	}
}
