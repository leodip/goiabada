package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/pkg/errors"

	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/otp"
)

func HandleAuthOtpGet(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	otpSecretGenerator OtpSecretGenerator,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		requiredState := oauth.AuthStateLevel2OTP
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		sess, err := httpSession.Get(r, constants.AuthServerSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		// Fetch client to get display settings
		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

		displayInfo := getClientDisplayInfo(database, client)

		if user.OTPEnabled {

			delete(sess.Values, constants.SessionKeyOTPImage)
			delete(sess.Values, constants.SessionKeyOTPSecret)

			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			bind := map[string]interface{}{
				"error": nil,
				// The rendered form says which ceremony rendered it, and HandleAuthOtpPost refuses
				// a submission naming any other one. A code entered here after a second
				// /auth/authorize replaced the auth context would otherwise complete that other
				// request's level 2 (#79).
				"ceremonyId":              authContext.CeremonyId,
				"layoutShowClientSection": displayInfo.ShowSection,
				"layoutClientName":        displayInfo.ClientName,
				"layoutHasClientLogo":     displayInfo.HasLogo,
				"layoutClientLogoUrl":     displayInfo.LogoURL,
				"layoutClientDescription": displayInfo.Description,
				"layoutClientWebsiteUrl":  displayInfo.WebsiteURL,
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_otp.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		} else {
			// must enroll first

			// generate secret
			settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			base64Image, secretKey, err := otpSecretGenerator.GenerateOTPSecret(user.Email, settings.AppName)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			bind := map[string]interface{}{
				"error":                   nil,
				"ceremonyId":              authContext.CeremonyId,
				"base64Image":             base64Image,
				"secretKey":               secretKey,
				"layoutShowClientSection": displayInfo.ShowSection,
				"layoutClientName":        displayInfo.ClientName,
				"layoutHasClientLogo":     displayInfo.HasLogo,
				"layoutClientLogoUrl":     displayInfo.LogoURL,
				"layoutClientDescription": displayInfo.Description,
				"layoutClientWebsiteUrl":  displayInfo.WebsiteURL,
			}

			// save image and secret in the session state
			sess.Values[constants.SessionKeyOTPSecret] = secretKey
			sess.Values[constants.SessionKeyOTPImage] = base64Image
			err = httpSession.Save(r, w, sess)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_otp_enrollment.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}
	}
}

func HandleAuthOtpPost(
	httpHelper HttpHelper,
	httpSession sessions.Store,
	authHelper AuthHelper,
	database data.Database,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, err := authHelper.GetAuthContext(r)
		if err != nil {
			if errDetail, ok := err.(*customerrors.ErrorDetail); ok && errDetail.IsError(customerrors.ErrNoAuthContext) {
				var profileUrl = GetProfileURL()
				slog.Warn(fmt.Sprintf("auth context is missing, redirecting to %v", profileUrl))
				http.Redirect(w, r, profileUrl, http.StatusFound)
			} else {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		// Before the AuthState check, so an OTP prompt left open in another tab gets the 400
		// mismatch page rather than the 500 that a replaced context's state would produce. And
		// before the code is looked at: MatchStep is never reached, so TryConsumeUserOTPStep is
		// never reached either, and a stale submission cannot burn a step of a passcode the
		// ceremony the user is actually on still needs (#79, #111 decision 3).
		//
		// r.PostFormValue rather than r.FormValue, as on the other two bound forms: this form
		// posts to action="" and only the submitted body is a submission.
		if !ceremonyMatches(authContext.CeremonyId, r.PostFormValue(ceremonyIdField)) {
			rejectCeremonyMismatch(httpHelper, auditLogger, w, r, authContext)
			return
		}

		requiredState := oauth.AuthStateLevel2OTP
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		sess, err := httpSession.Get(r, constants.AuthServerSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		base64Image, secretKey := "", ""
		if val, ok := sess.Values[constants.SessionKeyOTPImage]; ok {
			base64Image = val.(string)
		}
		if val, ok := sess.Values[constants.SessionKeyOTPSecret]; ok {
			secretKey = val.(string)
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		// Fetch client to get display settings
		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("client not found")))
			return
		}

		displayInfo := getClientDisplayInfo(database, client)

		renderError := func(message string) {
			bind := map[string]interface{}{
				"error": message,
				// In the shared part of the map rather than in the enrollment-only half below,
				// because both templates carry the hidden input. Without it a single mistyped
				// code would end the ceremony: the retry would name no ceremony and be refused.
				"ceremonyId":              authContext.CeremonyId,
				"layoutShowClientSection": displayInfo.ShowSection,
				"layoutClientName":        displayInfo.ClientName,
				"layoutHasClientLogo":     displayInfo.HasLogo,
				"layoutClientLogoUrl":     displayInfo.LogoURL,
				"layoutClientDescription": displayInfo.Description,
				"layoutClientWebsiteUrl":  displayInfo.WebsiteURL,
			}

			template := "/auth_otp.html"
			if len(base64Image) > 0 && len(secretKey) > 0 {
				template = "/auth_otp_enrollment.html"
				bind["base64Image"] = base64Image
				bind["secretKey"] = secretKey
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", template, bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
		}

		// i18n surface: A — browser-flow form rerender.
		if !user.Enabled {
			auditLogger.Log(constants.AuditUserDisabled, map[string]interface{}{
				"userId": user.Id,
			})
			renderError(i18n.NewLocalizedError(i18n.ErrCodeOtpAccountDisabled, nil).Localize(r.Context()))
			return
		}

		otpCode := r.FormValue("otp")
		if len(otpCode) == 0 {
			renderError(i18n.NewLocalizedError(i18n.ErrCodeOtpCodeRequired, nil).Localize(r.Context()))
			return
		}

		incorrectOtpError := i18n.NewLocalizedError(i18n.ErrCodeOtpIncorrectCode, nil).Localize(r.Context())

		if user.OTPEnabled {
			// already has OTP enrolled; decrypt the stored secret to validate
			otpSecret, err := user.GetOTPSecret()
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			step, matched := otp.MatchStep(otpCode, otpSecret, time.Now().UTC())
			if !matched {
				// Every wrong code is a guess at three of a million, so this is the
				// counter the whole OTP budget exists to move (#219).
				credentialFailures.RecordCredentialFailure(r)
				auditLogger.Log(constants.AuditAuthFailedOtp, map[string]interface{}{
					"userId": user.Id,
				})
				renderError(incorrectOtpError)
				return
			}

			// requireOTPEnabled is true here: this claim asserts a factor, and that
			// assertion is only true of an enrolled authenticator. Without the term a
			// request that loaded the user before a concurrent disable could still claim
			// a step and be issued a token naming amr "otp" for an authenticator that had
			// just been removed (#111 decision 10).
			consumed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, true)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if !consumed {
				// A replayed step is refused exactly as a wrong code is, so it counts as
				// one: a code already spent proves nothing about who is submitting it.
				credentialFailures.RecordCredentialFailure(r)
				auditLogger.Log(constants.AuditOTPCodeReplayDetected, map[string]interface{}{
					"userId": user.Id,
					"step":   step,
				})
				auditLogger.Log(constants.AuditAuthFailedOtp, map[string]interface{}{
					"userId": user.Id,
				})
				renderError(incorrectOtpError)
				return
			}
		} else {
			// is enrolling to TOTP now
			step, matched := otp.MatchStep(otpCode, secretKey, time.Now().UTC())
			if !matched {
				credentialFailures.RecordCredentialFailure(r)
				auditLogger.Log(constants.AuditAuthFailedOtp, map[string]interface{}{
					"userId": user.Id,
				})
				renderError(incorrectOtpError)
				return
			}

			// requireOTPEnabled is false here: enrollment is establishing the
			// authenticator rather than asserting it, and otp_enabled is still off until
			// the write below (#111 decision 10). The claim comes first deliberately: if
			// the enable write then fails, a code is burned and the user retries with the
			// next one, whereas the reverse order would leave OTP enabled on a request
			// that was refused.
			consumed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			if !consumed {
				credentialFailures.RecordCredentialFailure(r)
				auditLogger.Log(constants.AuditOTPCodeReplayDetected, map[string]interface{}{
					"userId": user.Id,
					"step":   step,
				})
				auditLogger.Log(constants.AuditAuthFailedOtp, map[string]interface{}{
					"userId": user.Id,
				})
				renderError(incorrectOtpError)
				return
			}

			// save TOTP secret (encrypted at rest)
			if err := user.SetOTPSecret(secretKey); err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			user.OTPEnabled = true
			err = database.UpdateUser(nil, user)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			auditLogger.Log(constants.AuditEnabledOTP, map[string]interface{}{
				"userId": user.Id,
			})
		}

		// from this point the user is considered authenticated with otp

		auditLogger.Log(constants.AuditAuthSuccessOtp, map[string]interface{}{
			"userId": user.Id,
		})

		authContext.AddAuthMethod(enums.AuthMethodOTP.String())
		// Mark that real authentication occurred — used by handler_auth_completed
		// to decide whether to refresh the session's AuthTime.
		//
		// Deliberately does NOT set authContext.Level1AuthCompleted. OTP is level 2, and a
		// ceremony can arrive here having reused a session rather than entered a password,
		// so verifying OTP is no proof of level 1 and must not let a ceremony recreate a
		// session that was ended mid-flight (#129 decision 15).
		utcNow := time.Now().UTC()
		authContext.AuthenticatedAt = &utcNow
		authContext.AuthState = oauth.AuthStateAuthenticationCompleted
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/completed", http.StatusFound)
	}
}
