package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/pkg/errors"

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

			// An enrolment key this ceremony generated before the user enrolled somewhere
			// else is dead now, and HandleAuthOtpPost picks the template for its error
			// rerender by whether one is present, so leaving it here would redraw the
			// enrolment page for a user who is already enrolled. Same clearing this arm did
			// when the seed and its image lived in two slots on the browser session (#242).
			authContext.OTPKeyURL = ""

			err = authHelper.SaveAuthContext(w, r, authContext)
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

			// Generate only when this ceremony has no usable key yet, so a reload of
			// /auth/otp renders the secret and QR code the user has already scanned.
			// Generating on every GET is the defect: it replaced the seed behind a scanned
			// QR code, so every code from it was then checked against a secret the user was
			// never shown (#242 part 3).
			//
			// A stored URL that will not parse counts as none, which is the failure the one
			// field brings with it. This handler is the only writer of it, so an unusable
			// value can only be a defect or a context shape this binary does not understand;
			// generating shows the user a fresh QR code to scan, where refusing would wedge
			// the ceremony on a 500 that every reload repeats (#247).
			secretKey, err := otp.SecretFromKeyURL(authContext.OTPKeyURL)
			if err != nil {
				settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
				keyURL, genErr := otpSecretGenerator.GenerateOTPSecret(user.Email, settings.AppName)
				if genErr != nil {
					httpHelper.InternalServerError(w, r, genErr)
					return
				}
				authContext.OTPKeyURL = keyURL

				secretKey, err = otp.SecretFromKeyURL(keyURL)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
			}

			// Drawn from the URL on every render rather than carried beside it, so the
			// ceremony holds one value and the image cannot come to disagree with the secret
			// the code is checked against (#247).
			base64Image, err := otp.RenderQRCodeImage(authContext.OTPKeyURL)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			err = authHelper.SaveAuthContext(w, r, authContext)
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

		// The enrolment key comes off the ceremony rather than out of a slot shared by the
		// whole browser, so a submission can only ever be checked against the secret the
		// same ceremony rendered. Empty for a user who is already enrolled, which is what
		// sends the error rerender below to the verification template (#242 decision 4).
		//
		// The secret is derived here because every enrolling path needs it; the QR code is
		// not, because only the error rerender does, and encoding a PNG on every submission
		// to discard it is work the ceremony no longer has to do (#247).
		keyURL := authContext.OTPKeyURL
		var secretKey string
		if keyURL != "" {
			secretKey, err = otp.SecretFromKeyURL(keyURL)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
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
			if keyURL != "" {
				base64Image, imgErr := otp.RenderQRCodeImage(keyURL)
				if imgErr != nil {
					httpHelper.InternalServerError(w, r, imgErr)
					return
				}
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

		// r.PostFormValue rather than r.FormValue, matching the ceremony id read above so both
		// reads in this function agree about what a submission is: r.Form merges the URL query
		// behind the body, so /auth/otp?otp=... would let a passcode arrive in the request
		// target, where it reaches the browser's history, the Referer of anything the page
		// loads, and the access log of every proxy in front of the deployment (#202).
		otpCode := r.PostFormValue("otp")
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
			// The user write and the OTP configuration generation's advance commit together,
			// so there is no state in which the authenticator is on and no session knows
			// (#242 decision 2).
			enrolledGeneration, err := EnableUserOTPTx(database, user)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// Overwrite what /auth/level2 captured with the value the increment returned.
			// This ceremony asked the level 2 question against generation N and has just
			// answered it by MOVING the counter to N+1, so promoting N at /auth/completed
			// would leave the session it is about to bind owing another second-factor prompt
			// immediately. The value comes from the read-back rather than from N+1 computed
			// here, so a concurrent change cannot be laundered into it (#242).
			authContext.OtpConfigGeneration = &enrolledGeneration

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
		// The enrolment key has done its work: this ceremony has just proved the user holds
		// the authenticator, and nothing downstream reads the field. Leaving it set carries a
		// spent credential through /auth/completed, /auth/consent and /auth/issue, and leaves
		// it in the cookie of a ceremony abandoned after enrolling until a later
		// /auth/authorize replaces the context, whose ceiling is the cookie's own one-year
		// maximum age. Same discipline as User.SetOTPSecret, which blanks the plaintext seed
		// once it has encrypted it (#82, #247).
		authContext.OTPKeyURL = ""

		// Rotate the browser session's identifier here too, for the same reason the
		// password handler does: a credential has just been verified, and that is a
		// privilege change wherever it happens.
		//
		// The window this closes is smaller than the password one, since a ceremony
		// reaching level 2 has usually already rotated at level 1, but it is not empty: a
		// session that arrived at level 1 by single sign-on and is stepping up has not
		// rotated in this ceremony at all, so until /auth/completed runs the identifier it
		// carried at level 1 still names the row that is about to become level 2. Rotating
		// on acceptance means an identifier stolen at level 1 is dead the moment the
		// authenticator code is accepted rather than one redirect later.
		//
		// Before the save, for the ordering argument written out in handler_auth_pwd:
		// rotation persists the contents as they are now, so a failure between the two
		// leaves a fresh identifier on a session that has not been marked
		// authentication_completed (#266).
		if err := authHelper.RegenerateSession(w, r); err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/completed", http.StatusFound)
	}
}
