package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/otp"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// authOTPDatabase is what the OTP hop needs: the client, the user, and the OTP credential
// lifecycle this hop verifies against and may establish.
//
// It embeds the client display port because the screen renders through getClientDisplayInfo, and
// the OTP credential port because verifying a passcode and installing an authenticator both run
// through otpcredential, which owns the step claim as well as the write (#387).
type authOTPDatabase interface {
	clientDisplayDatabase
	otpcredential.Database

	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
}

func HandleAuthOtpGet(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	database authOTPDatabase,
	otpSecretGenerator OtpSecretGenerator,
	auditLogger AuditLogger,
	adminConsoleBaseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateLevel2OTP) {
			return
		}

		user, err := database.GetUserById(r.Context(), nil, authContext.UserId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			pageRenderer.InternalServerError(w, r, errs.New("user not found"))
			return
		}

		// Fetch client to get display settings
		client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.New("client not found"))
			return
		}

		displayInfo := getClientDisplayInfo(r.Context(), database, client)

		if user.OTPEnabled {

			// An enrolment key this ceremony generated before the user enrolled somewhere
			// else is dead now, and HandleAuthOtpPost picks the template for its error
			// rerender by whether one is present, so leaving it here would redraw the
			// enrolment page for a user who is already enrolled. Same clearing this arm did
			// when the seed and its image lived in two slots on the browser session (#242).
			authContext.OTPKeyURL = ""

			err = ceremonyStore.SaveAuthContext(w, r, authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
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

			err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_otp.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
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
				settings, ok := reqctx.SettingsFrom(r.Context())
				if !ok {
					pageRenderer.InternalServerError(w, r, reqctx.ErrNoSettings)
					return
				}
				keyURL, genErr := otpSecretGenerator.GenerateKeyURL(user.Email, settings.AppName)
				if genErr != nil {
					pageRenderer.InternalServerError(w, r, genErr)
					return
				}
				authContext.OTPKeyURL = keyURL

				secretKey, err = otp.SecretFromKeyURL(keyURL)
				if err != nil {
					pageRenderer.InternalServerError(w, r, err)
					return
				}
			}

			// Drawn from the URL on every render rather than carried beside it, so the
			// ceremony holds one value and the image cannot come to disagree with the secret
			// the code is checked against (#247).
			base64Image, err := otp.RenderQRCodeImage(authContext.OTPKeyURL)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}

			err = ceremonyStore.SaveAuthContext(w, r, authContext)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
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

			err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", "/auth_otp_enrollment.html", bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
		}
	}
}

func HandleAuthOtpPost(
	pageRenderer PageRenderer,
	ceremonyStore CeremonyStore,
	database authOTPDatabase,
	auditLogger AuditLogger,
	credentialFailures CredentialFailureRecorder,
	dataCipher *encryption.DataCipher,
	baseURL string,
	adminConsoleBaseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		// loadAuthContext refuses a submission naming another ceremony before the AuthState check, so
		// an OTP prompt left open in another tab gets the 400 mismatch page rather than the 500 that
		// a replaced context's state would produce, and before the code is looked at: MatchStep is
		// never reached, so TryConsumeUserOTPStep is never reached either, and a stale submission
		// cannot burn a step of a passcode the ceremony the user is actually on still needs (#79,
		// #111 decision 3).
		authContext, ok := loadAuthContext(pageRenderer, ceremonyStore, auditLogger, w, r, adminConsoleBaseURL)
		if !ok {
			return
		}

		if !requireAuthState(pageRenderer, w, r, authContext, ceremony.AuthStateLevel2OTP) {
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
			var err error
			secretKey, err = otp.SecretFromKeyURL(keyURL)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
				return
			}
		}

		user, err := database.GetUserById(r.Context(), nil, authContext.UserId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if user == nil {
			pageRenderer.InternalServerError(w, r, errs.New("user not found"))
			return
		}

		// Fetch client to get display settings
		client, err := database.GetClientByClientIdentifier(r.Context(), nil, authContext.ClientId)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			pageRenderer.InternalServerError(w, r, errs.New("client not found"))
			return
		}

		displayInfo := getClientDisplayInfo(r.Context(), database, client)

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
					pageRenderer.InternalServerError(w, r, imgErr)
					return
				}
				template = "/auth_otp_enrollment.html"
				bind["base64Image"] = base64Image
				bind["secretKey"] = secretKey
			}

			err = pageRenderer.RenderTemplate(w, r, "/layouts/auth_layout.html", template, bind)
			if err != nil {
				pageRenderer.InternalServerError(w, r, err)
			}
		}

		// i18n surface: A — browser-flow form rerender.
		if !user.Enabled {
			auditLogger.Log(r.Context(), audit.EventUserDisabled, map[string]interface{}{
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

		// One verification call on both arms, and which one is the difference the two arms have
		// always had: an enrolled user's passcode is checked against the authenticator stored on
		// their row, an enrolling one's against the seed this ceremony rendered. The step claim
		// that makes a passcode single-use rides inside either, with requireOTPEnabled set from
		// the entry point rather than from here (#111 decision 10, #387).
		var verified otpcredential.VerifyResult
		if user.OTPEnabled {
			verified, err = otpcredential.VerifyStored(r.Context(), database, dataCipher, user, otpCode, time.Now().UTC())
		} else {
			verified, err = otpcredential.VerifySupplied(r.Context(), database, user, secretKey, otpCode,
				time.Now().UTC())
		}
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}

		// The audit set stays here rather than moving with the verification, because it is what
		// genuinely differs between this ceremony and the account API: that endpoint raises
		// nothing on a wrong code and no failure event at all, where a browser authentication
		// refusal is an event an operator filters by (#387 decision 4).
		switch verified.Outcome {
		case otpcredential.OutcomeReplayed:
			// A replayed step is refused exactly as a wrong code is, so it counts as
			// one: a code already spent proves nothing about who is submitting it.
			credentialFailures.RecordCredentialFailure(r)
			auditLogger.Log(r.Context(), audit.EventOTPCodeReplayDetected, map[string]interface{}{
				"userId": user.Id,
				"step":   verified.Step,
			})
			auditLogger.Log(r.Context(), audit.EventAuthFailedOtp, map[string]interface{}{
				"userId": user.Id,
			})
			renderError(incorrectOtpError)
			return
		case otpcredential.OutcomeWrong:
			// Every wrong code is a guess at three of a million, so this is the
			// counter the whole OTP budget exists to move (#219).
			credentialFailures.RecordCredentialFailure(r)
			auditLogger.Log(r.Context(), audit.EventAuthFailedOtp, map[string]interface{}{
				"userId": user.Id,
			})
			renderError(incorrectOtpError)
			return
		}

		// The generation an enrolment below establishes, handed to RecordOTPVerified; nil when the
		// user was already enrolled.
		var enrolledGeneration *int64
		if !user.OTPEnabled {
			// is enrolling to TOTP now. The seed is encrypted at rest, the user written and the
			// OTP configuration generation's advance committed together, so there is no state in
			// which the authenticator is on and no session knows (#242 decision 2).
			generation, establishErr := otpcredential.Establish(r.Context(), database, dataCipher, user, secretKey)
			if establishErr != nil {
				pageRenderer.InternalServerError(w, r, establishErr)
				return
			}
			enrolledGeneration = &generation

			auditLogger.Log(r.Context(), audit.EventEnabledOTP, map[string]interface{}{
				"userId": user.Id,
			})
		}

		// from this point the user is considered authenticated with otp

		auditLogger.Log(r.Context(), audit.EventAuthSuccessOtp, map[string]interface{}{
			"userId": user.Id,
		})

		authContext.RecordOTPVerified(time.Now(), enrolledGeneration)

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
		if regenerateSessionErr := ceremonyStore.RegenerateSession(w, r); regenerateSessionErr != nil {
			pageRenderer.InternalServerError(w, r, regenerateSessionErr)
			return
		}

		err = ceremonyStore.SaveAuthContext(w, r, authContext)
		if err != nil {
			pageRenderer.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, ceremonyStepURL(baseURL, "/auth/completed", authContext), http.StatusFound)
	}
}
