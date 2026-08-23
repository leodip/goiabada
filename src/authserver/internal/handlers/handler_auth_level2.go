package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleAuthLevel2Get(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	database data.Database,
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

		requiredState := oauth.AuthStateRequiresLevel2
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		// here we'll select what type of level2 auth we'll use (otp, email_code, sms_code, magic_link)
		// today we only support otp, other types will be added in the future

		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId))))
			return
		}

		user, err := database.GetUserById(nil, authContext.UserId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		// GetUserById answers (nil, nil) for a row that is not there, so a user deleted
		// mid-ceremony reaches the dereference below. Byte-identical to the six sibling
		// ceremony handlers that already check this (HandleAuthOtpGet, HandleAuthOtpPost,
		// HandleConsentGet, HandleConsentPost, HandleAuthCompletedGet and
		// handleImplicitFlow): consistency is the point rather than a side benefit, because
		// "every handler nil-checks except this one" is the kind of gap that regresses
		// (#242 decision 5).
		if user == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("user not found")))
			return
		}

		// Capture the user's OTP configuration generation, before the switch so that every
		// arm below carries it: the level2_optional OTP prompt, the level2_optional skip for
		// a user with no authenticator, and level2_mandatory. **The skip has to count.** A
		// level2_optional ceremony for a user who has removed their authenticator is
		// legitimately answered by skipping OTP, and if that did not promote, every session
		// of that user would stay permanently behind and handlePromptNone would answer
		// interaction_required for the rest of each session's life.
		//
		// Nothing is written here. The value rides on the auth context and is promoted once,
		// at /auth/completed, so a ceremony abandoned at the OTP form discharges nothing
		// (#242 decision 3).
		otpConfigGeneration := user.OtpConfigGeneration
		authContext.OtpConfigGeneration = &otpConfigGeneration

		// is OTP optional or mandatory?
		targetAcrLevel := authContext.GetTargetAcrLevel(client.DefaultAcrLevel)
		switch targetAcrLevel {
		case enums.AcrLevel2Optional:
			// optional
			// if user has OTP enabled, we'll ask for it
			if user.OTPEnabled {
				authContext.AuthState = oauth.AuthStateLevel2OTP
				err = authHelper.SaveAuthContext(w, r, authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/otp", http.StatusFound)
			} else {
				// user without OTP, we'll skip it
				authContext.AuthState = oauth.AuthStateAuthenticationCompleted
				err = authHelper.SaveAuthContext(w, r, authContext)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
				http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/completed", http.StatusFound)
			}
		case enums.AcrLevel2Mandatory:
			// OTP is mandatory
			authContext.AuthState = oauth.AuthStateLevel2OTP
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/otp", http.StatusFound)
		default:
			// we should never reach this point
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("invalid targetAcrLevel: "+targetAcrLevel.String())))
		}
	}
}
