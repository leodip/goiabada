package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

func HandleAuthLevel1Get(
	httpHelper HttpHelper,
	authHelper AuthHelper,
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

		requiredState := oauth.AuthStateRequiresLevel1
		if authContext.AuthState != requiredState {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("authContext.AuthState is not "+requiredState)))
			return
		}

		// here we'll select what type of level1 auth we'll use (pwd, pin, magic_link)
		// today we only support pwd, other types will be added in the future

		authContext.AuthState = oauth.AuthStateLevel1Password
		err = authHelper.SaveAuthContext(w, r, authContext)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/pwd", http.StatusFound)
	}
}

func HandleAuthLevel1CompletedGet(
	httpHelper HttpHelper,
	authHelper AuthHelper,
	userSessionManager UserSessionManager,
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

		requiredStates := []string{oauth.AuthStateLevel1PasswordCompleted, oauth.AuthStateLevel1ExistingSession}
		if !slices.Contains(requiredStates, authContext.AuthState) {
			errorMsg := fmt.Sprintf("authContext.AuthState '%s' does not match any required state", authContext.AuthState)
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(errorMsg)))
			return
		}

		sessionIdentifier := ""
		if r.Context().Value(constants.ContextKeySessionIdentifier) != nil {
			sessionIdentifier = r.Context().Value(constants.ContextKeySessionIdentifier).(string)
		}

		userSession, err := database.GetUserSessionBySessionIdentifier(nil, sessionIdentifier)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		err = database.UserSessionLoadUser(nil, userSession)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		client, err := database.GetClientByClientIdentifier(nil, authContext.ClientId)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		if client == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New(fmt.Sprintf("client %v not found", authContext.ClientId))))
			return
		}

		targetAcrLevel := authContext.GetTargetAcrLevel(client.DefaultAcrLevel)

		// should we redirect to level 2 auth?
		shouldRedirectToLevel2 := false
		hasValidUserSession := userSessionManager.HasValidUserSession(r.Context(), userSession, authContext.ParseRequestedMaxAge())

		if hasValidUserSession {
			// Parse the session's ACR level
			acrLevelFromSession, err := enums.AcrLevelFromString(userSession.AcrLevel)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}

			// Step-up required if target ACR is higher than session ACR.
			// Uses enums.AcrLevel.IsHigherThan() as the single source of truth.
			if targetAcrLevel.IsHigherThan(acrLevelFromSession) {
				shouldRedirectToLevel2 = true
			}

			// Handle Level2AuthConfigHasChanged: if user changed their OTP config
			// (e.g., enrolled or removed OTP), they need to re-authenticate at level2.
			// This applies when session is already at level2 and target requires level2.
			if userSession.Level2AuthConfigHasChanged && targetAcrLevel.IsHigherThan(enums.AcrLevel1) {
				shouldRedirectToLevel2 = true
				userSession.Level2AuthConfigHasChanged = false
				err = database.UpdateUserSession(nil, userSession)
				if err != nil {
					httpHelper.InternalServerError(w, r, err)
					return
				}
			}
		} else if targetAcrLevel.IsHigherThan(enums.AcrLevel1) {
			// No valid session and target requires level2
			shouldRedirectToLevel2 = true
		}

		if shouldRedirectToLevel2 {
			// We need to redirect to level 2
			authContext.AuthState = oauth.AuthStateRequiresLevel2
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/level2", http.StatusFound)
			return
		} else {
			// Auth is completed
			authContext.AuthState = oauth.AuthStateAuthenticationCompleted
			err = authHelper.SaveAuthContext(w, r, authContext)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, config.GetAuthServer().BaseURL+"/auth/completed", http.StatusFound)
			return
		}
	}
}
