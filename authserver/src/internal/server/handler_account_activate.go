package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/core"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAccountActivateGet(userCreator userCreator, emailSender emailSender) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		email := r.URL.Query().Get("email")
		code := r.URL.Query().Get("code")

		if len(email) == 0 {
			s.internalServerError(w, r, errors.New("expecting email but it was empty"))
			return
		}

		if len(code) == 0 {
			s.internalServerError(w, r, errors.New("expecting code but it was empty"))
			return
		}

		preRegistration, err := s.database.GetPreRegistrationByEmail(email)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		if preRegistration == nil {
			s.internalServerError(w, r, errors.New("could not find pre registration"))
			return
		}

		settings := r.Context().Value(common.ContextKeySettings).(*entities.Settings)
		verificationCode, err := lib.DecryptText(preRegistration.VerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			s.internalServerError(w, r, errors.New("unable to decrypt verification code"))
			return
		}

		if verificationCode != code {
			s.internalServerError(w, r, fmt.Errorf("email %v is trying to activate the account with the wrong code", email))
			return
		}

		if preRegistration.VerificationCodeIssuedAt.Add(5 * time.Minute).Before(time.Now().UTC()) {
			// verification code has expired
			// delete pre registration and ask the user to register again

			err := s.database.DeletePreRegistration(preRegistration.Id)
			if err != nil {
				s.internalServerError(w, r, err)
			}

			bind := map[string]interface{}{
				"linkHasExpired": true,
			}

			err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation_result.html", bind)
			if err != nil {
				s.internalServerError(w, r, err)
			}
			return
		}

		_, err = userCreator.CreateUser(r.Context(), &core.CreateUserInput{
			Email:         preRegistration.Email,
			EmailVerified: true,
			PasswordHash:  preRegistration.PasswordHash,
		})
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		err = s.database.DeletePreRegistration(preRegistration.Id)
		if err != nil {
			s.internalServerError(w, r, err)
		}

		bind := map[string]interface{}{}

		err = s.renderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation_result.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
		}
	}
}
