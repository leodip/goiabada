package accounthandlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/leodip/goiabada/internal/constants"
	"github.com/leodip/goiabada/internal/data"
	"github.com/leodip/goiabada/internal/handlers"
	"github.com/leodip/goiabada/internal/lib"
	"github.com/leodip/goiabada/internal/models"
	"github.com/leodip/goiabada/internal/users"
	"github.com/pkg/errors"
)

func HandleAccountActivateGet(
	httpHelper handlers.HttpHelper,
	database data.Database,
	userCreator handlers.UserCreator,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		email := r.URL.Query().Get("email")
		code := r.URL.Query().Get("code")

		if len(email) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting email but it was empty")))
			return
		}

		if len(code) == 0 {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("expecting code but it was empty")))
			return
		}

		preRegistration, err := database.GetPreRegistrationByEmail(nil, email)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		if preRegistration == nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("could not find pre registration")))
			return
		}

		settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
		verificationCode, err := lib.DecryptText(preRegistration.VerificationCodeEncrypted, settings.AESEncryptionKey)
		if err != nil {
			httpHelper.InternalServerError(w, r, errors.WithStack(errors.New("unable to decrypt verification code")))
			return
		}

		if verificationCode != code {
			httpHelper.InternalServerError(w, r, errors.WithStack(fmt.Errorf("email %v is trying to activate the account with the wrong code", email)))
			return
		}

		if preRegistration.VerificationCodeIssuedAt.Time.Add(5 * time.Minute).Before(time.Now().UTC()) {
			// verification code has expired
			// delete pre registration and ask the user to register again

			err := database.DeletePreRegistration(nil, preRegistration.Id)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}

			bind := map[string]interface{}{
				"linkHasExpired": true,
			}

			err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation_result.html", bind)
			if err != nil {
				httpHelper.InternalServerError(w, r, err)
			}
			return
		}

		createdUser, err := userCreator.CreateUser(r.Context(), &users.CreateUserInput{
			Email:         preRegistration.Email,
			EmailVerified: true,
			PasswordHash:  preRegistration.PasswordHash,
		})
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}

		lib.LogAudit(constants.AuditCreatedUser, map[string]interface{}{
			"email": createdUser.Email,
		})

		err = database.DeletePreRegistration(nil, preRegistration.Id)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
		}

		lib.LogAudit(constants.AuditActivatedAccount, map[string]interface{}{
			"email": createdUser.Email,
		})

		bind := map[string]interface{}{}

		err = httpHelper.RenderTemplate(w, r, "/layouts/auth_layout.html", "/account_register_activation_result.html", bind)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}
