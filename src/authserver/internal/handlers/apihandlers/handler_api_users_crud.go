package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/emaildelivery"
	"github.com/leodip/goiabada/authserver/internal/emaillinks"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/usercreation"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/securerandom"
)

// usersCrudDatabase is what the user endpoints need: the user row, the writes that change it, and
// the transaction they share.
//
// It embeds the account OTP port because disabling a user's OTP runs through
// otpcredential.Remove, and the revocation port because every credential write here revokes what
// the old credential authorized.
// It embeds what the administrative policy reads to judge whether the user is an administrator.
type usersCrudDatabase interface {
	userTargetPolicyDatabase
	userRemovalDatabase
	accountOTPDatabase
	revocation.Database

	DeleteUser(ctx context.Context, tx *sql.Tx, userId int64) error
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	SetUserPasswordHash(ctx context.Context, tx *sql.Tx, userId int64, passwordHash string) error
	TrySetUserEnabled(ctx context.Context, tx *sql.Tx, userId int64, expected bool, desired bool) (bool, error)
}

// HandleUserGet - GET /api/v1/admin/users/{id}
func HandleUserGet(
	database usersCrudDatabase,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get user from database
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Create response
		response := api.GetUserResponse{
			User: *apimapping.ToUserResponse(user),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleUserPasswordPut - PUT /api/v1/admin/users/{id}/password
func HandleUserPasswordPut(
	database usersCrudDatabase,
	passwordValidator PasswordValidator,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Decode the request body
		var req api.UpdateUserPasswordRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.NewPassword == "" {
			writeJSONError(w, "New password is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get existing user
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate password
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}
		err = passwordValidator.ValidatePassword(settings.PasswordPolicy, req.NewPassword)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Only authserver:manage writes to an administrator (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		// Hash password
		passwordHash, err := passwordhash.Hash(req.NewPassword)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// The fourth site, unmentioned by the issue (#106 decision 2). An admin setting
		// someone else's password revokes everything with no exceptSid: the admin's own
		// session is unaffected because it belongs to a different user, and the target's
		// sessions are exactly what must go.
		//
		// Narrow write, not a full-row UpdateUser: the model was loaded before validation, so
		// writing every column back would undo a concurrent disable (decision 14).
		result, err := revocation.RevokeUserAuthStateTx(r.Context(), database, user.Id, "", func(tx *sql.Tx) error {
			return database.SetUserPasswordHash(r.Context(), tx, user.Id, passwordHash)
		})
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		// Both events, after commit. The pre-existing one is unchanged (decision 7).
		auditLogger.Log(r.Context(), audit.EventUpdatedUserAuthentication, map[string]interface{}{
			"userId":       user.Id,
			"loggedInUser": loggedInUser,
		})
		revocation.LogRevokedUserAuthState(r.Context(), auditLogger, user.Id,
			revocation.ReasonAdminPasswordSet, loggedInUser, result)

		// Get the updated user to return
		updatedUser, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Create response
		response := api.UpdateUserResponse{
			User: *apimapping.ToUserResponse(updatedUser),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleUserOTPPut - PUT /api/v1/admin/users/{id}/otp
func HandleUserOTPPut(
	database usersCrudDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Decode the request body
		var req api.UpdateUserOTPRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Check if trying to enable OTP (not supported)
		if req.Enabled {
			writeJSONError(w, "Enabling OTP is not supported through this endpoint", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Get existing user
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Only proceed if user currently has OTP enabled and we're disabling it
		if !user.OTPEnabled {
			writeJSONError(w, "User does not have OTP enabled", "OTP_NOT_ENABLED", http.StatusBadRequest)
			return
		}

		// Only authserver:manage writes to an administrator (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		// Disable OTP. Clearing the secret, turning otp_enabled off and resetting the
		// consumed-step marker are one atomic operation, shared with the account API's disable
		// branch (#111 decisions 4 and 13); otpcredential.Remove carries the reasoning.
		removed, err := otpcredential.Remove(r.Context(), database, user)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if !removed {
			// The authenticator is no longer as this request read it: answered from a re-read,
			// with nothing written and nothing audited (#471 decision 2).
			writeLostOTPChange(w, r, database, user.Id, false)
			return
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.EventDisabledOTP, map[string]interface{}{
			"userId": user.Id,
		})

		// Get the updated user to return
		updatedUser, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Create response
		response := api.UpdateUserResponse{
			User: *apimapping.ToUserResponse(updatedUser),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleUserCreatePost - POST /api/v1/admin/users/create
func HandleUserCreatePost(
	pageRenderer PageRenderer,
	database usersCrudDatabase,
	userCreator UserCreator,
	emailValidator EmailValidator,
	profileValidator *accountvalidation.ProfileValidator,
	passwordValidator PasswordValidator,
	auditLogger AuditLogger,
	emailSender EmailSender,
	dataCipher *encryption.DataCipher,
	baseURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Decode the request body
		var req api.CreateUserAdminRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get settings from context
		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		// Validate required fields
		if req.Email == "" {
			writeJSONError(w, "Email is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Normalize and validate email
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))

		// Email format validation
		err := emailValidator.ValidateEmailAddress(req.Email)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// Email length validation
		if len(req.Email) > 60 {
			writeJSONError(w, "The email address cannot exceed a maximum length of 60 characters", "EMAIL_TOO_LONG", http.StatusBadRequest)
			return
		}

		// Check for duplicate email
		existingUser, err := database.GetUserByEmail(r.Context(), nil, req.Email)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if existingUser != nil {
			writeJSONError(w, "This email address is already registered", "EMAIL_ALREADY_EXISTS", http.StatusConflict)
			return
		}

		// Name validations
		err = profileValidator.ValidateName(req.GivenName, i18n.ErrCodeProfileGivenNameInvalid)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		err = profileValidator.ValidateName(req.MiddleName, i18n.ErrCodeProfileMiddleNameInvalid)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		err = profileValidator.ValidateName(req.FamilyName, i18n.ErrCodeProfileFamilyNameInvalid)
		if err != nil {
			writeValidationError(w, r, err)
			return
		}

		// setPasswordType is published as enum [now, email] and left out of the schema's required
		// array, which in OpenAPI means absent is allowed and a present value must be one of the
		// two. The document was therefore already right; the handler was not. It compared against
		// the two values and refused nothing else, so on a deployment with SMTP configured a third
		// value took neither the password branch nor the email branch: the account was created
		// enabled, holding authserver:manage-account, with no password, no forgot-password code and
		// no setup email. Nobody was ever told it existed. A passwordless row cannot be signed in
		// to -- bcrypt refuses an empty hash for every password, the empty one included -- so the
		// defect was a silent provisioning failure rather than a way in, and this refusal is what
		// the contract already promised (#350).
		if req.SetPasswordType != "" &&
			req.SetPasswordType != api.SetPasswordTypeNow &&
			req.SetPasswordType != api.SetPasswordTypeEmail {

			writeJSONError(w, "setPasswordType must be \"now\" or \"email\"",
				"VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// One boolean decides both arms, so they are exhaustive by construction and no value can
		// take neither again. Email is the significant value; everything else, absent included,
		// sets the password now, which is what a deployment with no SMTP has always done for every
		// value. Defaulting the other way would make an omitted field send mail the caller never
		// asked for.
		sendSetupEmail := settings.SMTPEnabled && req.SetPasswordType == api.SetPasswordTypeEmail

		// Password handling
		var passwordHash string
		if !sendSetupEmail {
			if req.Password == "" {
				writeJSONError(w, "Password is required", "VALIDATION_ERROR", http.StatusBadRequest)
				return
			}

			// Validate password
			err = passwordValidator.ValidatePassword(settings.PasswordPolicy, req.Password)
			if err != nil {
				writeValidationError(w, r, err)
				return
			}

			// Hash password
			passwordHash, err = passwordhash.Hash(req.Password)
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}
		}

		// Sanitize names
		req.GivenName = strings.TrimSpace(req.GivenName)
		req.MiddleName = strings.TrimSpace(req.MiddleName)
		req.FamilyName = strings.TrimSpace(req.FamilyName)

		input := &usercreation.Input{
			Email:         req.Email,
			EmailVerified: req.EmailVerified,
			PasswordHash:  passwordHash,
			GivenName:     req.GivenName,
			MiddleName:    req.MiddleName,
			FamilyName:    req.FamilyName,
		}

		// The setup email's code is issued before the create and inserted with the row, so nothing
		// writes the user after the insert: a save of the row as created could undo whatever
		// another request changed in between (#471 decision 4). A create that loses its address
		// below discards the code with the row.
		var verificationCode string
		if sendSetupEmail {
			verificationCode = securerandom.String(32)
			input.ForgotPasswordCodeEncrypted, err = dataCipher.Encrypt(verificationCode)
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}

			// The hash is how the reset link finds this row again, since the link carries
			// the code and no email address (#112). The encryption above stays: it is what
			// proves a submitted code matches, where the hash only locates the row.
			input.ForgotPasswordCodeHash = hashutil.HashString(verificationCode)
			input.ForgotPasswordCodeIssuedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		}

		// Create user using UserCreator
		createdUser, err := userCreator.CreateUser(r.Context(), input)
		if err != nil {
			// The address check above answers the ordinary case; this is the race it cannot
			// close, where a concurrent create takes the address between that read and this
			// write. The engine refuses the insert and the data layer tags it, so the answer is
			// 409 here too rather than a 500 the caller cannot act on.
			//
			// The users table carries two unique keys, email and subject, but subject is a fresh
			// UUID this request just generated, so email is the only one a create can realistically
			// collide on.
			//
			// This replaces a test for the words "email" and "already" in the driver's sentence,
			// which matched none of the four engines' actual duplicate-key messages and so had
			// never fired: every lost race answered 500 (#279).
			writeEmailTakenOrInternalServerError(w, r, errs.Wrap(err, "failed to create user"))
			return
		}

		// Get logged in user from access token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.EventCreatedUser, map[string]interface{}{
			"email":        createdUser.Email,
			"loggedInUser": loggedInUser,
		})

		// Handle email flow if needed
		if sendSetupEmail {
			// Prepare and send email
			name := createdUser.FullName()
			if len(name) == 0 {
				name = createdUser.Email
			}

			bind := map[string]interface{}{
				"name": name,
				"link": emaillinks.ResetPasswordLink(baseURL, verificationCode),
			}

			// Newly-created user has no stored Locale yet; render the
			// "set your password" email in English. Once the user logs in
			// and chooses a locale, subsequent emails honor it.
			emailReq := r.WithContext(i18n.WithLocale(r.Context(), true, createdUser.Locale, "en"))
			buf, err := pageRenderer.RenderTemplateToBuffer(emailReq, "/layouts/email_layout.html", "/emails/email_newuser_set_password.html", bind)
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}

			input := &emaildelivery.SendEmailInput{
				To:       createdUser.Email,
				Subject:  i18n.T(emailReq.Context(), "email.newuser_set_password.subject", map[string]any{"appName": settings.AppName}),
				HtmlBody: buf.String(),
			}
			err = emailSender.SendEmail(r.Context(), emaildelivery.SMTPConfigFromSettings(settings), input)
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}
		}

		// Create response
		response := api.CreateUserResponse{
			User: *apimapping.ToUserResponse(createdUser),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusCreated, response)
	}
}

// errUserAlreadyDisabled is what HandleUserEnabledPut's write callback returns to
// revocation.RevokeUserAuthStateTx when the compare-and-set found the account already disabled.
// It exists so the transaction ends before the sweep and without committing: a nil return would
// sweep a user a previous disable already dealt with, and any other error would be reported as a
// fault, when the honest answer is "nothing to do".
var errUserAlreadyDisabled = errors.New("the user is already disabled")

// HandleUserEnabledPut - PUT /api/v1/admin/users/{id}/enabled
func HandleUserEnabledPut(
	database usersCrudDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Decode the request body
		var req api.UpdateUserEnabledRequest
		if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Get existing user
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Only authserver:manage writes to an administrator (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		// Get logged in user from access token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		// This endpoint serves BOTH directions, so the write is a compare-and-set and the
		// revocation is conditional on it (#106 findings 4 and 21, decision 14).
		//
		// Only the enabled-to-disabled transition revokes. Enabling must not, since there is
		// no credential change to invalidate, and re-disabling an already-disabled account
		// must not either: it would advance the generation and evict sessions that a previous
		// disable already dealt with, so a repeated request would not be idempotent.
		// TrySetUserEnabled reports whether it actually flipped the row, and that report is
		// the condition. Both directions use it, so neither stays on the full-row UpdateUser
		// that decision 14 rules out.
		//
		// The sweep is conditional on the write, and RevokeUserAuthStateTx carries that without a
		// switch: the write callback returns errUserAlreadyDisabled when nothing flipped, which
		// ends the transaction before the sweep, exactly as the password reset's
		// errResetPasswordClaimLost does when its conditional write claims no row (#425). The
		// helper opens it through RunInTransaction, so a deadlock reruns the compare-and-set and
		// the sweep together (#301); the compare-and-set asks the row again on every attempt.
		disableWithRevocation := func() (revocation.UserAuthStateResult, bool, error) {
			// Disabling a holder of manage can remove the last administrator, so the write takes
			// the administrators' lock as the transaction's first statement, decides from the
			// user's grants as read under it, and is rolled back, sweep and all, when it would
			// leave no enabled user holding manage (#402 decisions 10 and 11).
			result, txErr := revocation.RevokeUserAuthStateTx(r.Context(), database, userId, "", func(tx *sql.Tx) error {
				administrators, lockErr := lockAdministrators(r.Context(), database, tx)
				if lockErr != nil {
					return lockErr
				}
				holdsManage, readErr := administrators.userHoldsManage(r.Context(), database, userId)
				if readErr != nil {
					return readErr
				}
				if decideErr := administrators.decide(r.Context(), holdsManage); decideErr != nil {
					return decideErr
				}
				flipped, setErr := database.TrySetUserEnabled(r.Context(), tx, userId, true, false)
				if setErr != nil {
					return setErr
				}
				if !flipped {
					// Already disabled. Nothing was written, so there is nothing to commit and
					// nothing to sweep. The sentinel is not a deadlock, so the transaction rolls
					// the empty attempt back once and hands it straight back.
					return errUserAlreadyDisabled
				}
				return administrators.leavesAnAdministrator(r.Context())
			})
			if errors.Is(txErr, errUserAlreadyDisabled) {
				return revocation.UserAuthStateResult{}, false, nil
			}
			if txErr != nil {
				return revocation.UserAuthStateResult{}, false, txErr
			}
			return result, true, nil
		}

		var result revocation.UserAuthStateResult
		transitioned := false

		if req.Enabled {
			// Enabling. Narrow write, no revocation, no new event. Uses the same
			// compare-and-set so this direction does not stay on the full-row UpdateUser.
			if _, err = database.TrySetUserEnabled(r.Context(), nil, userId, false, true); err != nil {
				writeInternalServerError(w, r, err)
				return
			}
		} else {
			result, transitioned, err = disableWithRevocation()
			if errors.Is(err, errLastAdministrator) {
				writeLastAdministrator(w)
				return
			}
			if err != nil {
				writeInternalServerError(w, r, err)
				return
			}
		}

		// Unchanged in both directions, per decision 7: the endpoint's existing event still
		// fires for every successful request, including the ones that revoke nothing.
		auditLogger.Log(r.Context(), audit.EventUpdatedUserDetails, map[string]interface{}{
			"userId":       userId,
			"loggedInUser": loggedInUser,
		})

		// Only on a real disable transition, and only after its commit.
		if transitioned {
			revocation.LogRevokedUserAuthState(r.Context(), auditLogger, userId,
				revocation.ReasonAccountDisabled, loggedInUser, result)
		}

		// Get the updated user to return
		updatedUser, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Create response
		response := api.UpdateUserResponse{
			User: *apimapping.ToUserResponse(updatedUser),
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}

// HandleUserDelete - DELETE /api/v1/admin/users/{id}
func HandleUserDelete(
	database usersCrudDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authentication and authorization handled by middleware

		// Get user ID from URL parameter
		userIdStr := chi.URLParam(r, "id")
		if userIdStr == "" {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		userId, err := strconv.ParseInt(userIdStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Check if user exists before deleting
		user, err := database.GetUserById(r.Context(), nil, userId)
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Only authserver:manage writes to an administrator (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		// Delete user from database. Deleting a holder of manage can remove the last
		// administrator, so the deletion runs in a transaction that takes the administrators' lock
		// first, decides from the user's grants as read under it, and is rolled back when it would
		// leave no enabled user holding manage (#402 decisions 10 and 11).
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			administrators, lockErr := lockAdministrators(r.Context(), database, tx)
			if lockErr != nil {
				return lockErr
			}
			holdsManage, readErr := administrators.userHoldsManage(r.Context(), database, userId)
			if readErr != nil {
				return readErr
			}
			if decideErr := administrators.decide(r.Context(), holdsManage); decideErr != nil {
				return decideErr
			}
			if deleteErr := database.DeleteUser(r.Context(), tx, userId); deleteErr != nil {
				return errs.Wrap(deleteErr, "unable to delete the user")
			}
			return administrators.leavesAnAdministrator(r.Context())
		})
		if errors.Is(err, errLastAdministrator) {
			writeLastAdministrator(w)
			return
		}
		if err != nil {
			writeInternalServerError(w, r, err)
			return
		}

		// Get logged in user from access token
		jwtToken, ok := reqctx.ValidatedTokenFrom(r.Context())
		var loggedInUser string
		if ok {
			loggedInUser = jwtToken.StringClaim("sub")
		}

		// Log audit event
		auditLogger.Log(r.Context(), audit.EventDeletedUser, map[string]interface{}{
			"userId":       userId,
			"loggedInUser": loggedInUser,
		})

		// Create response
		response := api.SuccessResponse{
			Success: true,
		}

		// Set content type and encode response
		writeJSON(w, r, http.StatusOK, response)
	}
}
