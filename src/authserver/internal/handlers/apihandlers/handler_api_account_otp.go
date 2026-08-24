package apihandlers

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/authserver/internal/middleware"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/encryption"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/otp"
)

// otpEnrollmentLifetime is how long an enrollment the server has issued stays usable: the window
// in which GET /api/v1/account/otp/enrollment keeps answering with the same seed, and in which PUT
// /api/v1/account/otp will still accept a passcode generated from it.
//
// Fifteen minutes, against the five that the three other pending-credential pairs on the users
// table use. Those time a code that arrives by email or SMS and is typed straight in, about a
// minute's work. This times installing an authenticator app, scanning a QR code and reading a
// passcode off it, which a first-time enroller can plausibly exceed, and the refusal would land
// after they had already scanned (#247).
const otpEnrollmentLifetime = 15 * time.Minute

// maxOTPRequestBodyBytes bounds the PUT's body, which is read whole because it is parsed twice:
// once into the request and once as a raw object, to see whether the caller sent a secretKey at
// all. A legitimate body here is a few hundred bytes.
const maxOTPRequestBodyBytes = 64 * 1024

// livePendingEnrollmentKeyURL returns the otpauth:// URL of the enrollment this server last issued
// the user, or "" when there is none to honour: no ciphertext, no issue time, or an issue time
// before staleBefore.
//
// The stored ciphertext is the whole key URL rather than the bare base32 seed, so a repeat call
// answers with a byte-identical QR image and the seed comes off the URL wherever it is needed.
//
// staleBefore is passed in rather than computed here because the same instant has to reach
// TryInstallPendingOTPEnrollment, whose WHERE clause draws the same line with a strict "issued
// before". A reader and a compare-and-set writer disagreeing about the boundary would produce a
// value this function calls dead and the database refuses to replace, which is a wedged endpoint
// rather than a stale seed.
//
// A ciphertext that will not decrypt is an error rather than a "none". Reporting none would send
// the caller down the minting path, where that same conditional UPDATE declines to replace a value
// that is not yet stale, so the request would answer 200 with a seed that was never stored and
// that the PUT could therefore never accept (#247).
func livePendingEnrollmentKeyURL(user *models.User, staleBefore time.Time) (string, error) {
	if len(user.OtpEnrollmentSecretEncrypted) == 0 || !user.OtpEnrollmentIssuedAt.Valid {
		return "", nil
	}
	if user.OtpEnrollmentIssuedAt.Time.Before(staleBefore) {
		return "", nil
	}
	return encryption.DecryptData(user.OtpEnrollmentSecretEncrypted)
}

// HandleAPIAccountOTPEnrollmentGet - GET /api/v1/account/otp/enrollment
func HandleAPIAccountOTPEnrollmentGet(
	database data.Database,
	otpSecretGenerator handlers.OtpSecretGenerator,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Token and scope are enforced by middleware; extract validated token
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
			return
		}

		subject := jwtToken.GetStringClaim("sub")
		if strings.TrimSpace(subject) == "" {
			writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
			return
		}

		// Load user
		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// If already enabled, cannot enroll
		if user.OTPEnabled {
			writeJSONError(w, "OTP is already enabled", "OTP_ALREADY_ENABLED", http.StatusBadRequest)
			return
		}

		// Answer with the enrollment this user already has pending, and mint one only when
		// there is none. That single rule is what makes the endpoint idempotent, and
		// idempotence is the whole of it: minting on every call replaced the seed behind a
		// QR code the user had already scanned, so every passcode they then read off it was
		// checked against a secret they were never shown. #242 closed exactly that at the
		// browser ceremony and it was still live here, for the admin console and for every
		// third-party caller (#247).
		//
		// Minting also became a write rather than a hand-out. Before this, the server never
		// learned which authenticator it had issued: the PUT matched the submitted code
		// against the secret the same request carried and then stored that value, so a
		// caller could enroll a seed the server had never generated.
		now := time.Now().UTC()
		staleBefore := now.Add(-otpEnrollmentLifetime)

		keyURL, err := livePendingEnrollmentKeyURL(user, staleBefore)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		if keyURL == "" {
			// The generator hands back the otpauth:// URL alone, and the QR image and the
			// base32 secret below are both derived from it, so there is one value to store
			// and no second copy that could disagree with it.
			settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
			keyURL, err = otpSecretGenerator.GenerateOTPSecret(user.Email, settings.AppName)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			secretEncrypted, err := encryption.EncryptData(keyURL)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			installed, err := database.TryInstallPendingOTPEnrollment(nil, user.Id, secretEncrypted, now, staleBefore)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
			if !installed {
				// Losing the compare-and-set is an ordinary outcome, not a failure: another
				// request for this user installed an enrollment between the read above and
				// this write, or the user finished enrolling in between. Returning the seed
				// that was NOT stored would hand out a QR code the PUT can never accept, so
				// the row is read back and the winner's value answered instead. Two
				// concurrent calls then agree on one enrollment, which is the reason the
				// install is conditional at all.
				user, err = database.GetUserById(nil, user.Id)
				if err != nil {
					writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
					return
				}
				if user == nil {
					writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
					return
				}
				if user.OTPEnabled {
					writeJSONError(w, "OTP is already enabled", "OTP_ALREADY_ENABLED", http.StatusBadRequest)
					return
				}

				keyURL, err = livePendingEnrollmentKeyURL(user, staleBefore)
				if err != nil {
					writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
					return
				}
				if keyURL == "" {
					// Neither this call nor a winner holds one, with OTP still off. Nothing
					// the caller did produces this: the write's predicate and the read above
					// draw the expiry line at the same instant, so it means the row moved in
					// a way this handler cannot account for. Answering 200 with an
					// unstored seed is the one thing that must not happen here.
					writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
					return
				}
			}
		}

		base64Image, err := otp.RenderQRCodeImage(keyURL)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		secretKey, err := otp.SecretFromKeyURL(keyURL)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		resp := api.AccountOTPEnrollmentResponse{Base64Image: base64Image, SecretKey: secretKey}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// HandleAPIAccountOTPPut - PUT /api/v1/account/otp
func HandleAPIAccountOTPPut(
	database data.Database,
	auditLogger handlers.AuditLogger,
	credentialFailures handlers.CredentialFailureRecorder,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Token and scope are enforced by middleware; extract validated token
		jwtToken, ok := middleware.GetValidatedToken(r)
		if !ok {
			writeJSONError(w, "Access token required", "ACCESS_TOKEN_REQUIRED", http.StatusUnauthorized)
			return
		}

		subject := jwtToken.GetStringClaim("sub")
		if strings.TrimSpace(subject) == "" {
			writeJSONError(w, "Invalid token subject", "INVALID_SUBJECT", http.StatusUnauthorized)
			return
		}

		// Decode request body twice: once as a raw object, to see which field names the
		// caller actually sent, and once into the request itself.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOTPRequestBodyBytes))
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		var rawFields map[string]json.RawMessage
		if err := json.Unmarshal(body, &rawFields); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// This endpoint no longer accepts a secret from its caller, and a request still
		// carrying one is refused rather than quietly ignored. The server now issues the
		// enrollment at GET /api/v1/account/otp/enrollment, records it, and enrolls that
		// value and no other, so a secretKey in this body can only mean the caller believes
		// it is choosing which authenticator is installed. It is not, and silence would
		// leave it believing it had (#247).
		//
		// The refusal is on the field's presence, not on its value: nothing here sets
		// DisallowUnknownFields, so dropping the field from the struct alone would have been
		// silently backward compatible, which is the outcome this exists to avoid. Testing
		// the raw object is also what makes "secretKey": null and a non-string secretKey
		// refuse the same way a string does.
		//
		// It runs ahead of the user load and the password check because it is a statement
		// about the shape of the request rather than about who sent it, and an integrator
		// upgrading needs to see the reason rather than a password failure.
		if _, sent := rawFields["secretKey"]; sent {
			writeJSONError(w,
				"This endpoint no longer accepts a secretKey. Start an enrollment with GET /api/v1/account/otp/enrollment and submit only the code from your authenticator app.",
				"SECRET_KEY_NOT_ACCEPTED", http.StatusBadRequest)
			return
		}

		var req api.UpdateAccountOTPRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Load user
		user, err := database.GetUserBySubject(nil, subject)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "USER_NOT_FOUND", http.StatusNotFound)
			return
		}

		// Verify password for both enable and disable operations
		if strings.TrimSpace(req.Password) == "" {
			writeJSONError(w, "Authentication failed. Check your password and try again.", "AUTHENTICATION_FAILED", http.StatusBadRequest)
			return
		}
		if !hashutil.VerifyPasswordHash(user.PasswordHash, req.Password) {
			// The one branch here that is a guess at the password, and so the only one that
			// spends the budget shared with PUT /api/v1/account/password. The blank check
			// above compares nothing, and the enable branch's wrong code and replay below are
			// deliberately unbounded: that code is checked against a seed this server issued
			// to this same caller at GET /api/v1/account/otp/enrollment, which their own
			// access token entitles them to fetch outright, so guessing the code gains
			// nothing that asking for it would not. (Until #247 the reason was that the code
			// was checked against a secret the same request carried. The conclusion survived
			// the seed moving server-side; the premise did not, so it is restated rather than
			// left standing as written.) This check is what guards disabling OTP, which takes
			// no code at all (#113, #219).
			credentialFailures.RecordCredentialFailure(r)

			writeJSONError(w, "Authentication failed. Check your password and try again.", "AUTHENTICATION_FAILED", http.StatusBadRequest)
			return
		}

		// Branch by operation
		if req.Enabled {
			// Enable OTP
			if user.OTPEnabled {
				writeJSONError(w, "OTP is already enabled", "OTP_ALREADY_ENABLED", http.StatusBadRequest)
				return
			}
			if strings.TrimSpace(req.OtpCode) == "" {
				writeJSONError(w, "OTP code is required to enable.", "OTP_CODE_REQUIRED", http.StatusBadRequest)
				return
			}

			// OTP code must be 6 digits
			if len(req.OtpCode) != 6 {
				writeJSONError(w, "Invalid OTP code.", "INVALID_OTP_CODE", http.StatusBadRequest)
				return
			}
			for i := 0; i < 6; i++ {
				if req.OtpCode[i] < '0' || req.OtpCode[i] > '9' {
					writeJSONError(w, "Invalid OTP code.", "INVALID_OTP_CODE", http.StatusBadRequest)
					return
				}
			}

			// The seed this code is checked against is the one the server issued at GET
			// /api/v1/account/otp/enrollment and recorded on the user row, never one the
			// caller names. That is the whole of the fix: before it, the code was matched
			// against the secret the request carried and that same value was then stored, so
			// the server enrolled whatever it was handed and never learned what it had
			// issued (#247).
			//
			// No live enrollment refuses the request rather than falling back to anything.
			// A partially migrated or rolled back deployment therefore fails closed:
			// enrolling stops working, which is the safe direction, instead of accepting a
			// secret from the wire again.
			now := time.Now().UTC()
			keyURL, err := livePendingEnrollmentKeyURL(user, now.Add(-otpEnrollmentLifetime))
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
			if keyURL == "" {
				writeJSONError(w,
					"No OTP enrollment is pending, or the one you started has expired. Request a new one with GET /api/v1/account/otp/enrollment and try again.",
					"OTP_ENROLLMENT_NOT_PENDING", http.StatusBadRequest)
				return
			}

			pendingSecret, err := otp.SecretFromKeyURL(keyURL)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			// A replayed code must be indistinguishable from a wrong one to the caller, so
			// both branches below write this same body (#111).
			incorrectOtpCode := "Incorrect OTP Code. OTP codes are time-sensitive and change every 30 seconds. Make sure you're using the most recent code generated by your authenticator app."

			step, matched := otp.MatchStep(req.OtpCode, pendingSecret, now)
			if !matched {
				writeJSONError(w, incorrectOtpCode, "INVALID_OTP_CODE", http.StatusBadRequest)
				return
			}

			// requireOTPEnabled is false here: this is enrollment establishing the
			// authenticator rather than a verification asserting it, and otp_enabled is
			// still off until the write below (#111 decision 10). It can only be off: the
			// OTP_ALREADY_ENABLED check above refuses an enable when it is on. The claim
			// comes first deliberately, as at the browser enrollment site: if the write
			// then fails, a code is burned and the user retries with the next one, whereas
			// the reverse order would leave OTP enabled on a request that was refused.
			consumed, err := database.TryConsumeUserOTPStep(nil, user.Id, step, false)
			if err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
			if !consumed {
				// No AuditAuthFailedOtp beside it, unlike the browser sites: this endpoint
				// emits nothing when a code is simply wrong, and enabling OTP is not an
				// authentication ceremony. Decision 5 puts the replay event alongside the
				// existing failure event, and here there is none.
				auditLogger.Log(constants.AuditOTPCodeReplayDetected, map[string]interface{}{
					"userId": user.Id,
					"step":   step,
				})
				writeJSONError(w, incorrectOtpCode, "INVALID_OTP_CODE", http.StatusBadRequest)
				return
			}

			if err := user.SetOTPSecret(pendingSecret); err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}
			user.OTPEnabled = true

			// The user write and the OTP configuration generation's advance commit together,
			// so there is no state in which the authenticator is on and no session knows
			// (#242 decision 2). The returned generation is discarded here: only the browser
			// ceremony, which captured the pre-enrollment value earlier in the same ceremony,
			// has a use for it.
			if _, err := handlers.EnableUserOTPTx(database, user); err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			auditLogger.Log(constants.AuditEnabledOTP, map[string]interface{}{
				"userId": user.Id,
			})
		} else {
			// Disable OTP
			if !user.OTPEnabled {
				writeJSONError(w, "User does not have OTP enabled", "OTP_NOT_ENABLED", http.StatusBadRequest)
				return
			}

			if err := disableUserOTP(database, user); err != nil {
				writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
				return
			}

			auditLogger.Log(constants.AuditDisabledOTP, map[string]interface{}{
				"userId": user.Id,
			})
		}

		// Nothing to flag on the caller's own session. Both branches above advanced
		// users.otp_config_generation inside the transaction that changed the authenticator,
		// which covers EVERY session of this user in one statement.
		//
		// What stood here read the caller's own sid claim, looked that one session up, set a
		// boolean on it and discarded both the read error and the write error. It therefore
		// reached at most one session, and none at all for a token with no sid claim, so a
		// user who enabled OTP through this endpoint left their other live sessions asserting
		// acr: urn:goiabada:level2_optional with amr: ["pwd"] for an authenticator they now
		// had (#242, parts 1.2 and 1.3).

		// Get updated user and respond
		updated, err := database.GetUserById(nil, user.Id)
		if err != nil {
			writeJSONError(w, "Internal server error", "INTERNAL_SERVER_ERROR", http.StatusInternalServerError)
			return
		}

		resp := api.UpdateUserResponse{User: *api.ToUserResponse(updated)}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			writeJSONError(w, "Failed to encode response", "ENCODING_ERROR", http.StatusInternalServerError)
			return
		}
	}
}

// disableUserOTP removes a user's authenticator: it clears the secret, turns otp_enabled off and
// returns the consumed-step marker to 0. The marker belongs to the authenticator being removed, and
// UpdateUser cannot carry it because the column is dont-update, which is why it takes a second write
// (#111 decision 4). The reset is also the only in-product remedy if a clock jump strands a user's
// marker in the future: without it, disabling OTP and re-enrolling would claim against the same
// poisoned marker and fail too.
//
// **The two writes commit together, and that is the point of this function** (#111 decision 13).
// Committed separately, which is how they were written before that decision, they leave a window in
// which the row reads otp_enabled = false with the old marker still standing. The window is between
// two committed statements, not inside one: no engine this server supports exposes an uncommitted
// write to an outside reader, so a transaction is the remedy rather than the hazard. An enrollment
// landing in that window loads the disabled state, matches a code and
// claims its step successfully, and then this reset erases the claim: the row settles at
// otp_enabled = 1 with last_otp_step = 0 and a code already consumed, so that code is claimable
// again at the browser prompt for the rest of its acceptance window. A concurrent enrollment sees
// either the pre-disable state, where OTP_ALREADY_ENABLED refuses it at the account API and decision
// 10's requireOTPEnabled refuses it at the browser verification branch, or the fully disabled state
// including the reset, where its claim stands. Neither method needed a transaction on its own; the
// pair does.
//
// The order inside the transaction is decision 10's, otp_enabled cleared before the marker. The
// commit boundary is now what closes that window rather than the ordering, since no reader outside
// the transaction observes either write until both have landed, but the order is kept: it costs
// nothing and it is the order the two disable sites have always written in.
//
// Shared by the two sites decision 4 names, HandleAPIAccountOTPPut's disable branch and
// HandleAPIUserOTPPut. There is no third: the browser flow enrolls but never disables.
func disableUserOTP(database data.Database, user *models.User) error {
	user.ClearOTPSecret()
	user.OTPEnabled = false

	tx, err := database.BeginTransaction()
	if err != nil {
		return err
	}
	defer database.RollbackTransaction(tx) //nolint:errcheck

	if err := database.UpdateUser(tx, user); err != nil {
		return err
	}
	if err := database.ResetUserOTPStep(tx, user.Id); err != nil {
		return err
	}
	// The counter that tells every one of this user's sessions they owe a second factor
	// again, advanced inside the same transaction as the removal itself. Being per user is
	// what makes "every session" one statement: the boolean this replaced was per session
	// and written only for the caller's own sid, so a user disabling their authenticator
	// from one device left every other session asserting amr ["pwd","otp"] for an
	// authenticator that no longer existed (#242 decisions 1 and 2).
	//
	// Its error is returned rather than discarded, and that is the other half of decision 2:
	// a removal that commits without the counter moving is precisely the state the re-prompt
	// exists to prevent.
	if _, err := database.IncrementUserOtpConfigGeneration(tx, user.Id); err != nil {
		return err
	}
	return database.CommitTransaction(tx)
}
