// Package recovery is the operation behind the `recover` subcommand, the one way back into an
// instance whose last administrator cannot sign in: the OTP device is lost, or the password is
// forgotten and SMTP is not configured, or every holder of authserver:manage has left. Bootstrap
// seeds only an empty database, and editing the users rows by hand bypasses the authentication
// generation and writes no audit record (#498).
//
// The command's authority is the database credentials it is run with, which is what makes it
// trustworthy: whoever holds them already controls the instance. Run refuses an unknown or
// disabled user rather than creating or enabling one, and writes through the same writes the Admin
// API uses, in one transaction, so the authentication generation advances, the sessions end and
// the audit trail names the command as the actor. It lives here rather than in the command's main
// package so the data tier can run it on every engine (#498).
package recovery

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/otpcredential"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/errs"
)

// Actor is what a recovery's audit events name as the actor, under the `command` key, where the
// API sites name the signed-in user under logged_in_user (#498: "recording an audit event that
// names the command as the actor"). There is no signed-in administrator here, and the database
// credentials the command is gated on are the authority it acts with, so the record says who
// acted by naming the command itself.
const Actor = "goiabada-authserver recover"

// Database is what Run reads and writes: the revocation sweep's and the OTP removal's ports, and
// the reads and writes of the user, the manage permission and the settings beside them.
type Database interface {
	revocation.Database
	otpcredential.Database
	AcquireManagePermissionRow(ctx context.Context, tx *sql.Tx) (int64, error)
	AcquireUserRow(ctx context.Context, tx *sql.Tx, userId int64) error
	CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *record.UserPermission) error
	GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]record.Permission, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*record.Resource, error)
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error)
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error)
	GetUserByIdForUpdate(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	GetUserPermissionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserPermission, error)
	SetUserPasswordHash(ctx context.Context, tx *sql.Tx, userId int64, passwordHash string) error
}

// AuditLogger records what a recovery did, after it committed.
type AuditLogger interface {
	Log(ctx context.Context, auditEvent string, details map[string]interface{})
}

// Request is what the command was asked to do. Each action is applied only as asked.
type Request struct {
	Email       string // the stored address of the user to recover
	Password    string // a new password for the user, empty when none is asked
	GrantManage bool   // grant authserver:manage
	RemoveOTP   bool   // remove the user's OTP authenticator
}

// Outcome is what a committed recovery did: each action's result as the committing attempt
// produced it, and the revocation sweep's.
type Outcome struct {
	UserId        int64
	Email         string // the address as Run looked it up, trimmed and lowercased
	PasswordSet   bool
	OTPRemoved    bool // false when no authenticator was enrolled
	ManageGranted bool // false when the user already held it
	Revocation    revocation.UserAuthStateResult
}

// RefusedError is a recovery Run would not make, for a reason the operator can act on: an
// unknown or disabled user, a password the policy refuses, a seed missing the manage permission,
// or a user changed while the command ran. Nothing was written.
type RefusedError struct {
	Reason string
}

func (e *RefusedError) Error() string { return e.Reason }

func refused(format string, a ...any) error {
	return errs.WithStack(&RefusedError{Reason: fmt.Sprintf(format, a...)})
}

// Run applies req to the user it names. On any error nothing is written and no audit event is
// recorded; a *RefusedError among them is a refusal rather than a failure.
func Run(ctx context.Context, database Database, auditLogger AuditLogger, req Request) (Outcome, error) {
	// The address is trimmed and lowercased for the same reason the credential paths do it
	// before GetUserByEmail: every write path stores one, and the engine-fold check in that
	// read refuses an address that differs in anything the engine resolved away.
	email := strings.ToLower(strings.TrimSpace(req.Email))

	user, err := database.GetUserByEmail(ctx, nil, email)
	if err != nil {
		return Outcome{}, errs.Wrap(err, "unable to read the user")
	}
	if user == nil {
		return Outcome{}, refused("no user holds the address %s", email)
	}
	if !user.Enabled {
		return Outcome{}, refused("the user holding %s is disabled; enable the user first, in the "+
			"admin console or through the Admin API", email)
	}

	// The manage permission's id is read before the transaction: the permission row it names is
	// seeded with the instance and changes with a migration, not with a concurrent request.
	// Whether the user already holds it is read inside the transaction, under the permission's row.
	var managePermissionId int64
	if req.GrantManage {
		managePermissionId, err = managePermission(ctx, database)
		if err != nil {
			return Outcome{}, err
		}
	}

	// A password is held to the stored policy, as the Admin API holds one: the database
	// credentials are the command's authority over WHO signs in, not a licence to weaken what
	// a password must look like, and the deployment's rule is the one every form applies
	// (#550 names the rule this follows).
	var passwordHash string
	if req.Password != "" {
		// A password of spaces and tabs alone is refused before the policy, which counts them like
		// any other character: the sign-in form refuses one as blank before any lookup, so stored,
		// it would replace the forgotten password with one nobody can sign in with. It is not
		// trimmed, so spaces around a real password are kept as typed.
		if strings.TrimSpace(req.Password) == "" {
			return Outcome{}, refused("the password is blank: it holds only whitespace, which " +
				"sign-in refuses")
		}
		settings, settingsErr := database.GetSettingsById(ctx, nil, 1)
		if settingsErr != nil {
			return Outcome{}, errs.Wrap(settingsErr, "unable to read the settings")
		}
		if settings == nil {
			return Outcome{}, refused("the database holds no settings row, so there is no " +
				"password policy to hold the new password to")
		}
		validationErr := accountvalidation.NewPasswordValidator().ValidatePassword(settings.PasswordPolicy, req.Password,
			accountvalidation.AccountWords{Email: user.Email, Username: user.Username, AppName: settings.AppName})
		if validationErr != nil {
			return Outcome{}, refused("the password is refused by the stored password policy: %v", validationErr)
		}
		passwordHash, err = passwordhash.Hash(req.Password)
		if err != nil {
			return Outcome{}, errs.Wrap(err, "unable to hash the password")
		}
	}

	// One transaction holds every write the request asked for and the revocation sweep, which is
	// what the Admin API's password change does through the same helper: the sweep's
	// generation advance is what ends the user's sessions, refresh tokens included, so a
	// recovered user signs in with nothing issued before the recovery still standing (#106,
	// #498).
	//
	// The body takes the user's row and decides from what it reads under it: whether the user is
	// still there and enabled, and which authenticator the removal compares against. Read before
	// the transaction, a removal and re-enrolment landing in between left an authenticator in
	// place while the command said none had been enrolled. Every credential change takes the same
	// row first, so under it the user is what this attempt decides on (#131, #542).
	//
	// The user's row is the transaction's first statement, before anything that reads. On MySQL
	// the first plain read fixes the snapshot every later plain read answers from, the sweep's
	// reads of the sessions and refresh tokens among them, so a read before the wait for the
	// user's row hid what the wait let commit: a session a sign-in started, or the child a refresh
	// rotation wrote, both under that row, stayed out of the sweep and out of its audit record
	// while the generation advanced past them (#498 round 8 F1). Taken first, the row is held
	// before any snapshot is, and the sweep reads whatever committed before it. The read of the
	// user under it is a locking one, which answers the row as committed whatever an engine's
	// snapshot holds.
	//
	// A grant is not a credential change: the Admin API's saves of who holds manage take the
	// manage permission's row first (lockAdministrators, #402 decision 11) and never the user's,
	// and on PostgreSQL the user's row lock does not wait for their insert. So a grant asked for
	// takes that row too, after the user's, and whether manage is already held is read under it: a
	// grant landing in between is waited for and found rather than written a second time. A save
	// holding that row can still deadlock with this transaction where its insert's foreign-key
	// check waits for the user's row; the engine rolls one back whole and RunInTransaction reruns
	// it, as below, rather than an order imposed against it (#301).
	//
	// The body is safe to rerun on a deadlock, for the reason RevokeUserAuthStateTx gives: it
	// reads afresh, each write is a compare-and-set, an idempotent column write or an insert
	// whose absence was just read, and the outcome is reset first, so it is whatever the
	// committing attempt produced (#301).
	outcome := Outcome{Email: email, UserId: user.Id}
	result, err := revocation.RevokeUserAuthStateTx(ctx, database, user.Id, "", func(tx *sql.Tx) error {
		outcome.PasswordSet, outcome.OTPRemoved, outcome.ManageGranted = false, false, false

		if acquireErr := database.AcquireUserRow(ctx, tx, user.Id); acquireErr != nil {
			return acquireErr
		}
		if req.GrantManage {
			if _, acquireErr := database.AcquireManagePermissionRow(ctx, tx); acquireErr != nil {
				return acquireErr
			}
		}
		current, readErr := database.GetUserByIdForUpdate(ctx, tx, user.Id)
		if readErr != nil {
			return readErr
		}
		if current == nil {
			return refused("the user holding %s was deleted while the command ran", email)
		}
		if !current.Enabled {
			return refused("the user holding %s was disabled while the command ran", email)
		}

		if passwordHash != "" {
			if writeErr := database.SetUserPasswordHash(ctx, tx, current.Id, passwordHash); writeErr != nil {
				return writeErr
			}
			outcome.PasswordSet = true
		}
		if req.RemoveOTP {
			removed, removeErr := otpcredential.RemoveTx(ctx, database, tx, current)
			if removeErr != nil {
				return removeErr
			}
			// RemoveTx answers false both when nothing was enrolled and when its compare-and-set
			// lost to a concurrent change of the authenticator. Only the first is a removal with
			// nothing to remove; the second would leave an authenticator the operator asked to
			// remove, so the whole recovery is refused and nothing commits.
			if !removed && current.OTPEnabled {
				return refused("the OTP authenticator of the user holding %s changed while the "+
					"command ran, so nothing was written; run the command again", email)
			}
			outcome.OTPRemoved = removed
		}
		if req.GrantManage {
			grants, grantsErr := database.GetUserPermissionsByUserId(ctx, tx, current.Id)
			if grantsErr != nil {
				return grantsErr
			}
			for _, grant := range grants {
				if grant.PermissionId == managePermissionId {
					return nil
				}
			}
			if writeErr := database.CreateUserPermission(ctx, tx, &record.UserPermission{
				UserId:       current.Id,
				PermissionId: managePermissionId,
			}); writeErr != nil {
				return writeErr
			}
			outcome.ManageGranted = true
		}
		return nil
	})
	if err != nil {
		return Outcome{}, err
	}
	outcome.Revocation = result

	// The audit events, after the commit, as every revocation site writes them: a record of a
	// rollback is a false record (#106 decision 5). Each is written only for what the committing
	// attempt did, and each names the command as the actor.
	if outcome.PasswordSet {
		auditLogger.Log(ctx, audit.EventUpdatedUserAuthentication, map[string]interface{}{
			"user_id": user.Id,
			"command": Actor,
		})
	}
	if outcome.OTPRemoved {
		auditLogger.Log(ctx, audit.EventDisabledOTP, map[string]interface{}{
			"user_id": user.Id,
			"command": Actor,
		})
	}
	if outcome.ManageGranted {
		auditLogger.Log(ctx, audit.EventAddedUserPermission, map[string]interface{}{
			"user_id":       user.Id,
			"permission_id": managePermissionId,
			"command":       Actor,
		})
		// The record every change to who is an administrator writes, after the change's own, so
		// one filter or one alert rule sees every such change, a recovery's grant included
		// (#402 decision 6).
		auditLogger.Log(ctx, audit.EventAdministrativePermissionChanged, map[string]interface{}{
			"change":      "granted",
			"target_kind": "user",
			"target_id":   user.Id,
			"permission_identifiers": []string{
				builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier,
			},
			"command": Actor,
		})
	}
	revocation.LogRevokedUserAuthStateByCommand(ctx, auditLogger, user.Id, revocation.ReasonRecoveryCommand,
		Actor, result)

	return outcome, nil
}

// managePermission answers the id of the auth server resource's manage permission, or the
// refusal of a database that holds none.
func managePermission(ctx context.Context, database Database) (int64, error) {
	resource, err := database.GetResourceByResourceIdentifier(ctx, nil, builtin.AuthServerResourceIdentifier)
	if err != nil {
		return 0, errs.Wrap(err, "unable to read the auth server resource")
	}
	if resource == nil {
		return 0, refused("the database holds no %s resource, so there is no %s permission to grant",
			builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)
	}
	permissions, err := database.GetPermissionsByResourceId(ctx, nil, resource.Id)
	if err != nil {
		return 0, errs.Wrap(err, "unable to read the resource's permissions")
	}
	for _, permission := range permissions {
		if permission.PermissionIdentifier == builtin.ManagePermissionIdentifier {
			return permission.Id, nil
		}
	}
	return 0, refused("the %s resource holds no %s permission",
		builtin.AuthServerResourceIdentifier, builtin.ManagePermissionIdentifier)
}
