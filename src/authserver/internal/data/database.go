package data

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
)

// Database is composition-only. No handler, middleware or application service takes it: each
// declares a port of its own, beside the function that takes it, naming the operations that file
// needs (#386 decisions 3 and 8). Four things still need the whole list, and they are the whole of
// the list:
//
//   - datafactory, which builds one and returns it; its own two readers, the email case pre-flight
//     and the startup task, take ports like everything else (#438 decision 8);
//   - server.Server, which holds it and hands it to every constructor, each of which narrows it;
//   - tests/data, which exercises all 224 of these methods on every engine, and is the tier that
//     proves each one works there;
//   - this declaration itself, which is the compiler's check that the four engine adapters still
//     implement a complete set -- worth more since #416 replaced their explicit delegations with
//     embedding, because a method lost in commondb is no longer lost in four visible places.
//
// The generated mock is of this interface and of no port, which is what lets a handler declaring a
// three-method port still be tested with the double every other test uses (#386 decision 12).
type Database interface {
	BeginTransaction(ctx context.Context) (*sql.Tx, error)
	CommitTransaction(ctx context.Context, tx *sql.Tx) error
	RollbackTransaction(ctx context.Context, tx *sql.Tx) error
	// RunInTransaction opens a transaction, runs fn on it, commits when fn returns nil and rolls
	// back when it does not, returning fn's error unchanged. When the engine aborts the
	// transaction as a deadlock victim, inside fn or at the commit, the whole body is rerun,
	// bounded, and only the last such error surfaces. It is how every transaction owner opens
	// its transaction: the repository imposes no order in which transactions take their rows,
	// so a deadlock between two transactions on the same account is answered here, by rerunning
	// the victim, rather than prevented by a rule every site has to remember (#301). fn must keep its effects inside the
	// transaction and write any audit event after this returns, so a rerun is a first run.
	//
	// A cancelled ctx stops the helper before it starts another attempt and interrupts the
	// pause between them: the error then satisfies errors.Is for context.Canceled or
	// context.DeadlineExceeded, with the deadlock that caused the retry joined to it where
	// there was one (#386 decision 13).
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	// ScanEmailCase reads every users row as its id, its stored address and that address as
	// THIS engine's own LOWER() reduces it, which is the read behind the startup pre-flight
	// (the auth server's datafactory.CheckEmailCaseBeforeMigrating). It compares nothing: the
	// engines disagree about what LOWER() means and the rule is Go's strings.ToLower, so the
	// comparison is the caller's (#351). It replaced BackfillLowercaseEmails, which repaired
	// the data at startup rather than refusing to migrate it.
	ScanEmailCase(ctx context.Context) ([]record.EmailCaseRow, error)
	// ReencryptToKey re-encrypts every secret stored at rest, and every RSA private key, from
	// oldKey to newKey, both 32 bytes, in one RunInTransaction: a failure leaves everything
	// under oldKey. It decides nothing. Whether the data is under oldKey at all is the startup
	// task's question, answered from a canary before this is called (#83, #438 decision 8).
	ReencryptToKey(ctx context.Context, oldKey, newKey []byte) error
	IsEmpty(ctx context.Context) (bool, error)
	// PoolStats answers the connection pool's statistics as database/sql keeps them: its cap, its
	// connections by state, the requests that waited for one and for how long, and the connections
	// it closed by reason. It is the one read of the pool from above this layer, which the metrics
	// a scrape reports are read through (#400 decision 5). It runs no statement and takes no
	// context, because it reads counters the pool already holds in memory.
	PoolStats() sql.DBStats

	CreateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error
	UpdateClient(ctx context.Context, tx *sql.Tx, client *record.Client) error
	// SetClientPublic makes one client public and reports whether THIS call performed
	// the confidential-to-public transition, which is the write that removes the
	// client's obligation to authenticate and so the one that must revoke its
	// outstanding grants (see #245). True means this call made the change; false means
	// the client was already public and nothing was taken away.
	//
	// A transaction is required. The answer is established by the statements
	// themselves rather than by a read the caller compares against, because a read and
	// the write after it can straddle another writer's commit, and a classification
	// taken from the stale side leaves the grants alive.
	SetClientPublic(ctx context.Context, tx *sql.Tx, clientId int64) (bool, error)
	// SetClientAdministrativeScopesAllowed writes whether a client may request the administrative
	// authserver scopes. It is that column's one writer: UpdateClient never writes it (#499).
	SetClientAdministrativeScopesAllowed(ctx context.Context, tx *sql.Tx, clientId int64, allowed bool) error
	// AcquireClientRow takes the client's row inside the caller's transaction and holds it
	// until that transaction ends, so a read taken afterwards cannot be invalidated by
	// another writer before the caller writes it back (see #245).
	//
	// It exists because a re-read is not atomic with the write that follows it. A caller
	// that reads a column to decide what to preserve, and then writes the whole row, can
	// have another transaction commit in the gap and will write the value it read before
	// that commit. Acquiring first makes the read happen under this transaction's own row
	// lock, which is the only thing that makes the pair atomic.
	//
	// A transaction is required: without one the statement autocommits and the row is
	// released before the read even runs.
	AcquireClientRow(ctx context.Context, tx *sql.Tx, clientId int64) error
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*record.Client, error)
	GetClientsByIds(ctx context.Context, tx *sql.Tx, clientIds []int64) ([]record.Client, error)
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*record.Client, error)
	GetAllClients(ctx context.Context, tx *sql.Tx) ([]record.Client, error)
	DeleteClient(ctx context.Context, tx *sql.Tx, clientId int64) error
	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *record.Client) error
	ClientLoadWebOrigins(ctx context.Context, tx *sql.Tx, client *record.Client) error
	ClientLoadPermissions(ctx context.Context, tx *sql.Tx, client *record.Client) error

	CreateUser(ctx context.Context, tx *sql.Tx, user *record.User) error
	UpdateUser(ctx context.Context, tx *sql.Tx, user *record.User) error
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	GetUsersByIds(ctx context.Context, tx *sql.Tx, userIds []int64) (map[int64]record.User, error)
	GetUserByUsername(ctx context.Context, tx *sql.Tx, username string) (*record.User, error)
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*record.User, error)
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.User, error)
	// GetUserByForgotPasswordCodeHash finds the user holding an outstanding reset code,
	// by an unsalted SHA-256 of that code. This is what lets the reset link carry the
	// code and nothing else, so no email address travels in it (#112). An empty codeHash
	// returns (nil, nil) without querying: '' is the dormant value on every row with no
	// code outstanding, so a query would match one of them.
	GetUserByForgotPasswordCodeHash(ctx context.Context, tx *sql.Tx, codeHash string) (*record.User, error)
	SearchUsersPaginated(ctx context.Context, tx *sql.Tx, query string, page int, pageSize int) ([]record.User, int, error)
	DeleteUser(ctx context.Context, tx *sql.Tx, userId int64) error
	// AcquireUserRow takes the user's row inside the caller's transaction and holds it until
	// that transaction ends, the third of its kind beside AcquireUserSessionRow and
	// AcquireClientRow. A refresh rotation takes it first, and a credential change takes the same
	// row first through its write and IncrementUserAuthStateGeneration, so the two serialize and a
	// child token is never stamped from a parent a revocation has already moved past (#131).
	//
	// It assigns auth_state_generation to itself and leaves updated_at alone, because the admin
	// console shows that column as "Last updated at" and a refresh is not an edit of the account.
	// A user that is not there is not an error: there is nothing to hold, and the read that follows
	// decides whether the user exists.
	//
	// A transaction is required: without one the statement autocommits and the row is released
	// before the caller can use it.
	AcquireUserRow(ctx context.Context, tx *sql.Tx, userId int64) error
	// IncrementUserAuthStateGeneration advances the user's authentication generation
	// and returns the new value. Separate from UpdateUser because the column is tagged
	// dont-update: credential handlers used to write the whole user back, so an ordinary
	// update would have let a stale model regress the boundary (#106). None does now, and
	// TestNoWholeRowUserSave holds it, but fixtures still seed through UpdateUser (#471).
	//
	// tx is REQUIRED and a nil transaction is rejected. The increment and the read-back
	// cannot be one statement portably across the four engines, so outside a
	// transaction a concurrent increment can land between them and this caller would
	// return the other caller's generation.
	IncrementUserAuthStateGeneration(ctx context.Context, tx *sql.Tx, userId int64) (int64, error)
	// IncrementUserOtpConfigGeneration advances the user's OTP configuration generation
	// and returns the new value. Called at every site that establishes or removes an
	// authenticator, inside the same transaction as the write that changed it, so there
	// is no state in which the authenticator has changed and no session knows (#242).
	// Separate from UpdateUser because the column is tagged dont-update, for the reason
	// IncrementUserAuthStateGeneration gives.
	//
	// tx is REQUIRED and a nil transaction is rejected, as above and for the same
	// reason. The browser enrollment caller needs the returned value: it captured the
	// pre-enrollment generation at /auth/level2 and would otherwise promote that stale
	// value at /auth/completed, leaving a session that just enrolled and verified owing
	// another prompt at once. Computing the successor in Go instead is what the
	// read-back exists to refuse.
	IncrementUserOtpConfigGeneration(ctx context.Context, tx *sql.Tx, userId int64) (int64, error)
	// SetUserPasswordHash writes a password hash and clears any outstanding
	// forgot-password code in the same statement. Narrow rather than a full-row
	// update, so a concurrent admin disable cannot be undone by it (#106).
	SetUserPasswordHash(ctx context.Context, tx *sql.Tx, userId int64, passwordHash string) error
	// SetUserProfile writes the user's eleven profile columns (username, the four names,
	// website, gender, birth date, the zone's country and zone, and locale) from user, and
	// updated_at, and no other column; it sets user.UpdatedAt to what it stored. SetUserAddress
	// does the same for the six address columns, and SetUserPhone for the phone's country,
	// calling code, number and verified flag. Each is an unconditional write shared by the
	// self-service and the administrator's save of its group, so the last save of a group wins;
	// narrow rather than a full-row update of the user the request read, so neither save can
	// undo a concurrent disable, password change or OTP change (#471).
	SetUserProfile(ctx context.Context, tx *sql.Tx, user *record.User) error
	SetUserAddress(ctx context.Context, tx *sql.Tx, user *record.User) error
	SetUserPhone(ctx context.Context, tx *sql.Tx, user *record.User) error
	// TrySetUserEmail moves a user's address from fromEmail to toEmail, clears the verified
	// flag, any pending verification code and any outstanding reset code in the same
	// statement, and writes no other column; the verification code's issued-at stays, because
	// the resend cooldown reads it. It matches only while the row still carries fromEmail with
	// fromVerified, and reports whether it did, so of two concurrent changes from one read
	// exactly one is made and only that one notifies the previous address. Narrow rather than a
	// full-row update, so the self-service email change cannot undo a concurrent admin disable,
	// password change or OTP change. A taken address is ErrUniqueViolation, as on UpdateUser
	// (#404). The reset code goes because it belongs to the address it was mailed to (#471).
	TrySetUserEmail(ctx context.Context, tx *sql.Tx, userId int64, fromEmail string, fromVerified bool, toEmail string) (bool, error)
	// SetUserEmail writes the administrator's email change: the address and verified flag from
	// user, a cleared verification code and issued-at, a reset code cleared when the row held
	// another address, and updated_at, and no other column; it sets user.UpdatedAt to what it stored. Unconditional, so the last
	// change wins; narrow rather than a full-row update, so it cannot undo a concurrent disable,
	// password change or OTP change. A taken address is ErrUniqueViolation (#471).
	SetUserEmail(ctx context.Context, tx *sql.Tx, user *record.User) error
	// TryIssueEmailVerificationCode stores the code the administrator generates, encrypted,
	// issued at issuedAt, and unverifies the address, only while the account still holds email,
	// the address the request read and reports, and reports whether it did (#471).
	TryIssueEmailVerificationCode(ctx context.Context, tx *sql.Tx, userId int64, email string, codeEncrypted []byte,
		issuedAt time.Time) (bool, error)
	// TryStoreEmailVerificationCode stores a verification code, encrypted, issued at
	// issuedAt, only while the account still holds email, unverified, and no code was
	// issued after issuedNotAfter, and reports whether it did. It is the resend cooldown
	// as one conditional write: of concurrent sends exactly one claims the code and mails
	// it, where a read then a write let every one of them pass the check (#404).
	TryStoreEmailVerificationCode(ctx context.Context, tx *sql.Tx, userId int64, email string, codeEncrypted []byte,
		issuedAt time.Time, issuedNotAfter time.Time) (bool, error)
	// TryVerifyUserEmail marks a user's address verified and clears the code, only while
	// the account still holds email, unverified, with codeEncrypted still the pending code,
	// which is the ciphertext the caller compared; the issued-at stays for the resend
	// cooldown. It reports whether it did. Narrow rather than writing back the row the
	// request loaded, which could undo a concurrent admin disable or email change (#404).
	TryVerifyUserEmail(ctx context.Context, tx *sql.Tx, userId int64, email string, codeEncrypted []byte) (bool, error)
	// TryConsumeForgotPasswordCode writes a password hash, claims the outstanding reset
	// code and marks the address verified, since redeeming a link sent to it proves it, in
	// one conditional UPDATE, reporting whether this call is the one that made the
	// transition. Compare-and-set for the same reason MarkCodeAsUsed is: a
	// read-then-unconditional-write lets two concurrent requests both believe they
	// completed the reset.
	//
	// Separate from SetUserPasswordHash rather than a fourth parameter on it, because
	// its other two callers (admin user create, account password change) hold no
	// outstanding code and would have to pass a meaningless predicate. An empty codeHash
	// or a zero userId is an error rather than a false: '' is the dormant value on every
	// row with no code outstanding, so an empty predicate would claim one of them (#112).
	// It claims nothing on a disabled account, so a reset never sets a password there (#404).
	TryConsumeForgotPasswordCode(ctx context.Context, tx *sql.Tx, userId int64, codeHash string, passwordHash string) (bool, error)
	// TryStoreForgotPasswordCode stores a reset code on a user, its encrypted form, its
	// hash and when it was issued, only while the account is still enabled, its address
	// is still verified and still the one given, and reports whether it did. Narrow and
	// conditional rather than a full-row update of the user the request loaded, so a
	// concurrent admin disable is neither undone by it nor followed by a mail (#404).
	TryStoreForgotPasswordCode(ctx context.Context, tx *sql.Tx, userId int64, email string, codeEncrypted []byte,
		codeHash string, issuedAt time.Time) (bool, error)
	// TrySetUserEnabled flips enabled from expected to desired, reporting whether this
	// call made the transition. Compare-and-set for the same reason MarkCodeAsUsed is.
	// The disable direction's return gates the revocation sweep (#106).
	TrySetUserEnabled(ctx context.Context, tx *sql.Tx, userId int64, expected bool, desired bool) (bool, error)
	// TryConsumeUserOTPStep records step as the user's most recently consumed TOTP
	// time step, only if it is strictly newer than what is stored, and reports whether
	// this call made the transition. Compare-and-set for the same reason MarkCodeAsUsed
	// is: accepting a code and recording it as used must not be separable, or two
	// concurrent submissions of one code both pass (#111). The enrolment claim: it names
	// no authenticator state, because it runs while otp_enabled is still off and the
	// establish that follows is the compare-and-set on the authenticator (#471). False
	// means no row transitioned, which is a replay in all but a rare interleaving, never
	// specifically proof of one.
	TryConsumeUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64) (bool, error)
	// TryConsumeEnrolledUserOTPStep is the verification claim: TryConsumeUserOTPStep's
	// claim, matching only while otp_enabled is on at expectedGeneration, the
	// otp_config_generation read with the secret the passcode was checked against. A
	// passcode checked against an authenticator removed, or removed and replaced, under
	// the request is refused rather than asserting otp for one that no longer exists
	// (#111, #144, #471). False carries the same imprecision as TryConsumeUserOTPStep's.
	TryConsumeEnrolledUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64,
		expectedGeneration int64) (bool, error)
	// ResetUserOTPStep returns the consumed-step marker to 0. Called when OTP is
	// disabled: the marker belongs to the enrolled authenticator, and it is the only
	// remedy if a clock jump strands the marker in the future (#111).
	ResetUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64) error
	// TryInstallPendingOTPEnrollment records a TOTP enrollment the server has just
	// issued, only if the user has no live one and no authenticator already, and
	// reports whether this call installed it. Compare-and-set is what makes the
	// issuing endpoint idempotent: concurrent requests all find nothing pending,
	// exactly one wins, and the losers answer with the winner's seed rather than
	// handing out a second QR code that invalidates the one already scanned. An
	// existing value counts as replaceable when it is absent or was issued before
	// staleBefore, which keeps the lifetime itself in the handler (#247).
	TryInstallPendingOTPEnrollment(ctx context.Context, tx *sql.Tx, userId int64, secretEncrypted []byte,
		issuedAt time.Time, staleBefore time.Time) (bool, error)
	// TryEstablishUserOTP installs an authenticator: it stores the encrypted seed and turns
	// otp_enabled on, and writes no other column but updated_at, only while OTP is still off at
	// expectedGeneration, the otp_config_generation the request read. It reports whether it did,
	// so of two enrolments from one read exactly one lands, and an enrolment read before an
	// enable and a disable landed in between is refused rather than installed over them. Narrow
	// rather than a full-row update, so it cannot undo a concurrent disable or password change
	// (#144, #471).
	TryEstablishUserOTP(ctx context.Context, tx *sql.Tx, userId int64, expectedGeneration int64,
		secretEncrypted []byte) (bool, error)
	// TryRemoveUserOTP removes an authenticator: it clears the seed and turns otp_enabled off,
	// and writes no other column but updated_at, only while OTP is still on at
	// expectedGeneration, the otp_config_generation the request read. It reports whether it did,
	// so a removal read before the authenticator was replaced does not remove the replacement
	// (#471).
	TryRemoveUserOTP(ctx context.Context, tx *sql.Tx, userId int64, expectedGeneration int64) (bool, error)
	// ClearPendingOTPEnrollment returns the pending enrollment pair to NULL. Called
	// inside the transaction that establishes the authenticator, so no committed
	// state has OTP enabled with a live pending seed still installed (#247).
	ClearPendingOTPEnrollment(ctx context.Context, tx *sql.Tx, userId int64) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *record.User) error
	UsersLoadGroups(ctx context.Context, tx *sql.Tx, users []record.User) error
	UserLoadPermissions(ctx context.Context, tx *sql.Tx, user *record.User) error
	UsersLoadPermissions(ctx context.Context, tx *sql.Tx, users []record.User) error
	UserLoadAttributes(ctx context.Context, tx *sql.Tx, user *record.User) error

	CreateCode(ctx context.Context, tx *sql.Tx, code *record.Code) error
	UpdateCode(ctx context.Context, tx *sql.Tx, code *record.Code) error
	// MarkCodeAsUsed atomically flips a code from unused to used and reports
	// whether this call is the one that made the transition. It is the guard
	// against double-spending a single authorization code (see #77). A revoked
	// code is never claimable, which is what stops a redemption that validated
	// just before its session was terminated (see #129). False means no row
	// transitioned, whether used, revoked or missing, and never specifically
	// reuse: that is the validator's finding, not this one's.
	MarkCodeAsUsed(ctx context.Context, tx *sql.Tx, codeId int64) (bool, error)
	// RevokeCodesBySessionIdentifier marks every not-yet-revoked code of one session
	// revoked and reports how many rows it transitioned. Ending a session durably
	// cuts off the grants that session authorized, and marking the code reaches
	// every refresh token descended from it, present and future, because a rotated
	// child inherits its parent's code_id (see #129).
	RevokeCodesBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (int64, error)
	// RevokeCodesByClientId marks every not-yet-revoked code of one client revoked and
	// reports how many rows it transitioned. It is the durable half of flipping a
	// client from confidential to public: marking the code reaches every refresh token
	// descended from it, present and future, because a rotated child inherits its
	// parent's code_id, so a token inserted after this statement committed is born
	// already rejected. The count is what this call transitioned and not what the
	// client has, so a second flip reports 0 (see #245).
	RevokeCodesByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (int64, error)
	GetCodeById(ctx context.Context, tx *sql.Tx, codeId int64) (*record.Code, error)
	GetCodeByCodeHash(ctx context.Context, tx *sql.Tx, codeHash string, used bool) (*record.Code, error)
	DeleteCode(ctx context.Context, tx *sql.Tx, codeId int64) error
	CodeLoadClient(ctx context.Context, tx *sql.Tx, code *record.Code) error
	CodeLoadUser(ctx context.Context, tx *sql.Tx, code *record.Code) error
	// DeleteCodesWithoutRefreshTokens reaps every code created before createdBefore
	// that no refresh token references: redeemed without a refresh token following,
	// revoked while still unredeemed (#129), or never redeemed at all (#436). The
	// reference test is null-safe, so a ROPC refresh token's NULL code_id stops
	// nothing (#130).
	//
	// createdBefore is a required grace cutoff. Without it the sweep races the token
	// endpoint, which marks a code used and only then inserts the refresh token that
	// references it, so a code mid-redemption matches and its deletion fails the
	// insert with a foreign key violation. Past the 60 second code lifetime no code
	// can gain a refresh token, so a cutoff comfortably beyond 60 seconds is safe.
	//
	// A code any refresh token still references is deliberately out of reach, revoked
	// or not, because that marker is what rejects the token.
	DeleteCodesWithoutRefreshTokens(ctx context.Context, tx *sql.Tx, createdBefore time.Time) error

	CreateResource(ctx context.Context, tx *sql.Tx, resource *record.Resource) error
	UpdateResource(ctx context.Context, tx *sql.Tx, resource *record.Resource) error
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*record.Resource, error)
	GetResourcesByIds(ctx context.Context, tx *sql.Tx, resourceIds []int64) ([]record.Resource, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*record.Resource, error)
	GetAllResources(ctx context.Context, tx *sql.Tx) ([]record.Resource, error)
	DeleteResource(ctx context.Context, tx *sql.Tx, resourceId int64) error

	CreatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error
	UpdatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*record.Permission, error)
	GetPermissionsByIds(ctx context.Context, tx *sql.Tx, permissionIds []int64) ([]record.Permission, error)
	GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]record.Permission, error)
	DeletePermission(ctx context.Context, tx *sql.Tx, permissionId int64) error
	PermissionsLoadResources(ctx context.Context, tx *sql.Tx, permissions []record.Permission) error
	// AcquireManagePermissionRow takes the authserver resource's manage permission row inside the
	// caller's transaction, holds it until that transaction ends, and answers that permission's
	// id. It is the one row every write that can remove the last holder of authserver:manage takes
	// first, so two such removals serialize and the second decides, from rows it reads after the
	// wait, what the first committed (#402 decision 11).
	//
	// A database with no manage permission is an error rather than an acquisition of nothing,
	// because a guard behind a lock that holds nothing would count without serializing anything.
	//
	// A transaction is required: without one the statement autocommits and the row is released
	// before the caller can count under it.
	AcquireManagePermissionRow(ctx context.Context, tx *sql.Tx) (int64, error)

	CreateKeyPair(ctx context.Context, tx *sql.Tx, keyPair *record.KeyPair) error
	UpdateKeyPair(ctx context.Context, tx *sql.Tx, keyPair *record.KeyPair) error
	// UpdateKeyPairState moves one key from an expected state to a new one, and reports
	// whether this call is the one that made the transition. Compare-and-set for the same
	// reason MarkCodeAsUsed is: a read-then-unconditional-write lets two concurrent
	// rotations both act on the snapshot they read, and the loser then destroys the key
	// the winner had just demoted for the grace period rotation exists to provide (#251).
	//
	// A false return means no row transitioned, so the caller lost a race or the row is
	// gone. It is not an error.
	UpdateKeyPairState(ctx context.Context, tx *sql.Tx, keyPairId int64, fromState string, toState string) (bool, error)
	GetKeyPairById(ctx context.Context, tx *sql.Tx, keyPairId int64) (*record.KeyPair, error)
	GetAllSigningKeys(ctx context.Context, tx *sql.Tx) ([]record.KeyPair, error)
	// GetCurrentSigningKey returns an error when no key is in the current state, rather
	// than the (nil, nil) this codebase returns for a lookup that may legitimately miss.
	// The current signing key is a singleton the server cannot run without: every caller
	// dereferences the result to read key material, so (nil, nil) is a nil-pointer panic
	// at each of them and one more at every call site added later. Narrowing the contract
	// here is what makes all of them correct at once, as IncrementUserAuthStateGeneration
	// rejects a nil transaction rather than tolerating it (#251).
	GetCurrentSigningKey(ctx context.Context, tx *sql.Tx) (*record.KeyPair, error)
	DeleteKeyPair(ctx context.Context, tx *sql.Tx, keyPairId int64) error

	CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *record.RedirectURI) error
	GetRedirectURIById(ctx context.Context, tx *sql.Tx, redirectURIId int64) (*record.RedirectURI, error)
	GetRedirectURIsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.RedirectURI, error)
	DeleteRedirectURI(ctx context.Context, tx *sql.Tx, redirectURIId int64) error

	CreateWebOrigin(ctx context.Context, tx *sql.Tx, webOrigin *record.WebOrigin) error
	GetWebOriginById(ctx context.Context, tx *sql.Tx, webOriginId int64) (*record.WebOrigin, error)
	GetAllWebOrigins(ctx context.Context, tx *sql.Tx) ([]record.WebOrigin, error)
	GetWebOriginsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.WebOrigin, error)
	WebOriginExists(ctx context.Context, tx *sql.Tx, origin string) (bool, error)
	DeleteWebOrigin(ctx context.Context, tx *sql.Tx, webOriginId int64) error

	CreateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error
	// CreateInitialSettings writes a deployment's one settings row at the id IsEmpty and every
	// reader ask for, whatever the engine's counter would hand out, inside the transaction it is
	// given and never outside one: the first seed's settings row (#424 decision 14).
	CreateInitialSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error
	UpdateSettings(ctx context.Context, tx *sql.Tx, settings *record.Settings) error
	GetSettingsById(ctx context.Context, tx *sql.Tx, settingsId int64) (*record.Settings, error)
	// TryClaimCleanupRun atomically claims the next background cleanup run via a
	// conditional update on settings.last_cleanup_at, and reports whether this
	// caller won it. claimableBefore is the cutoff (pass now minus the interval).
	// This is what keeps the cleanup single-flight across instances and puts the
	// schedule on the wall clock instead of one process's uptime.
	TryClaimCleanupRun(ctx context.Context, tx *sql.Tx, now time.Time, claimableBefore time.Time) (bool, error)

	CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *record.UserPermission) error
	UpdateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *record.UserPermission) error
	GetUserPermissionById(ctx context.Context, tx *sql.Tx, userPermissionId int64) (*record.UserPermission, error)
	GetUsersByPermissionIdPaginated(ctx context.Context, tx *sql.Tx, permissionId int64, page int, pageSize int) ([]record.User, int, error)
	GetUserPermissionByUserIdAndPermissionId(ctx context.Context, tx *sql.Tx, userId, permissionId int64) (*record.UserPermission, error)
	GetUserPermissionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserPermission, error)
	GetUserPermissionsByUserIds(ctx context.Context, tx *sql.Tx, userIds []int64) ([]record.UserPermission, error)
	DeleteUserPermission(ctx context.Context, tx *sql.Tx, userPermissionId int64) error
	// CountEnabledUsersHoldingPermission counts the enabled users holding the permission, directly
	// or through any of their groups, each once. Read on tx, it counts what the transaction itself
	// has written. It is what the last-administrator guard counts, under AcquireManagePermissionRow,
	// before and after a write that can remove a holder of authserver:manage (#402 decision 10).
	CountEnabledUsersHoldingPermission(ctx context.Context, tx *sql.Tx, permissionId int64) (int, error)

	CreateGroup(ctx context.Context, tx *sql.Tx, group *record.Group) error
	UpdateGroup(ctx context.Context, tx *sql.Tx, group *record.Group) error
	GetGroupById(ctx context.Context, tx *sql.Tx, groupId int64) (*record.Group, error)
	GetGroupByGroupIdentifier(ctx context.Context, tx *sql.Tx, groupIdentifier string) (*record.Group, error)
	GetGroupsByIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.Group, error)
	GetAllGroups(ctx context.Context, tx *sql.Tx) ([]record.Group, error)
	GetAllGroupsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int) ([]record.Group, int, error)
	GetGroupMembersPaginated(ctx context.Context, tx *sql.Tx, groupId int64, page int, pageSize int) ([]record.User, int, error)
	CountGroupMembers(ctx context.Context, tx *sql.Tx, groupId int64) (int, error)
	DeleteGroup(ctx context.Context, tx *sql.Tx, groupId int64) error
	GroupsLoadAttributes(ctx context.Context, tx *sql.Tx, groups []record.Group) error
	GroupsLoadPermissions(ctx context.Context, tx *sql.Tx, groups []record.Group) error
	GroupLoadPermissions(ctx context.Context, tx *sql.Tx, group *record.Group) error

	CreateUserAttribute(ctx context.Context, tx *sql.Tx, userAttribute *record.UserAttribute) error
	UpdateUserAttribute(ctx context.Context, tx *sql.Tx, userAttribute *record.UserAttribute) error
	GetUserAttributeById(ctx context.Context, tx *sql.Tx, userAttributeId int64) (*record.UserAttribute, error)
	GetUserAttributesByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserAttribute, error)
	DeleteUserAttribute(ctx context.Context, tx *sql.Tx, userAttributeId int64) error

	CreateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *record.UserProfilePicture) error
	UpdateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *record.UserProfilePicture) error
	GetUserProfilePictureByUserId(ctx context.Context, tx *sql.Tx, userId int64) (*record.UserProfilePicture, error)
	DeleteUserProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)

	CreateClientLogo(ctx context.Context, tx *sql.Tx, clientLogo *record.ClientLogo) error
	UpdateClientLogo(ctx context.Context, tx *sql.Tx, clientLogo *record.ClientLogo) error
	GetClientLogoByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (*record.ClientLogo, error)
	DeleteClientLogo(ctx context.Context, tx *sql.Tx, clientId int64) error
	ClientHasLogo(ctx context.Context, tx *sql.Tx, clientId int64) (bool, error)

	CreateAuditLog(ctx context.Context, tx *sql.Tx, auditLog *record.AuditLog) error
	DeleteOldAuditLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error)
	GetAuditLogsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int, auditEvent string, requestId string) ([]record.AuditLog, int, error)

	CreateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *record.ClientPermission) error
	UpdateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *record.ClientPermission) error
	GetClientPermissionById(ctx context.Context, tx *sql.Tx, clientPermissionId int64) (*record.ClientPermission, error)
	GetClientPermissionByClientIdAndPermissionId(ctx context.Context, tx *sql.Tx, clientId, permissionId int64) (*record.ClientPermission, error)
	GetClientPermissionsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.ClientPermission, error)
	DeleteClientPermission(ctx context.Context, tx *sql.Tx, clientPermissionId int64) error

	CreateUserSession(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	UpdateUserSession(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	GetUserSessionById(ctx context.Context, tx *sql.Tx, userSessionId int64) (*record.UserSession, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*record.UserSession, error)
	GetUserSessionsByClientIdPaginated(ctx context.Context, tx *sql.Tx, clientId int64, page int, pageSize int) ([]record.UserSession, int, error)
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserSession, error)
	DeleteUserSession(ctx context.Context, tx *sql.Tx, userSessionId int64) error
	// AcquireUserSessionRow takes the session's row inside the caller's transaction and
	// holds it until that transaction ends, the way AcquireClientRow does for a client
	// (#245). It keys on the session identifier because that is what a ceremony holds,
	// and that column is UNIQUE on all four engines, so the statement is a single-row
	// lock everywhere.
	//
	// What it buys is an order between two transactions that would otherwise not have
	// one: a ceremony inserting an authorization code and a termination sweeping that
	// session's grants both write this row before touching anything else, so one waits
	// for the other. Whichever waits then learns its answer after the wait rather than
	// from a snapshot taken before it (#139).
	//
	// True means the row was still there, false means it is gone. The answer is
	// reported rather than left to a later read, because "the session is gone" is the
	// condition the caller acts on and asking it twice would let the two answers
	// disagree.
	//
	// A transaction is required: without one the statement autocommits and the row is
	// released before the caller can use it, which is the whole of what this buys. An
	// empty session identifier is refused, because no row carries one and the statement
	// would otherwise report "gone" for every session there is.
	AcquireUserSessionRow(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (bool, error)
	// PromoteUserSessionGeneration moves one session to a new authentication
	// generation. Narrow because BumpUserSession writes the whole row on every
	// request and would otherwise undo the promotion (#106). Errors if no row matched:
	// a caller preserving a session and its tokens together must not have half of that
	// silently succeed.
	PromoteUserSessionGeneration(ctx context.Context, tx *sql.Tx, userSessionId int64, generation int64) error
	// PromoteUserSessionOtpConfigGeneration records that this session has satisfied the
	// level 2 question against the given OTP configuration generation. Narrow for the
	// reason PromoteUserSessionGeneration is: BumpUserSession writes the whole row on
	// every request and would otherwise undo the promotion. Errors if no row matched,
	// also for that reason.
	//
	// Called from exactly one place, /auth/completed, and with a value captured earlier
	// in the ceremony rather than read live: an authenticator change landing between
	// /auth/level2 and here must not be discharged by a ceremony that never saw it
	// (#242, #106 decision 11).
	PromoteUserSessionOtpConfigGeneration(ctx context.Context, tx *sql.Tx, userSessionId int64, generation int64) error
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	UserSessionsLoadUsers(ctx context.Context, tx *sql.Tx, userSessions []record.UserSession) error
	UserSessionLoadClients(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error
	UserSessionsLoadClients(ctx context.Context, tx *sql.Tx, userSessions []record.UserSession) error
	DeleteIdleSessions(ctx context.Context, tx *sql.Tx, idleTimeout time.Duration) error
	DeleteExpiredSessions(ctx context.Context, tx *sql.Tx, maxLifetime time.Duration) error

	// A browser session is the state the session cookie used to carry. The cookie now
	// holds an opaque identifier and the row holds everything else (#266).
	//
	// Every method is keyed on (owner, sessionIdHash) rather than on the surrogate id,
	// because the store never holds the id: it has an identifier from a cookie and the
	// name of the application asking. That pair is the table's unique index.
	CreateBrowserSession(ctx context.Context, tx *sql.Tx, browserSession *record.BrowserSession) error
	// GetBrowserSessionByOwnerAndSessionIdHash returns the live session, or nil if there
	// is none. `now` is an active-expiry predicate and not a hint: the statement matches
	// only expires_at > now, so an expired row reads as absent whether or not the reaper
	// has reached it. Without that term the idle timeout and the maximum lifetime would
	// be a deletion schedule rather than a request-time rule, and a session would
	// survive every one of its own deadlines until a sweep happened to run.
	//
	// nil and an error are different answers and must stay that way: nil is "there is no
	// such session", which is a fresh session, and an error is "I could not ask", which
	// is a refused request. Collapsing the second into the first would silently sign
	// everyone out during any database interruption.
	GetBrowserSessionByOwnerAndSessionIdHash(ctx context.Context, tx *sql.Tx, owner, sessionIdHash string, now time.Time) (*record.BrowserSession, error)
	// UpdateBrowserSessionData replaces one session's contents and moves its deadlines.
	// Narrow rather than the house's full-row Update<Model> because it sits on a
	// per-request path and because the caller holds no id, the reason
	// PromoteUserSessionOtpConfigGeneration is narrow.
	//
	// It reports whether a row TRANSITIONED, not whether one matched: false means the
	// session is gone or expired, which is what lets the caller tell "written" from "the
	// row is no longer there". The expires_at > now term is in the WHERE for the reason
	// it is in the read, so a write can never touch an expired row back to life.
	UpdateBrowserSessionData(ctx context.Context, tx *sql.Tx, owner, sessionIdHash, data string, now, expiresAt time.Time) (bool, error)
	// TouchBrowserSession records that a live session was used, and reports whether a row
	// transitioned. It moves expires_at as well as last_accessed: the idle window is
	// expressed in expires_at, so a touch that left it alone would never extend the
	// session and the idle timeout would behave as an absolute one.
	TouchBrowserSession(ctx context.Context, tx *sql.Tx, owner, sessionIdHash string, now, expiresAt time.Time) (bool, error)
	DeleteBrowserSession(ctx context.Context, tx *sql.Tx, owner, sessionIdHash string) error
	// DeleteExpiredBrowserSessions reaps on expires_at alone, across both owners. The
	// row was already unusable before this ran, by the predicate above; this is what
	// stops the table growing.
	DeleteExpiredBrowserSessions(ctx context.Context, tx *sql.Tx, now time.Time) error

	// A parked authorization request is what a POST to /auth/authorize leaves for the GET it
	// answers with (#246, #437). Keyed on the handle's digest, like a browser session on its
	// identifier's.
	CreateAuthorizeRequest(ctx context.Context, tx *sql.Tx, authorizeRequest *record.AuthorizeRequest) error
	// GetAuthorizeRequestByHandleHash returns the live request, or nil: `now` is an active-expiry
	// predicate, so an expired row reads as absent whether or not the sweep has reached it.
	GetAuthorizeRequestByHandleHash(ctx context.Context, tx *sql.Tx, handleHash string, now time.Time) (*record.AuthorizeRequest, error)
	// ClaimAuthorizeRequest deletes one request and reports whether THIS call did, the one-winner
	// claim in MarkCodeAsUsed's shape: only the caller told true may act on what it read.
	ClaimAuthorizeRequest(ctx context.Context, tx *sql.Tx, authorizeRequestId int64) (bool, error)
	// DeleteExpiredAuthorizeRequests reaps on expires_at alone.
	DeleteExpiredAuthorizeRequests(ctx context.Context, tx *sql.Tx, now time.Time) error

	// A rate-limit counter is one shared tier's count for one key digest in one window, which is
	// what lets every replica spend the same credential-guessing budget (#394).
	//
	// ReserveRateLimitHit charges one hit to keyHash's current window when admit, handed the
	// current and previous windows' counts before this hit, answers true, and reports whether it
	// charged. The read, the decision and the charge are atomic across every handle on the
	// database, across a window's roll too: the charge takes the previous window's row and then
	// the current one's, and admit is asked again under both, so two pods can never both take the
	// last slot, whichever of two adjacent windows each is charging. A key that already has a row
	// for a later window is ErrRateLimitWindowMoved, with nothing charged. A refusal writes
	// nothing. It owns its transaction, as ReencryptToKey does, because creating a window's row
	// can lose a race on the key, which on PostgreSQL aborts the transaction it ran in. expiresAt
	// is when the current window's row stops counting.
	ReserveRateLimitHit(ctx context.Context, keyHash string, current, previous, expiresAt time.Time,
		admit func(curr, prev int) bool) (bool, error)
	// RefundRateLimitHit takes one hit back from the window it was charged in, never below zero.
	RefundRateLimitHit(ctx context.Context, tx *sql.Tx, keyHash string, windowStart time.Time) error
	// GetRateLimitCounts reports keyHash's hits in the current and the previous window, zero
	// where there is no row.
	GetRateLimitCounts(ctx context.Context, tx *sql.Tx, keyHash string, current, previous time.Time) (curr, prev int, err error)
	// DeleteExpiredRateLimitCounters reaps on expires_at alone.
	DeleteExpiredRateLimitCounters(ctx context.Context, tx *sql.Tx, now time.Time) error

	CreateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *record.UserConsent) error
	UpdateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *record.UserConsent) error
	GetUserConsentById(ctx context.Context, tx *sql.Tx, userConsentId int64) (*record.UserConsent, error)
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error)
	GetConsentsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserConsent, error)
	DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentId int64) error
	DeleteAllUserConsent(ctx context.Context, tx *sql.Tx) error
	UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []record.UserConsent) error

	CreatePreRegistration(ctx context.Context, tx *sql.Tx, preRegistration *record.PreRegistration) error
	UpdatePreRegistration(ctx context.Context, tx *sql.Tx, preRegistration *record.PreRegistration) error
	GetPreRegistrationById(ctx context.Context, tx *sql.Tx, preRegistrationId int64) (*record.PreRegistration, error)
	GetPreRegistrationByEmail(ctx context.Context, tx *sql.Tx, email string) (*record.PreRegistration, error)
	// GetPreRegistrationByVerificationCodeHash finds the pre-registration an activation
	// code belongs to, by an unsalted SHA-256 of that code. This is what lets the
	// activation link carry the code and nothing else, so no email address travels in it
	// (#112). An empty codeHash returns (nil, nil) without querying, as the user lookup
	// does.
	GetPreRegistrationByVerificationCodeHash(ctx context.Context, tx *sql.Tx, codeHash string) (*record.PreRegistration, error)
	// TryReplacePreRegistrationCode gives a dead pending registration a fresh code, only while
	// the row still holds the dead code the caller read, and reports whether this call did.
	// Compare-and-set for the same reason MarkCodeAsUsed is: of two repeats racing for one dead
	// row, exactly one replaces it and sends a link (#207 decision 6).
	TryReplacePreRegistrationCode(ctx context.Context, tx *sql.Tx, preRegistrationId int64, deadCodeHash string,
		codeEncrypted []byte, codeHash string, issuedAt time.Time) (bool, error)
	DeletePreRegistration(ctx context.Context, tx *sql.Tx, preRegistrationId int64) error
	// DeletePreRegistrationHoldingCode deletes a pending registration only while it still holds
	// the code the caller read, and reports whether this call did. A replacement keeps the row's
	// id, so a delete by id alone from a caller that read the row before it would take the fresh
	// link with it (#207 decision 6).
	DeletePreRegistrationHoldingCode(ctx context.Context, tx *sql.Tx, preRegistrationId int64, codeHash string) (bool, error)
	// DeleteDeadPreRegistrations sweeps every pending registration whose code was issued before
	// deadBefore, or never issued, and leaves every other. The caller passes
	// emaillinks.PreRegistrationDeadBefore, the one definition of a pending registration that can
	// no longer complete, so the sweep and the replacement never disagree about a row (#207
	// decision 7).
	DeleteDeadPreRegistrations(ctx context.Context, tx *sql.Tx, deadBefore time.Time) error

	CreateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *record.UserGroup) error
	UpdateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *record.UserGroup) error
	GetUserGroupById(ctx context.Context, tx *sql.Tx, userGroupId int64) (*record.UserGroup, error)
	GetUserGroupByUserIdAndGroupId(ctx context.Context, tx *sql.Tx, userId, groupId int64) (*record.UserGroup, error)
	GetUserGroupsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserGroup, error)
	GetUserGroupsByUserIds(ctx context.Context, tx *sql.Tx, userIds []int64) ([]record.UserGroup, error)
	DeleteUserGroup(ctx context.Context, tx *sql.Tx, userGroupId int64) error

	CreateGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttribute *record.GroupAttribute) error
	UpdateGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttribute *record.GroupAttribute) error
	GetGroupAttributeById(ctx context.Context, tx *sql.Tx, groupAttributeId int64) (*record.GroupAttribute, error)
	GetGroupAttributesByGroupId(ctx context.Context, tx *sql.Tx, groupId int64) ([]record.GroupAttribute, error)
	GetGroupAttributesByGroupIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.GroupAttribute, error)
	DeleteGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttributeId int64) error

	CreateGroupPermission(ctx context.Context, tx *sql.Tx, groupPermission *record.GroupPermission) error
	UpdateGroupPermission(ctx context.Context, tx *sql.Tx, groupPermission *record.GroupPermission) error
	GetGroupPermissionById(ctx context.Context, tx *sql.Tx, groupPermissionId int64) (*record.GroupPermission, error)
	GetGroupPermissionByGroupIdAndPermissionId(ctx context.Context, tx *sql.Tx, groupId, permissionId int64) (*record.GroupPermission, error)
	GetGroupPermissionsByGroupIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.GroupPermission, error)
	GetGroupPermissionsByGroupId(ctx context.Context, tx *sql.Tx, groupId int64) ([]record.GroupPermission, error)
	DeleteGroupPermission(ctx context.Context, tx *sql.Tx, groupPermissionId int64) error

	CreateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	UpdateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	// MarkRefreshTokenAsRevoked atomically flips a refresh token from live to revoked
	// and reports whether this call is the one that made the transition. It is the
	// guard against double-spending a single refresh token, for the same reason
	// MarkCodeAsUsed guards an authorization code (#128).
	MarkRefreshTokenAsRevoked(ctx context.Context, tx *sql.Tx, refreshTokenId int64) (bool, error)
	// RevokeRefreshTokenFamily revokes every currently live member of one rotation
	// family, identified by the first_refresh_token_jti its members share, and returns
	// the exact number of rows it moved from live to revoked. An empty identifier is an
	// error rather than a no-op, since on a revocation path it can only be a caller
	// bug (#128).
	RevokeRefreshTokenFamily(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (int64, error)
	// RecordRefreshTokenFamilyRevoked writes the durable record that a rotation family is
	// revoked, and reports whether this call wrote it. A family already recorded is left as it
	// was. A sweep of live rows cannot catch a child a rotation inserts after the sweep, and a
	// record outlives every member, so a child born into a recorded family is refused (#132,
	// #259). Two overlapping first writes of one family lose on the key as ErrUniqueViolation,
	// and the caller reruns its transaction once.
	RecordRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string, reason string) (bool, error)
	// IsRefreshTokenFamilyRevoked reports whether a rotation family has a revocation record.
	IsRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error)
	// DeleteOrphanedRefreshTokenFamilyRevocations removes the records of families that have no
	// refresh token left, which is when a record has nothing left to refuse.
	DeleteOrphanedRefreshTokenFamilyRevocations(ctx context.Context, tx *sql.Tx) error
	GetRefreshTokenById(ctx context.Context, tx *sql.Tx, refreshTokenId int64) (*record.RefreshToken, error)
	GetRefreshTokenByJti(ctx context.Context, tx *sql.Tx, jti string) (*record.RefreshToken, error)
	GetRefreshTokensByCodeId(ctx context.Context, tx *sql.Tx, codeId int64) ([]*record.RefreshToken, error)
	GetRefreshTokensBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) ([]*record.RefreshToken, error)
	// GetRefreshTokensByUserId returns every refresh token belonging to a user,
	// through either linkage shape: codes.user_id for the authorization code flow and
	// refresh_tokens.user_id for ROPC. GetRefreshTokensBySessionIdentifier cannot
	// substitute for it, because that query joins through codes and so excludes ROPC
	// rows, and because it needs a live session row to supply the identifier (#106).
	GetRefreshTokensByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]*record.RefreshToken, error)
	// GetRefreshTokensByClientId returns every refresh token belonging to a client,
	// through either linkage shape: codes.client_id for the authorization code flow,
	// where refresh_tokens.client_id is null, and refresh_tokens.client_id for ROPC,
	// where there is no code at all. GetRefreshTokensBySessionIdentifier cannot
	// substitute for it, for the two reasons it cannot substitute for the by-user
	// query: it joins through codes and so excludes ROPC rows, and it needs a live
	// session row to supply the identifier. Used by the confidential-to-public flip,
	// which must reach every grant the client holds however it was issued (#245).
	GetRefreshTokensByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]*record.RefreshToken, error)
	// PromoteRefreshTokenGenerations moves the named, unrevoked refresh tokens to a
	// new authentication generation. An empty id list is a no-op (#106).
	PromoteRefreshTokenGenerations(ctx context.Context, tx *sql.Tx, refreshTokenIds []int64, generation int64) error
	DeleteRefreshToken(ctx context.Context, tx *sql.Tx, refreshTokenId int64) error
	RefreshTokenLoadCode(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *record.RefreshToken) error
	// DeleteExpiredRefreshTokens deletes refresh tokens the protocol can no longer
	// accept, by expires_at or max_lifetime. Being revoked is NOT a reason to delete
	// a row: a revoked row is the replay-detection signal, and reaping it early means
	// a replay is refused but never detected and its live family never contained
	// (#128, RFC 9700 Section 4.14.2).
	DeleteExpiredRefreshTokens(ctx context.Context, tx *sql.Tx) error

	CreateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error
	UpdateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *record.UserSessionClient) error
	GetUserSessionClientById(ctx context.Context, tx *sql.Tx, userSessionClientId int64) (*record.UserSessionClient, error)
	GetUserSessionsClientByIds(ctx context.Context, tx *sql.Tx, userSessionClientIds []int64) ([]record.UserSessionClient, error)
	GetUserSessionClientsByUserSessionId(ctx context.Context, tx *sql.Tx, userSessionId int64) ([]record.UserSessionClient, error)
	GetUserSessionClientsByUserSessionIds(ctx context.Context, tx *sql.Tx, userSessionIds []int64) ([]record.UserSessionClient, error)
	DeleteUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClientId int64) error
	UserSessionClientsLoadClients(ctx context.Context, tx *sql.Tx, userSessionClients []record.UserSessionClient) error
}

// ErrUniqueViolation is what a caller asks about when it wants to know whether a write lost a race
// for a unique key: an insert or an update the engine refused because some unique index already
// holds that value.
//
// It exists so that question has one answer on all four engines. Each driver reports the violation
// its own way -- SQLite code 2067, MySQL 1062, PostgreSQL SQLSTATE 23505, SQL Server 2627 or 2601,
// by value or by pointer -- and before this the one caller that cared read the driver's English
// sentence looking for the words "email" and "already", which matched none of the four engines'
// actual texts and so had never once fired. commondb tags a failure it classifies as one with this
// sentinel on the way out of the data layer, so every caller above it asks errors.Is and nothing
// else (#279).
//
// It is a plain stdlib errors.New, and it is the one shape guard.AssertNoLegacyErrors exempts: a
// package-level sentinel must carry no stack, because a stack captured at init records the
// program's startup rather than the failure, and would then masquerade as the origin of every error
// wrapping it.
//
// It says nothing about WHICH key was violated. A caller that needs to distinguish two unique keys
// on one table has to look at the driver error itself, which is still reachable through errors.As
// below this.
var ErrUniqueViolation = errors.New("unique constraint violation")

// ErrRateLimitWindowMoved is ReserveRateLimitHit finding a row for a window later than the one it
// was asked to charge: another pod has opened that window for the key, and may have admitted
// against a count this charge would change after the fact, so nothing is charged. The caller
// places the reservation again, in the later window (#394).
var ErrRateLimitWindowMoved = errors.New("the rate limit window has moved on")
