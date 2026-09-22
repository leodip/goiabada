package data

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/commondb"
	"github.com/leodip/goiabada/authserver/internal/models"
)

type Database interface {
	BeginTransaction(ctx context.Context) (*sql.Tx, error)
	CommitTransaction(tx *sql.Tx) error
	RollbackTransaction(tx *sql.Tx) error
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
	Migrate() error
	// ScanEmailCase reads every users row as its id, its stored address and that address as
	// THIS engine's own LOWER() reduces it, which is the read behind the startup pre-flight
	// (the auth server's datafactory.CheckEmailCaseBeforeMigrating). It compares nothing: the
	// engines disagree about what LOWER() means and the rule is Go's strings.ToLower, so the
	// comparison is the caller's (#351). It replaced BackfillLowercaseEmails, which repaired
	// the data at startup rather than refusing to migrate it.
	ScanEmailCase() ([]models.EmailCaseRow, error)
	RotateEncryptionKeyIfNeeded(currentKey, previousKey []byte) (bool, error)
	IsEmpty() (bool, error)

	CreateClient(ctx context.Context, tx *sql.Tx, client *models.Client) error
	UpdateClient(ctx context.Context, tx *sql.Tx, client *models.Client) error
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
	GetClientById(ctx context.Context, tx *sql.Tx, clientId int64) (*models.Client, error)
	GetClientsByIds(ctx context.Context, tx *sql.Tx, clientIds []int64) ([]models.Client, error)
	GetClientByClientIdentifier(ctx context.Context, tx *sql.Tx, clientIdentifier string) (*models.Client, error)
	GetAllClients(ctx context.Context, tx *sql.Tx) ([]models.Client, error)
	DeleteClient(ctx context.Context, tx *sql.Tx, clientId int64) error
	ClientLoadRedirectURIs(ctx context.Context, tx *sql.Tx, client *models.Client) error
	ClientLoadWebOrigins(ctx context.Context, tx *sql.Tx, client *models.Client) error
	ClientLoadPermissions(ctx context.Context, tx *sql.Tx, client *models.Client) error

	CreateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
	UpdateUser(ctx context.Context, tx *sql.Tx, user *models.User) error
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*models.User, error)
	GetUsersByIds(ctx context.Context, tx *sql.Tx, userIds []int64) (map[int64]models.User, error)
	GetUserByUsername(ctx context.Context, tx *sql.Tx, username string) (*models.User, error)
	GetUserBySubject(ctx context.Context, tx *sql.Tx, subject string) (*models.User, error)
	GetUserByEmail(ctx context.Context, tx *sql.Tx, email string) (*models.User, error)
	// GetUserByForgotPasswordCodeHash finds the user holding an outstanding reset code,
	// by an unsalted SHA-256 of that code. This is what lets the reset link carry the
	// code and nothing else, so no email address travels in it (#112). An empty codeHash
	// returns (nil, nil) without querying: '' is the dormant value on every row with no
	// code outstanding, so a query would match one of them.
	GetUserByForgotPasswordCodeHash(ctx context.Context, tx *sql.Tx, codeHash string) (*models.User, error)
	SearchUsersPaginated(ctx context.Context, tx *sql.Tx, query string, page int, pageSize int) ([]models.User, int, error)
	DeleteUser(ctx context.Context, tx *sql.Tx, userId int64) error
	// IncrementUserAuthStateGeneration advances the user's authentication generation
	// and returns the new value. Separate from UpdateUser because the column is tagged
	// dont-update: every credential handler writes the whole user back, so an ordinary
	// update would let a stale model regress the boundary (#106).
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
	// TryConsumeForgotPasswordCode writes a password hash and claims the outstanding
	// reset code in one conditional UPDATE, reporting whether this call is the one that
	// made the transition. Compare-and-set for the same reason MarkCodeAsUsed is: a
	// read-then-unconditional-write lets two concurrent requests both believe they
	// completed the reset.
	//
	// Separate from SetUserPasswordHash rather than a fourth parameter on it, because
	// its other two callers (admin user create, account password change) hold no
	// outstanding code and would have to pass a meaningless predicate. An empty codeHash
	// or a zero userId is an error rather than a false: '' is the dormant value on every
	// row with no code outstanding, so an empty predicate would claim one of them (#112).
	TryConsumeForgotPasswordCode(ctx context.Context, tx *sql.Tx, userId int64, codeHash string, passwordHash string) (bool, error)
	// TrySetUserEnabled flips enabled from expected to desired, reporting whether this
	// call made the transition. Compare-and-set for the same reason MarkCodeAsUsed is.
	// The disable direction's return gates the revocation sweep (#106).
	TrySetUserEnabled(ctx context.Context, tx *sql.Tx, userId int64, expected bool, desired bool) (bool, error)
	// TryConsumeUserOTPStep records step as the user's most recently consumed TOTP
	// time step, only if it is strictly newer than what is stored, and reports whether
	// this call made the transition. Compare-and-set for the same reason MarkCodeAsUsed
	// is: accepting a code and recording it as used must not be separable, or two
	// concurrent submissions of one code both pass (#111). requireOTPEnabled adds
	// otp_enabled to the predicate, which verification sites set and enrollment sites
	// do not. False means no row transitioned, which is a replay in all but a rare
	// interleaving, never specifically proof of one.
	TryConsumeUserOTPStep(ctx context.Context, tx *sql.Tx, userId int64, step int64, requireOTPEnabled bool) (bool, error)
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
	// ClearPendingOTPEnrollment returns the pending enrollment pair to NULL. Called
	// inside the transaction that establishes the authenticator, so no committed
	// state has OTP enabled with a live pending seed still installed (#247).
	ClearPendingOTPEnrollment(ctx context.Context, tx *sql.Tx, userId int64) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *models.User) error
	UsersLoadGroups(ctx context.Context, tx *sql.Tx, users []models.User) error
	UserLoadPermissions(ctx context.Context, tx *sql.Tx, user *models.User) error
	UsersLoadPermissions(ctx context.Context, tx *sql.Tx, users []models.User) error
	UserLoadAttributes(ctx context.Context, tx *sql.Tx, user *models.User) error

	CreateCode(ctx context.Context, tx *sql.Tx, code *models.Code) error
	UpdateCode(ctx context.Context, tx *sql.Tx, code *models.Code) error
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
	GetCodeById(ctx context.Context, tx *sql.Tx, codeId int64) (*models.Code, error)
	GetCodeByCodeHash(ctx context.Context, tx *sql.Tx, codeHash string, used bool) (*models.Code, error)
	DeleteCode(ctx context.Context, tx *sql.Tx, codeId int64) error
	CodeLoadClient(ctx context.Context, tx *sql.Tx, code *models.Code) error
	CodeLoadUser(ctx context.Context, tx *sql.Tx, code *models.Code) error
	// DeleteUsedCodesWithoutRefreshTokens reaps codes that can no longer produce
	// anything: those redeemed but never followed by a refresh token, and those
	// revoked while still unredeemed, which is what ending a session leaves behind
	// when the grant it marked had not been exchanged yet (#129).
	//
	// createdBefore is a required grace cutoff shared by both, and only codes created
	// before it are deleted. For the redeemed ones it is required for correctness:
	// without it the sweep races the token endpoint, which marks a code used and only
	// then inserts the refresh token that references it, so a code mid-redemption
	// matches and its deletion fails the insert with a foreign key violation. For the
	// revoked ones it is the 60 second code lifetime, past which the code can no
	// longer be exchanged at all. A cutoff comfortably beyond 60 seconds serves both.
	//
	// A revoked code that WAS redeemed is deliberately out of reach here while any
	// refresh token still references it, because that marker is what rejects the
	// token.
	DeleteUsedCodesWithoutRefreshTokens(ctx context.Context, tx *sql.Tx, createdBefore time.Time) error

	CreateResource(ctx context.Context, tx *sql.Tx, resource *models.Resource) error
	UpdateResource(ctx context.Context, tx *sql.Tx, resource *models.Resource) error
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*models.Resource, error)
	GetResourcesByIds(ctx context.Context, tx *sql.Tx, resourceIds []int64) ([]models.Resource, error)
	GetResourceByResourceIdentifier(ctx context.Context, tx *sql.Tx, resourceIdentifier string) (*models.Resource, error)
	GetAllResources(ctx context.Context, tx *sql.Tx) ([]models.Resource, error)
	DeleteResource(ctx context.Context, tx *sql.Tx, resourceId int64) error

	CreatePermission(ctx context.Context, tx *sql.Tx, permission *models.Permission) error
	UpdatePermission(ctx context.Context, tx *sql.Tx, permission *models.Permission) error
	GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*models.Permission, error)
	GetPermissionsByIds(ctx context.Context, tx *sql.Tx, permissionIds []int64) ([]models.Permission, error)
	GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]models.Permission, error)
	DeletePermission(ctx context.Context, tx *sql.Tx, permissionId int64) error
	PermissionsLoadResources(ctx context.Context, tx *sql.Tx, permissions []models.Permission) error

	CreateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error
	UpdateKeyPair(tx *sql.Tx, keyPair *models.KeyPair) error
	// UpdateKeyPairState moves one key from an expected state to a new one, and reports
	// whether this call is the one that made the transition. Compare-and-set for the same
	// reason MarkCodeAsUsed is: a read-then-unconditional-write lets two concurrent
	// rotations both act on the snapshot they read, and the loser then destroys the key
	// the winner had just demoted for the grace period rotation exists to provide (#251).
	//
	// A false return means no row transitioned, so the caller lost a race or the row is
	// gone. It is not an error.
	UpdateKeyPairState(tx *sql.Tx, keyPairId int64, fromState string, toState string) (bool, error)
	GetKeyPairById(tx *sql.Tx, keyPairId int64) (*models.KeyPair, error)
	GetAllSigningKeys(tx *sql.Tx) ([]models.KeyPair, error)
	// GetCurrentSigningKey returns an error when no key is in the current state, rather
	// than the (nil, nil) this codebase returns for a lookup that may legitimately miss.
	// The current signing key is a singleton the server cannot run without: every caller
	// dereferences the result to read key material, so (nil, nil) is a nil-pointer panic
	// at each of them and one more at every call site added later. Narrowing the contract
	// here is what makes all of them correct at once, as IncrementUserAuthStateGeneration
	// rejects a nil transaction rather than tolerating it (#251).
	GetCurrentSigningKey(tx *sql.Tx) (*models.KeyPair, error)
	DeleteKeyPair(tx *sql.Tx, keyPairId int64) error

	CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *models.RedirectURI) error
	GetRedirectURIById(ctx context.Context, tx *sql.Tx, redirectURIId int64) (*models.RedirectURI, error)
	GetRedirectURIsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]models.RedirectURI, error)
	DeleteRedirectURI(ctx context.Context, tx *sql.Tx, redirectURIId int64) error

	CreateWebOrigin(ctx context.Context, tx *sql.Tx, webOrigin *models.WebOrigin) error
	GetWebOriginById(ctx context.Context, tx *sql.Tx, webOriginId int64) (*models.WebOrigin, error)
	GetAllWebOrigins(ctx context.Context, tx *sql.Tx) ([]models.WebOrigin, error)
	GetWebOriginsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]models.WebOrigin, error)
	WebOriginExists(ctx context.Context, tx *sql.Tx, origin string) (bool, error)
	DeleteWebOrigin(ctx context.Context, tx *sql.Tx, webOriginId int64) error

	CreateSettings(tx *sql.Tx, settings *models.Settings) error
	UpdateSettings(tx *sql.Tx, settings *models.Settings) error
	GetSettingsById(tx *sql.Tx, settingsId int64) (*models.Settings, error)
	// TryClaimCleanupRun atomically claims the next background cleanup run via a
	// conditional update on settings.last_cleanup_at, and reports whether this
	// caller won it. claimableBefore is the cutoff (pass now minus the interval).
	// This is what keeps the cleanup single-flight across instances and puts the
	// schedule on the wall clock instead of one process's uptime.
	TryClaimCleanupRun(tx *sql.Tx, now time.Time, claimableBefore time.Time) (bool, error)

	CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *models.UserPermission) error
	UpdateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *models.UserPermission) error
	GetUserPermissionById(ctx context.Context, tx *sql.Tx, userPermissionId int64) (*models.UserPermission, error)
	GetUsersByPermissionIdPaginated(ctx context.Context, tx *sql.Tx, permissionId int64, page int, pageSize int) ([]models.User, int, error)
	GetUserPermissionByUserIdAndPermissionId(ctx context.Context, tx *sql.Tx, userId, permissionId int64) (*models.UserPermission, error)
	GetUserPermissionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserPermission, error)
	GetUserPermissionsByUserIds(ctx context.Context, tx *sql.Tx, userIds []int64) ([]models.UserPermission, error)
	DeleteUserPermission(ctx context.Context, tx *sql.Tx, userPermissionId int64) error

	CreateGroup(tx *sql.Tx, group *models.Group) error
	UpdateGroup(tx *sql.Tx, group *models.Group) error
	GetGroupById(tx *sql.Tx, groupId int64) (*models.Group, error)
	GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*models.Group, error)
	GetGroupsByIds(tx *sql.Tx, groupIds []int64) ([]models.Group, error)
	GetAllGroups(tx *sql.Tx) ([]models.Group, error)
	GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]models.Group, int, error)
	GetGroupMembersPaginated(tx *sql.Tx, groupId int64, page int, pageSize int) ([]models.User, int, error)
	CountGroupMembers(tx *sql.Tx, groupId int64) (int, error)
	DeleteGroup(tx *sql.Tx, groupId int64) error
	GroupsLoadAttributes(tx *sql.Tx, groups []models.Group) error
	GroupsLoadPermissions(tx *sql.Tx, groups []models.Group) error
	GroupLoadPermissions(tx *sql.Tx, group *models.Group) error

	CreateUserAttribute(ctx context.Context, tx *sql.Tx, userAttribute *models.UserAttribute) error
	UpdateUserAttribute(ctx context.Context, tx *sql.Tx, userAttribute *models.UserAttribute) error
	GetUserAttributeById(ctx context.Context, tx *sql.Tx, userAttributeId int64) (*models.UserAttribute, error)
	GetUserAttributesByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserAttribute, error)
	DeleteUserAttribute(ctx context.Context, tx *sql.Tx, userAttributeId int64) error

	CreateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *models.UserProfilePicture) error
	UpdateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *models.UserProfilePicture) error
	GetUserProfilePictureByUserId(ctx context.Context, tx *sql.Tx, userId int64) (*models.UserProfilePicture, error)
	DeleteUserProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) error
	UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error)

	CreateClientLogo(ctx context.Context, tx *sql.Tx, clientLogo *models.ClientLogo) error
	UpdateClientLogo(ctx context.Context, tx *sql.Tx, clientLogo *models.ClientLogo) error
	GetClientLogoByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (*models.ClientLogo, error)
	DeleteClientLogo(ctx context.Context, tx *sql.Tx, clientId int64) error
	ClientHasLogo(ctx context.Context, tx *sql.Tx, clientId int64) (bool, error)

	CreateAuditLog(tx *sql.Tx, auditLog *models.AuditLog) error
	DeleteOldAuditLogs(tx *sql.Tx, cutoff time.Time, maxDeletions int) (int, error)
	GetAuditLogsPaginated(tx *sql.Tx, page int, pageSize int, auditEvent string, requestId string) ([]models.AuditLog, int, error)

	CreateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *models.ClientPermission) error
	UpdateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *models.ClientPermission) error
	GetClientPermissionById(ctx context.Context, tx *sql.Tx, clientPermissionId int64) (*models.ClientPermission, error)
	GetClientPermissionByClientIdAndPermissionId(ctx context.Context, tx *sql.Tx, clientId, permissionId int64) (*models.ClientPermission, error)
	GetClientPermissionsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]models.ClientPermission, error)
	DeleteClientPermission(ctx context.Context, tx *sql.Tx, clientPermissionId int64) error

	CreateUserSession(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
	UpdateUserSession(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
	GetUserSessionById(ctx context.Context, tx *sql.Tx, userSessionId int64) (*models.UserSession, error)
	GetUserSessionBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (*models.UserSession, error)
	GetUserSessionsByClientIdPaginated(ctx context.Context, tx *sql.Tx, clientId int64, page int, pageSize int) ([]models.UserSession, int, error)
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserSession, error)
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
	UserSessionLoadUser(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
	UserSessionsLoadUsers(ctx context.Context, tx *sql.Tx, userSessions []models.UserSession) error
	UserSessionLoadClients(ctx context.Context, tx *sql.Tx, userSession *models.UserSession) error
	UserSessionsLoadClients(ctx context.Context, tx *sql.Tx, userSessions []models.UserSession) error
	DeleteIdleSessions(ctx context.Context, tx *sql.Tx, idleTimeout time.Duration) error
	DeleteExpiredSessions(ctx context.Context, tx *sql.Tx, maxLifetime time.Duration) error

	// A browser session is the state the session cookie used to carry. The cookie now
	// holds an opaque identifier and the row holds everything else (#266).
	//
	// Every method is keyed on (owner, sessionIdHash) rather than on the surrogate id,
	// because the store never holds the id: it has an identifier from a cookie and the
	// name of the application asking. That pair is the table's unique index.
	CreateBrowserSession(ctx context.Context, tx *sql.Tx, browserSession *models.BrowserSession) error
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
	GetBrowserSessionByOwnerAndSessionIdHash(ctx context.Context, tx *sql.Tx, owner, sessionIdHash string, now time.Time) (*models.BrowserSession, error)
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

	CreateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *models.UserConsent) error
	UpdateUserConsent(ctx context.Context, tx *sql.Tx, userConsent *models.UserConsent) error
	GetUserConsentById(ctx context.Context, tx *sql.Tx, userConsentId int64) (*models.UserConsent, error)
	GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*models.UserConsent, error)
	GetConsentsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserConsent, error)
	DeleteUserConsent(ctx context.Context, tx *sql.Tx, userConsentId int64) error
	DeleteAllUserConsent(ctx context.Context, tx *sql.Tx) error
	UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []models.UserConsent) error

	CreatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error
	UpdatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error
	GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*models.PreRegistration, error)
	GetPreRegistrationByEmail(tx *sql.Tx, email string) (*models.PreRegistration, error)
	// GetPreRegistrationByVerificationCodeHash finds the pre-registration an activation
	// code belongs to, by an unsalted SHA-256 of that code. This is what lets the
	// activation link carry the code and nothing else, so no email address travels in it
	// (#112). An empty codeHash returns (nil, nil) without querying, as the user lookup
	// does.
	GetPreRegistrationByVerificationCodeHash(tx *sql.Tx, codeHash string) (*models.PreRegistration, error)
	DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error

	CreateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *models.UserGroup) error
	UpdateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *models.UserGroup) error
	GetUserGroupById(ctx context.Context, tx *sql.Tx, userGroupId int64) (*models.UserGroup, error)
	GetUserGroupByUserIdAndGroupId(ctx context.Context, tx *sql.Tx, userId, groupId int64) (*models.UserGroup, error)
	GetUserGroupsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserGroup, error)
	GetUserGroupsByUserIds(ctx context.Context, tx *sql.Tx, userIds []int64) ([]models.UserGroup, error)
	DeleteUserGroup(ctx context.Context, tx *sql.Tx, userGroupId int64) error

	CreateGroupAttribute(tx *sql.Tx, groupAttribute *models.GroupAttribute) error
	UpdateGroupAttribute(tx *sql.Tx, groupAttribute *models.GroupAttribute) error
	GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*models.GroupAttribute, error)
	GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]models.GroupAttribute, error)
	GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]models.GroupAttribute, error)
	DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error

	CreateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error
	UpdateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error
	GetGroupPermissionById(tx *sql.Tx, groupPermissionId int64) (*models.GroupPermission, error)
	GetGroupPermissionByGroupIdAndPermissionId(tx *sql.Tx, groupId, permissionId int64) (*models.GroupPermission, error)
	GetGroupPermissionsByGroupIds(tx *sql.Tx, groupIds []int64) ([]models.GroupPermission, error)
	GetGroupPermissionsByGroupId(tx *sql.Tx, groupId int64) ([]models.GroupPermission, error)
	DeleteGroupPermission(tx *sql.Tx, groupPermissionId int64) error

	CreateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	UpdateRefreshToken(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
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
	GetRefreshTokenById(ctx context.Context, tx *sql.Tx, refreshTokenId int64) (*models.RefreshToken, error)
	GetRefreshTokenByJti(ctx context.Context, tx *sql.Tx, jti string) (*models.RefreshToken, error)
	GetRefreshTokensByCodeId(ctx context.Context, tx *sql.Tx, codeId int64) ([]*models.RefreshToken, error)
	GetRefreshTokensBySessionIdentifier(ctx context.Context, tx *sql.Tx, sessionIdentifier string) ([]*models.RefreshToken, error)
	// GetRefreshTokensByUserId returns every refresh token belonging to a user,
	// through either linkage shape: codes.user_id for the authorization code flow and
	// refresh_tokens.user_id for ROPC. GetRefreshTokensBySessionIdentifier cannot
	// substitute for it, because that query joins through codes and so excludes ROPC
	// rows, and because it needs a live session row to supply the identifier (#106).
	GetRefreshTokensByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]*models.RefreshToken, error)
	// GetRefreshTokensByClientId returns every refresh token belonging to a client,
	// through either linkage shape: codes.client_id for the authorization code flow,
	// where refresh_tokens.client_id is null, and refresh_tokens.client_id for ROPC,
	// where there is no code at all. GetRefreshTokensBySessionIdentifier cannot
	// substitute for it, for the two reasons it cannot substitute for the by-user
	// query: it joins through codes and so excludes ROPC rows, and it needs a live
	// session row to supply the identifier. Used by the confidential-to-public flip,
	// which must reach every grant the client holds however it was issued (#245).
	GetRefreshTokensByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]*models.RefreshToken, error)
	// PromoteRefreshTokenGenerations moves the named, unrevoked refresh tokens to a
	// new authentication generation. An empty id list is a no-op (#106).
	PromoteRefreshTokenGenerations(ctx context.Context, tx *sql.Tx, refreshTokenIds []int64, generation int64) error
	DeleteRefreshToken(ctx context.Context, tx *sql.Tx, refreshTokenId int64) error
	RefreshTokenLoadCode(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	RefreshTokenLoadUser(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	RefreshTokenLoadClient(ctx context.Context, tx *sql.Tx, refreshToken *models.RefreshToken) error
	// DeleteExpiredRefreshTokens deletes refresh tokens the protocol can no longer
	// accept, by expires_at or max_lifetime. Being revoked is NOT a reason to delete
	// a row: a revoked row is the replay-detection signal, and reaping it early means
	// a replay is refused but never detected and its live family never contained
	// (#128, RFC 9700 Section 4.14.2).
	DeleteExpiredRefreshTokens(ctx context.Context, tx *sql.Tx) error

	CreateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *models.UserSessionClient) error
	UpdateUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClient *models.UserSessionClient) error
	GetUserSessionClientById(ctx context.Context, tx *sql.Tx, userSessionClientId int64) (*models.UserSessionClient, error)
	GetUserSessionsClientByIds(ctx context.Context, tx *sql.Tx, userSessionClientIds []int64) ([]models.UserSessionClient, error)
	GetUserSessionClientsByUserSessionId(ctx context.Context, tx *sql.Tx, userSessionId int64) ([]models.UserSessionClient, error)
	GetUserSessionClientsByUserSessionIds(ctx context.Context, tx *sql.Tx, userSessionIds []int64) ([]models.UserSessionClient, error)
	DeleteUserSessionClient(ctx context.Context, tx *sql.Tx, userSessionClientId int64) error
	UserSessionClientsLoadClients(ctx context.Context, tx *sql.Tx, userSessionClients []models.UserSessionClient) error
}

// ErrUniqueViolation is the sentinel a write reports when the engine refused it because a unique
// index already holds that value, and it is what a caller above the data layer matches with
// errors.Is. Its documentation is on the declaration.
//
// It is an alias rather than the declaration because of the import direction: commondb is where the
// translation happens and this package is what imports commondb, not the other way round. Callers
// spell it data.ErrUniqueViolation, which is the name they already have an import for (#279).
var ErrUniqueViolation = commondb.ErrUniqueViolation
