package apihandlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/i18n"
)

// maxGroupIdsPerRequest bounds how many group ids one request body may name.
//
// The list is validated by reading every group it names back from the database, and a list longer
// than one statement can bind is read in several of them (commondb's forEachIdBatch), so without a
// bound a caller holding manage-users can post a million ids and buy a thousand statements reading
// ids that cannot exist. The number is one statement's worth, which is the largest list that
// validation reads in one go, and it is far above any real request: a user can hold at most as
// many groups as the deployment has defined (#373).
//
// This bounds one array, not the request. How large a body the server reads before anything looks
// at it is #205's axis and wants one answer for every endpoint rather than one for this one.
//
// The number is a policy and not a schema rule, and it is worth being plain about what it costs:
// nothing limits how many groups a deployment defines, and a user can be put into more than a
// thousand of them one at a time through POST /api/v1/admin/groups/{id}/members. Such a user's
// membership cannot then be replaced through this endpoint, because even re-sending the set they
// already hold names more ids than this allows -- only a smaller set is accepted. That state is
// reachable rather than impossible, and the cap is a deliberate refusal to serve it rather than an
// oversight; it is published as maxItems on UpdateUserGroupsRequest so a caller meets it in the
// contract rather than at runtime.
const maxGroupIdsPerRequest = 1000

// userGroupsDatabase is what the user group membership endpoints need: the user, the groups, and
// the rows that join them, and what the administrative policy reads to judge a save.
type userGroupsDatabase interface {
	userTargetPolicyDatabase
	userGroupsPolicyDatabase
	lastAdministratorDatabase
	CountGroupMembers(ctx context.Context, tx *sql.Tx, groupId int64) (int, error)
	CreateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *record.UserGroup) error
	DeleteUserGroup(ctx context.Context, tx *sql.Tx, userGroupId int64) error
	GetGroupsByIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.Group, error)
	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *record.User) error
}

func HandleUserGroupsGet(
	database userGroupsDatabase,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		user, err := database.GetUserById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for groups"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		err = database.UserLoadGroups(r.Context(), nil, user)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error loading user groups"), "user_id", user.Id)
			return
		}

		memberCounts, err := countGroupMembers(r.Context(), database, user.Groups)
		if err != nil {
			writeInternalServerError(w, r, err, "user_id", user.Id)
			return
		}

		response := api.GetUserGroupsResponse{
			User:   *apimapping.ToUserResponse(user),
			Groups: apimapping.ToGroupResponses(user.Groups, memberCounts),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}

func HandleUserGroupsPut(
	database userGroupsDatabase,
	auditLogger AuditLogger,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		idStr := chi.URLParam(r, "id")
		if len(idStr) == 0 {
			writeJSONError(w, "User ID is required", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		var request api.UpdateUserGroupsRequest
		err = json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			writeJSONError(w, "Invalid request body", "INVALID_REQUEST_BODY", http.StatusBadRequest)
			return
		}

		// Refused on the body alone, before any query: the ids are not read one at a time, so the
		// cost of an oversized array is paid by the validation below rather than by the caller.
		if len(request.GroupIds) > maxGroupIdsPerRequest {
			writeJSONError(w, "Too many group ids", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// The set as the caller loaded it, required as it is on every list save: absent or null
		// decodes to nil and is refused, [] means the caller read no memberships (#428).
		if request.ExpectedGroupIds == nil {
			writeJSONError(w, "expectedGroupIds is required: send the group ids as you last read them, or [] if there were none.", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		// Deduplicated as the three permission saves are. A repeated id was answered as a group
		// that does not exist, since the lookup below returns each group once (#428).
		wanted := firstOccurrences(request.GroupIds)

		user, err := database.GetUserById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for groups"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		// Validate all requested groups exist
		if len(wanted) > 0 {
			groups, getGroupsErr := database.GetGroupsByIds(r.Context(), nil, wanted)
			if getGroupsErr != nil {
				writeInternalServerError(w, r, errs.Wrap(getGroupsErr, "database error getting groups by IDs for validation"), "group_ids", wanted, "user_id", user.Id)
				return
			}
			if len(groups) != len(wanted) {
				// i18n surface: C — admin/account API.
				writeValidationError(w, r, i18n.NewLocalizedError(i18n.ErrCodeUserGroupsNotFound, nil))
				return
			}
		}

		// The grant ceiling, after the request's 400 and 404 answers and before the transaction:
		// only authserver:manage moves a user into or out of a group holding an administrative
		// permission (#402).
		if !userGroupsCeilingAllows(w, r, database, auditLogger, user.Id, wanted, request.ExpectedGroupIds) {
			return
		}

		// The grant ceiling judged what the save changes; this judges whom it changes (#402 decision 1).
		if !userTargetCeilingAllows(w, r, database, auditLogger, user.Id) {
			return
		}

		membershipKey := func(ug record.UserGroup) int64 { return ug.GroupId }
		membershipId := func(ug record.UserGroup) int64 { return ug.Id }

		// One transaction, so a failure part way through commits nothing and the 500 is true, where
		// the autocommitted writes this replaced could leave a membership added, and audited, under
		// a 500 (#406's shape, on the one list save no issue named). No row lock, as for every list
		// save: two overlapping saves of one user's groups merge item by item, and users_groups has
		// no unique key, so a membership the two both add is stored twice, which is harmless and
		// collapsed by the next save's replaceSet. Opened through RunInTransaction, so a deadlock
		// victim is rerun whole (#301). The body is safe to rerun: the plan is recomputed from the
		// rows read on the transaction on every attempt, what is audited is assigned only by an
		// attempt that reached its end, and nothing is written to the response inside it (#428).
		//
		// What the groups added and removed hold is read on the transaction too, after the writes,
		// so the administrative_permission_changed records are written from what the committed
		// attempt saw; that read failing undoes the save, so a membership is never committed
		// without the records it owes (#402).
		//
		// Leaving a group that gives manage can remove the last administrator, so the transaction
		// takes the administrators' lock first and the save is refused, rolled back, when it would
		// leave no enabled user holding manage (#402 decisions 10 and 11).
		var added, removed []int64
		var joined, left []administrativeGroup
		err = database.RunInTransaction(r.Context(), func(tx *sql.Tx) error {
			administrators, lockErr := lockAdministrators(r.Context(), database, tx)
			if lockErr != nil {
				return lockErr
			}

			stored, loadErr := database.GetUserGroupsByUserId(r.Context(), tx, user.Id)
			if loadErr != nil {
				return errs.Wrap(loadErr, "database error loading user groups before update")
			}
			if !sameSet(stored, membershipKey, request.ExpectedGroupIds) {
				return errListChanged
			}

			insert, remove := replaceSet(stored, membershipKey, membershipId, wanted)
			attemptRemoved := revokedKeys(stored, membershipKey, wanted)
			leavesManage, guardReadErr := administrators.groupsGiveManage(r.Context(), attemptRemoved)
			if guardReadErr != nil {
				return guardReadErr
			}
			if decideErr := administrators.decide(r.Context(), leavesManage); decideErr != nil {
				return decideErr
			}

			for _, rowId := range remove {
				if deleteErr := database.DeleteUserGroup(r.Context(), tx, rowId); deleteErr != nil {
					return errs.Wrapf(deleteErr, "database error deleting user group membership %d", rowId)
				}
			}
			for _, groupId := range insert {
				if createErr := database.CreateUserGroup(r.Context(), tx, &record.UserGroup{
					UserId:  user.Id,
					GroupId: groupId,
				}); createErr != nil {
					return errs.Wrapf(createErr, "database error adding the user to group %d", groupId)
				}
			}
			if guardErr := administrators.leavesAnAdministrator(r.Context()); guardErr != nil {
				return guardErr
			}
			var attemptJoined, attemptLeft []administrativeGroup
			if changed := append(append([]int64{}, insert...), attemptRemoved...); len(changed) > 0 {
				groups, readErr := administrativeGroups(r.Context(), database, tx, changed)
				if readErr != nil {
					return readErr
				}
				for _, group := range groups {
					if slices.Contains(insert, group.id) {
						attemptJoined = append(attemptJoined, group)
					} else {
						attemptLeft = append(attemptLeft, group)
					}
				}
			}
			added, removed = insert, attemptRemoved
			joined, left = attemptJoined, attemptLeft
			return nil
		})
		if errors.Is(err, errLastAdministrator) {
			writeLastAdministrator(w)
			return
		}
		if err != nil {
			writeListSaveFailure(w, r, err, "user_id", user.Id)
			return
		}

		// Audit, once the save has committed: one event per membership added and per membership
		// removed, from the plan of the attempt that committed (#428).
		loggedInSubject := callerSubject(r)
		for _, groupId := range added {
			auditLogger.Log(r.Context(), audit.EventUserAddedToGroup, map[string]interface{}{
				"user_id":        user.Id,
				"group_id":       groupId,
				"logged_in_user": loggedInSubject,
			})
		}
		for _, groupId := range removed {
			auditLogger.Log(r.Context(), audit.EventUserRemovedFromGroup, map[string]interface{}{
				"user_id":        user.Id,
				"group_id":       groupId,
				"logged_in_user": loggedInSubject,
			})
		}
		recordMembershipChanges(r, auditLogger, user.Id, changeGranted, joined)
		recordMembershipChanges(r, auditLogger, user.Id, changeRevoked, left)

		// Reload user groups to get updated state
		err = database.UserLoadGroups(r.Context(), nil, user)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error reloading user groups after update"), "user_id", user.Id)
			return
		}

		// The membership change above is already written and audited, so a failure here answers
		// 500 for a request whose effect stands; a retry of the same set writes nothing new.
		memberCounts, err := countGroupMembers(r.Context(), database, user.Groups)
		if err != nil {
			writeInternalServerError(w, r, err, "user_id", user.Id)
			return
		}

		response := api.GetUserGroupsResponse{
			User:   *apimapping.ToUserResponse(user),
			Groups: apimapping.ToGroupResponses(user.Groups, memberCounts),
		}

		writeJSON(w, r, http.StatusOK, response)
	}
}
