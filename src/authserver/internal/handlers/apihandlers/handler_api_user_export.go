package apihandlers

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/reqctx"
	"github.com/leodip/goiabada/authserver/internal/userexport"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
)

// The export of one user's data (#781): one JSON document, built whole by userexport.Build, which
// leaves out the attributes no app receives (#782 decision 8), named for download and sent as every admin API answer is, buffered, so any
// failure is a clean 500 (decision 5). Only a token reaching both the users and the settings
// domain gets here, since the document holds the user's audit events (decision 1); routes.go
// mounts that check.

// userExportWriteTimeout is how long the export's answer has to reach the caller, in place of the
// listener's 60 seconds: 30,000 audit events are 12.6 MB as JSON, and a slow connection still
// finishes (decision 5).
const userExportWriteTimeout = 5 * time.Minute

// userExportDatabase is what the export reads: the user, and each part through the reads the admin
// API answers it with, so a part holds what the matching endpoint answers. It embeds the session
// row builder's port, the member count's and the legal document acceptances'.
type userExportDatabase interface {
	sessionDetailsDatabase
	groupMemberCounter
	legaldocuments.AcceptedDatabase

	GetUserById(ctx context.Context, tx *sql.Tx, userId int64) (*record.User, error)
	GetUserAttributesByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserAttribute, error)
	UserLoadGroups(ctx context.Context, tx *sql.Tx, user *record.User) error
	GetGroupAttributesByGroupId(ctx context.Context, tx *sql.Tx, groupId int64) ([]record.GroupAttribute, error)
	GroupLoadPermissions(ctx context.Context, tx *sql.Tx, group *record.Group) error
	UserLoadPermissions(ctx context.Context, tx *sql.Tx, user *record.User) error
	GetResourceById(ctx context.Context, tx *sql.Tx, resourceId int64) (*record.Resource, error)
	GetConsentsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserConsent, error)
	UserConsentsLoadClients(ctx context.Context, tx *sql.Tx, userConsents []record.UserConsent) error
	GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserSession, error)
	UserSessionsLoadClients(ctx context.Context, tx *sql.Tx, userSessions []record.UserSession) error
	GetUserProfilePictureByUserId(ctx context.Context, tx *sql.Tx, userId int64) (*record.UserProfilePicture, error)
	GetRefreshTokensByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]*record.RefreshToken, error)
	GetCodeById(ctx context.Context, tx *sql.Tx, codeId int64) (*record.Code, error)
	IsRefreshTokenFamilyRevoked(ctx context.Context, tx *sql.Tx, firstRefreshTokenJti string) (bool, error)
	GetAuditLogsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.AuditLog, error)
}

// HandleUserExportGet - GET /api/v1/admin/users/{id}/export
//
// baseURL is the auth server's own, which a legal document acceptance's address is built from.
func HandleUserExportGet(database userExportDatabase, auditLogger AuditLogger, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		extendWriteDeadline(w, r, userExportWriteTimeout)

		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSONError(w, "Invalid user ID format", "VALIDATION_ERROR", http.StatusBadRequest)
			return
		}

		settings, ok := reqctx.SettingsFrom(r.Context())
		if !ok {
			writeInternalServerError(w, r, reqctx.ErrNoSettings)
			return
		}

		user, err := database.GetUserById(r.Context(), nil, id)
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "database error getting user by ID for the export"), "user_id", id)
			return
		}
		if user == nil {
			writeJSONError(w, "User not found", "NOT_FOUND", http.StatusNotFound)
			return
		}

		document, err := buildUserExport(r.Context(), database, user, settings, baseURL, time.Now())
		if err != nil {
			writeInternalServerError(w, r, err, "user_id", user.Id)
			return
		}
		if !writeUserExport(w, r, document) {
			return
		}

		// Once the answer has been sent, whether or not the caller received all of it: the data
		// has left the server either way (decision 8).
		auditLogger.Log(r.Context(), audit.EventExportedUserData, map[string]interface{}{
			"user_id":        user.Id,
			"logged_in_user": callerSubject(r),
		})
	}
}

// buildUserExport reads every part of the user's document and builds it, or answers the first read
// that failed, so the document is never sent with a part missing (decision 5). It is the one
// builder of the document, whoever asks: the admin API's export calls it, and the account API's
// own copy (#782) is to call it too.
//
// Each part is read as the matching admin API endpoint reads it: the live sessions by the rule
// GET /users/{id}/sessions applies, and a legal document acceptance with its address built from
// baseURL. No session is marked current, the caller's own included, since the document is the
// same whoever asks. The audit events are every row about the user or made by them, read whole in
// id order, which Build strips of the other people who acted on the user (decision 2).
func buildUserExport(ctx context.Context, database userExportDatabase, user *record.User,
	settings *record.Settings, baseURL string, exportedAt time.Time) (api.UserExportResponse, error) {

	attributes, err := database.GetUserAttributesByUserId(ctx, nil, user.Id)
	if err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to read the user's attributes for the export")
	}

	resources := permissionResources{database: database, byId: map[int64]*record.Resource{}}
	groups, err := readUserExportGroups(ctx, database, user, &resources)
	if err != nil {
		return api.UserExportResponse{}, err
	}

	if err = database.UserLoadPermissions(ctx, nil, user); err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to read the user's permissions for the export")
	}
	if err = resources.load(ctx, user.Permissions); err != nil {
		return api.UserExportResponse{}, err
	}

	consents, err := database.GetConsentsByUserId(ctx, nil, user.Id)
	if err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to read the user's consents for the export")
	}
	if err = database.UserConsentsLoadClients(ctx, nil, consents); err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to read the clients of the user's consents for the export")
	}

	userSessions, err := database.GetUserSessionsByUserId(ctx, nil, user.Id)
	if err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to read the user's sessions for the export")
	}
	if err = database.UserSessionsLoadClients(ctx, nil, userSessions); err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to read the clients of the user's sessions for the export")
	}
	// A session's apps in the order of their association rows, which the read leaves unordered
	// and the mapping drops the ids of (decision 3).
	for i := range userSessions {
		slices.SortStableFunc(userSessions[i].Clients, func(a, b record.UserSessionClient) int { return cmp.Compare(a.Id, b.Id) })
	}
	sessions, err := buildSessionDetails(ctx, database, userSessions, settings, "")
	if err != nil {
		return api.UserExportResponse{}, err
	}

	accepted, err := legaldocuments.AcceptedBy(ctx, database, user.Id)
	if err != nil {
		return api.UserExportResponse{}, err
	}
	acceptances := make([]api.LegalDocumentAcceptanceResponse, 0, len(accepted))
	for i := range accepted {
		a := &accepted[i]
		acceptances = append(acceptances, apimapping.ToLegalDocumentAcceptanceResponse(&a.Acceptance, &a.Document, &a.Version, baseURL))
	}

	picture, err := database.GetUserProfilePictureByUserId(ctx, nil, user.Id)
	if err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to read the user's profile picture for the export")
	}

	refreshTokens, err := readUserExportRefreshTokens(ctx, database, user.Id)
	if err != nil {
		return api.UserExportResponse{}, err
	}

	auditLogs, err := database.GetAuditLogsByUserId(ctx, nil, user.Id)
	if err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to read the user's audit events for the export")
	}

	document, err := userexport.Build(user, userexport.Parts{
		Attributes:               apimapping.ToUserAttributeResponses(attributes),
		Groups:                   groups,
		Permissions:              apimapping.ToPermissionResponses(user.Permissions),
		Consents:                 apimapping.ToUserConsentResponses(consents),
		Sessions:                 sessions,
		LegalDocumentAcceptances: acceptances,
		ProfilePicture:           picture,
		RefreshTokens:            refreshTokens,
		AuditEvents:              auditLogs,
	}, settings.Issuer, exportedAt)
	if err != nil {
		return api.UserExportResponse{}, errs.Wrap(err, "unable to build the user export")
	}
	return document, nil
}

// readUserExportGroups is each group the user is a member of, as GET /users/{id}/groups answers it,
// with the attributes and permissions the user gets through it, as the group's own
// /attributes and /permissions answer them.
func readUserExportGroups(ctx context.Context, database userExportDatabase, user *record.User,
	resources *permissionResources) ([]api.UserExportGroupResponse, error) {

	if err := database.UserLoadGroups(ctx, nil, user); err != nil {
		return nil, errs.Wrap(err, "unable to read the user's groups for the export")
	}
	memberCounts, err := countGroupMembers(ctx, database, user.Groups)
	if err != nil {
		return nil, err
	}

	groups := make([]api.UserExportGroupResponse, 0, len(user.Groups))
	for i := range user.Groups {
		group := &user.Groups[i]
		attributes, err := database.GetGroupAttributesByGroupId(ctx, nil, group.Id)
		if err != nil {
			return nil, errs.Wrapf(err, "unable to read the attributes of group %d for the export", group.Id)
		}
		if err := database.GroupLoadPermissions(ctx, nil, group); err != nil {
			return nil, errs.Wrapf(err, "unable to read the permissions of group %d for the export", group.Id)
		}
		if err := resources.load(ctx, group.Permissions); err != nil {
			return nil, err
		}
		groups = append(groups, api.UserExportGroupResponse{
			GroupResponse: *apimapping.ToGroupResponse(group, memberCounts[group.Id]),
			Attributes:    apimapping.ToGroupAttributeResponses(attributes),
			Permissions:   apimapping.ToPermissionResponses(group.Permissions),
		})
	}
	return groups, nil
}

// readUserExportRefreshTokens is every refresh token row the auth server holds for the user, through
// its authorization code for the code flow and directly for the password grant, rotated-out and
// revoked rows included, each with its code, its client and whether its family is recorded as
// revoked (#781 decision 4). A grant rotated every few minutes keeps thousands of rows of one code
// and one family, so each code and family is read once, and the clients in one read.
func readUserExportRefreshTokens(ctx context.Context, database userExportDatabase, userId int64) ([]userexport.RefreshToken, error) {
	rows, err := database.GetRefreshTokensByUserId(ctx, nil, userId)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the user's refresh tokens for the export")
	}

	codes := map[int64]*record.Code{}
	families := map[string]bool{}
	clientIds := []int64{}
	tokens := make([]userexport.RefreshToken, 0, len(rows))
	for _, row := range rows {
		token := userexport.RefreshToken{Row: row}
		if row.CodeId.Valid {
			code, read := codes[row.CodeId.Int64]
			if !read {
				code, err = database.GetCodeById(ctx, nil, row.CodeId.Int64)
				if err != nil {
					return nil, errs.Wrapf(err, "unable to read code %d for the export", row.CodeId.Int64)
				}
				codes[row.CodeId.Int64] = code
			}
			token.Code = code
		}
		if clientId, ok := refreshTokenClientId(token); ok && !slices.Contains(clientIds, clientId) {
			clientIds = append(clientIds, clientId)
		}

		// Every row records the first jti of its family; one that does not belongs to no family
		// a record could name.
		if first := row.FirstRefreshTokenJti; first != "" {
			revoked, read := families[first]
			if !read {
				revoked, err = database.IsRefreshTokenFamilyRevoked(ctx, nil, first)
				if err != nil {
					return nil, errs.Wrap(err, "unable to read a refresh token family's revocation for the export")
				}
				families[first] = revoked
			}
			token.FamilyRevoked = revoked
		}
		tokens = append(tokens, token)
	}

	clients, err := database.GetClientsByIds(ctx, nil, clientIds)
	if err != nil {
		return nil, errs.Wrap(err, "unable to read the clients of the user's refresh tokens for the export")
	}
	byId := make(map[int64]*record.Client, len(clients))
	for i := range clients {
		byId[clients[i].Id] = &clients[i]
	}
	for i := range tokens {
		if clientId, ok := refreshTokenClientId(tokens[i]); ok {
			tokens[i].Client = byId[clientId]
		}
	}
	return tokens, nil
}

// refreshTokenClientId is the token's client: its code's for a code-flow token, its row's own for a
// password-grant one. ok is false when there is none to read, as for a code that is gone.
func refreshTokenClientId(token userexport.RefreshToken) (clientId int64, ok bool) {
	if token.Row.CodeId.Valid {
		if token.Code == nil {
			return 0, false
		}
		return token.Code.ClientId, true
	}
	return token.Row.ClientId.Int64, token.Row.ClientId.Valid
}

// permissionResources fills in each permission's resource, as the user and group permission reads
// do, reading each resource once however many permissions name it.
type permissionResources struct {
	database userExportDatabase
	byId     map[int64]*record.Resource
}

func (p *permissionResources) load(ctx context.Context, permissions []record.Permission) error {
	for i := range permissions {
		resourceId := permissions[i].ResourceId
		resource, read := p.byId[resourceId]
		if !read {
			var err error
			resource, err = p.database.GetResourceById(ctx, nil, resourceId)
			if err != nil {
				return errs.Wrapf(err, "unable to read resource %d for the export", resourceId)
			}
			p.byId[resourceId] = resource
		}
		if resource != nil {
			permissions[i].Resource = *resource
		}
	}
	return nil
}

// writeUserExport answers the document as a file to save: JSON, gzip-compressed when the request
// accepts gzip, named user-<id>-<date>.json. The whole body is encoded and compressed before the
// header, so a failure is the API's 500 rather than a cut file. ok false means a 500 was answered.
func writeUserExport(w http.ResponseWriter, r *http.Request, document api.UserExportResponse) (ok bool) {
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(document); err != nil {
		writeInternalServerError(w, r, errs.Wrap(err, "unable to encode the user export"), "user_id", document.Identifiers.Id)
		return false
	}

	header := w.Header()
	header.Add("Vary", "Accept-Encoding")
	if acceptsGzip(r) {
		var compressed bytes.Buffer
		zw := gzip.NewWriter(&compressed)
		_, err := zw.Write(body.Bytes())
		if err == nil {
			err = zw.Close()
		}
		if err != nil {
			writeInternalServerError(w, r, errs.Wrap(err, "unable to compress the user export"), "user_id", document.Identifiers.Id)
			return false
		}
		body = compressed
		header.Set("Content-Encoding", "gzip")
	}

	header.Set("Content-Type", "application/json")
	header.Set("Content-Disposition", `attachment; filename="`+userexport.FileName(document.Identifiers.Id, document.ExportedAt)+`"`)
	header.Set("Content-Length", strconv.Itoa(body.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body.Bytes())
	return true
}

// extendWriteDeadline gives this answer until timeout from now to be written, past the listener's
// write timeout. A writer that takes no deadline, as a test's recorder does, keeps the listener's;
// any other failure is logged, and the answer still goes out under the listener's bound.
func extendWriteDeadline(w http.ResponseWriter, r *http.Request, timeout time.Duration) {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		slog.WarnContext(r.Context(), "unable to extend the write deadline", "error", err)
	}
}

// acceptsGzip reports whether the request's Accept-Encoding allows a gzip-coded answer, read as RFC
// 9110 section 12.5.3 defines the field: each member is a coding with an optional weight, a weight
// of 0 makes that coding not acceptable, and "*" stands for any coding the field does not name.
// Section 8.4.1.3 has a recipient treat x-gzip as gzip. No field, or one naming neither gzip nor
// "*", leaves gzip out: an answer is sent plain unless the caller asked for gzip. A weight that is
// not a number is read as 0, so a malformed field never earns a compressed answer.
func acceptsGzip(r *http.Request) bool {
	gzipWeight, anyWeight := -1.0, -1.0
	for _, line := range r.Header.Values("Accept-Encoding") {
		for _, member := range strings.Split(line, ",") {
			coding, parameters, _ := strings.Cut(member, ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			weight := 1.0
			for _, parameter := range strings.Split(parameters, ";") {
				name, value, found := strings.Cut(parameter, "=")
				if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
					continue
				}
				parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil {
					parsed = 0
				}
				weight = parsed
			}
			switch coding {
			case "gzip", "x-gzip":
				gzipWeight = max(gzipWeight, weight)
			case "*":
				anyWeight = max(anyWeight, weight)
			}
		}
	}
	if gzipWeight >= 0 {
		return gzipWeight > 0
	}
	return anyWeight > 0
}
