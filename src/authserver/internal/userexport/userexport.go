// Package userexport builds the document that holds what the auth server holds about one user
// (#781), but for the attributes no app receives (#782 decision 8): what an operator hands a person
// who asked for a copy of their data. The admin API's export route answers it, and the account
// API's own copy (#782) calls the same builder, so the document is one thing whoever asks.
package userexport

import (
	"cmp"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/hashutil"
)

// FormatVersion is the document's format version. It goes up only for a change that breaks a
// reader; a field added to a reused entry is additive and leaves it (#781 decision 3).
const FormatVersion = 1

// Parts is what the admin API reads about the user beside the profile, each entry as the matching
// read answers it: GET /api/v1/admin/users/{id}/attributes, a group as /groups answers it with the
// group's own attribute and permission reads, /permissions, /consents, the live sessions of
// /sessions, and /legal-document-acceptances. ProfilePicture is the stored picture, nil when the
// user has none. RefreshTokens is every refresh token row the auth server holds for the user, with
// what its entry is read from. AuditEvents is every audit row about the user or made by them, as
// stored. The reads promise no order; Build gives every list one.
type Parts struct {
	Attributes               []api.UserAttributeResponse
	Groups                   []api.UserExportGroupResponse
	Permissions              []api.PermissionResponse
	Consents                 []api.UserConsentResponse
	Sessions                 []api.UserSessionDetailResponse
	LegalDocumentAcceptances []api.LegalDocumentAcceptanceResponse
	ProfilePicture           *record.UserProfilePicture
	RefreshTokens            []RefreshToken
	AuditEvents              []record.AuditLog
}

// RefreshToken is one refresh token row of the user's with what its entry is read from: Code is
// the authorization code a code-flow token came from, nil for a password-grant token, which has
// none, or when the code is gone; Client is the token's client, the code's for a code-flow token
// and the row's own for a password-grant one, nil when it is gone; FamilyRevoked says the token's
// rotation family is recorded as revoked.
type RefreshToken struct {
	Row           *record.RefreshToken
	Code          *record.Code
	Client        *record.Client
	FamilyRevoked bool
}

// Build is the document for user and what the admin API reads about them, exported at exportedAt
// by the auth server whose issuer is issuer.
//
// Each part is the entry the matching admin API read answers, inside the versioned wrapper, so
// nothing secret reaches it: the user is GET /api/v1/admin/users/{id}'s projection, which carries
// no password hash, two-factor secret or pending code, and no mapping copies the encrypted secret
// of a client loaded onto a consent or a session. An attribute of the user's or of a group's whose
// include-in-ID-token and include-in-access-token flags are both off reaches no app: it is an
// administrators' own note about the person, and is left out (#782 decision 8); groups and
// permissions are kept in full. Every list is in id order, oldest first, a
// group's attributes and permissions too, so two exports of one person compare line by line
// (#781 decision 3). Every list is [] rather than null when it is empty, so a reader never tells
// "none" from "not read". The audit events name no other person who acted on the user (decision
// 2); a row that cannot be read well enough to strip them is an error, and no document.
func Build(user *record.User, parts Parts, issuer string, exportedAt time.Time) (api.UserExportResponse, error) {
	events, err := auditEvents(user.ID, parts.AuditEvents)
	if err != nil {
		return api.UserExportResponse{}, err
	}

	// inIDOrder's copy is the one DeleteFunc changes, so the parts are left as they were.
	attributes := slices.DeleteFunc(inIDOrder(parts.Attributes, func(a api.UserAttributeResponse) int64 { return a.ID }),
		func(a api.UserAttributeResponse) bool { return !a.IncludeInIDToken && !a.IncludeInAccessToken })
	groups := inIDOrder(parts.Groups, func(g api.UserExportGroupResponse) int64 { return g.ID })
	for i := range groups {
		groups[i].Attributes = slices.DeleteFunc(
			inIDOrder(groups[i].Attributes, func(a api.GroupAttributeResponse) int64 { return a.ID }),
			func(a api.GroupAttributeResponse) bool { return !a.IncludeInIDToken && !a.IncludeInAccessToken })
		groups[i].Permissions = inIDOrder(groups[i].Permissions, permissionID)
	}

	var picture *api.UserExportProfilePictureResponse
	if parts.ProfilePicture != nil {
		picture = &api.UserExportProfilePictureResponse{
			ContentType: parts.ProfilePicture.ContentType,
			Data:        parts.ProfilePicture.Picture,
		}
	}

	return api.UserExportResponse{
		FormatVersion: FormatVersion,
		ExportedAt:    exportedAt.UTC(),
		Issuer:        issuer,
		Identifiers: api.UserExportIdentifiersResponse{
			ID:      user.ID,
			Subject: user.Subject,
			Email:   user.Email,
			// The digest an audit entry about the address records: the address is stored in
			// lowercase and trimmed, which is the form the digest is taken of.
			EmailDigest: hashutil.HashString(user.Email),
		},
		User:          *apimapping.ToUserResponse(user),
		Attributes:    attributes,
		Groups:        groups,
		Permissions:   inIDOrder(parts.Permissions, permissionID),
		Consents:      inIDOrder(parts.Consents, func(c api.UserConsentResponse) int64 { return c.ID }),
		Sessions:      inIDOrder(parts.Sessions, func(s api.UserSessionDetailResponse) int64 { return s.ID }),
		RefreshTokens: refreshTokens(parts.RefreshTokens),
		LegalDocumentAcceptances: inIDOrder(parts.LegalDocumentAcceptances,
			func(a api.LegalDocumentAcceptanceResponse) int64 { return a.ID }),
		ProfilePicture: picture,
		AuditEvents:    events,
	}, nil
}

func permissionID(p api.PermissionResponse) int64 { return p.ID }

// refreshTokens is each token's entry, in the rows' id order (#781 decision 4). A token is revoked
// when any of the three marks that stop it is set: its own row, its authorization code's, or its
// rotation family's, so the document never calls a stopped token active. A code-flow token's
// sign-in, its address, browser and time, is its code's. A password-grant token has no code, so its
// address and browser are empty and its sign-in time is its own row's, which rotation copies from
// the parent, the moment the password was checked.
func refreshTokens(tokens []RefreshToken) []api.UserExportRefreshTokenResponse {
	sorted := inIDOrder(tokens, func(t RefreshToken) int64 { return t.Row.ID })
	entries := make([]api.UserExportRefreshTokenResponse, 0, len(sorted))
	for _, token := range sorted {
		row := token.Row
		entry := api.UserExportRefreshTokenResponse{
			Scope:             row.Scope,
			Type:              row.RefreshTokenType,
			IssuedAt:          nullTime(row.IssuedAt),
			ExpiresAt:         nullTime(row.ExpiresAt),
			MaxLifetime:       nullTime(row.MaxLifetime),
			SessionIdentifier: row.SessionIdentifier,
			JTI:               row.RefreshTokenJTI,
			Revoked:           row.Revoked || token.FamilyRevoked,
		}
		if token.Client != nil {
			entry.ClientIdentifier = token.Client.ClientIdentifier
			entry.ClientName, entry.ClientNameUnverified = token.Client.NameForUsers()
		}
		if row.CodeID.Valid {
			if code := token.Code; code != nil {
				entry.Revoked = entry.Revoked || code.Revoked
				entry.IPAddress = code.IPAddress
				entry.UserAgent = code.UserAgent
				if !code.AuthenticatedAt.IsZero() {
					authenticatedAt := code.AuthenticatedAt
					entry.AuthenticatedAt = &authenticatedAt
				}
			}
		} else {
			entry.AuthenticatedAt = nullTime(row.AuthenticatedAt)
		}
		entries = append(entries, entry)
	}
	return entries
}

// auditEvents is each audit row's entry, in id order, without the other people who acted on the
// user (#781 decision 2). A row that another user's token made, an administrator's on the admin
// API, says an administrator acted: its logged_in_user_id and its details' logged_in_user, the
// administrator's subject, are left out. A sign-in on a browser that still carried another user's
// session leaves out previous_user_id, that user. A row the user's own token made keeps whom it
// acted on; a row no user's token made keeps its actor, a client or the recover command, neither a
// person. Every other byte of a row is as stored.
func auditEvents(userID int64, rows []record.AuditLog) ([]api.UserExportAuditEventResponse, error) {
	sorted := inIDOrder(rows, func(row record.AuditLog) int64 { return row.ID })
	entries := make([]api.UserExportAuditEventResponse, 0, len(sorted))
	for i := range sorted {
		row := &sorted[i]
		entry := api.UserExportAuditEventResponse{AuditLogResponse: apimapping.ToAuditLogResponse(row)}

		var hidden []string
		if row.LoggedInUserID.Valid && row.LoggedInUserID.Int64 != userID {
			entry.ActedByAdministrator = true
			entry.LoggedInUserID = nil
			hidden = append(hidden, "logged_in_user")
		}
		if row.AuditEvent == audit.EventCrossUserSessionReplaced {
			hidden = append(hidden, "previous_user_id")
		}
		if len(hidden) > 0 {
			details, err := withoutKeys(row.Details, hidden)
			if err != nil {
				return nil, errs.Wrapf(err, "unable to strip audit log %d for the export", row.ID)
			}
			entry.Details = details
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// withoutKeys is a JSON object's text without the keys given. Each other value is copied as it is
// written, so a number past what a float64 holds keeps every digit; the keys come out sorted, as
// every audit row's details are written. Text that is not a JSON object is an error, since the
// keys could not be told apart in it.
func withoutKeys(object string, keys []string) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(object), &fields); err != nil {
		return "", errs.Wrap(err, "the details are not a JSON object")
	}
	if fields == nil {
		return "", errs.New("the details are not a JSON object")
	}
	for _, key := range keys {
		delete(fields, key)
	}
	stripped, err := json.Marshal(fields)
	if err != nil {
		return "", errs.Wrap(err, "unable to encode the stripped details")
	}
	return string(stripped), nil
}

// nullTime is a stored instant, or nil where none is stored.
func nullTime(stored sql.NullTime) *time.Time {
	if !stored.Valid {
		return nil
	}
	instant := stored.Time
	return &instant
}

// inIDOrder is a copy of entries sorted by id, ascending, and never nil.
func inIDOrder[T any](entries []T, id func(T) int64) []T {
	sorted := make([]T, len(entries))
	copy(sorted, entries)
	slices.SortStableFunc(sorted, func(a, b T) int { return cmp.Compare(id(a), id(b)) })
	return sorted
}

// FileName is the name the document is saved under: user-<id>-<date>.json, the date being
// exportedAt's in UTC, as in user-42-2026-11-05.json. The id keeps the email address out of
// download folders and mail attachments (#781 decision 6).
func FileName(userID int64, exportedAt time.Time) string {
	return fmt.Sprintf("user-%d-%s.json", userID, exportedAt.UTC().Format(time.DateOnly))
}
