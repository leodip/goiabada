// Package userexport builds the document that holds everything the auth server holds about one
// user (#781): what an operator hands a person who asked for a copy of their data. The admin API's
// export route answers it, and the account API's own copy (#782) calls the same builder, so the
// document is one thing whoever asks.
package userexport

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/hashutil"
)

// FormatVersion is the document's format version. It goes up only for a change that breaks a
// reader; a field added to a reused entry is additive and leaves it (#781 decision 3).
const FormatVersion = 1

// Parts is what the admin API reads about the user beside the profile, each entry as the matching
// read answers it: GET /api/v1/admin/users/{id}/attributes, a group as /groups answers it with the
// group's own attribute and permission reads, /permissions, /consents, the live sessions of
// /sessions, and /legal-document-acceptances. ProfilePicture is the stored picture, nil when the
// user has none. The reads promise no order; Build gives every list one.
type Parts struct {
	Attributes               []api.UserAttributeResponse
	Groups                   []api.UserExportGroupResponse
	Permissions              []api.PermissionResponse
	Consents                 []api.UserConsentResponse
	Sessions                 []api.UserSessionDetailResponse
	LegalDocumentAcceptances []api.LegalDocumentAcceptanceResponse
	ProfilePicture           *record.UserProfilePicture
}

// Build is the document for user and what the admin API reads about them, exported at exportedAt
// by the auth server whose issuer is issuer.
//
// Each part is the entry the matching admin API read answers, inside the versioned wrapper, so
// nothing secret reaches it: the user is GET /api/v1/admin/users/{id}'s projection, which carries
// no password hash, two-factor secret or pending code, and no mapping copies the encrypted secret
// of a client loaded onto a consent or a session. Every list is in id order, oldest first, a
// group's attributes and permissions too, so two exports of one person compare line by line
// (#781 decision 3). Every list is [] rather than null when it is empty, so a reader never tells
// "none" from "not read".
func Build(user *record.User, parts Parts, issuer string, exportedAt time.Time) api.UserExportResponse {
	groups := inIdOrder(parts.Groups, func(g api.UserExportGroupResponse) int64 { return g.Id })
	for i := range groups {
		groups[i].Attributes = inIdOrder(groups[i].Attributes, func(a api.GroupAttributeResponse) int64 { return a.Id })
		groups[i].Permissions = inIdOrder(groups[i].Permissions, permissionId)
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
			Id:      user.Id,
			Subject: user.Subject,
			Email:   user.Email,
			// The digest an audit entry about the address records: the address is stored in
			// lowercase and trimmed, which is the form the digest is taken of.
			EmailDigest: hashutil.HashString(user.Email),
		},
		User:          *apimapping.ToUserResponse(user),
		Attributes:    inIdOrder(parts.Attributes, func(a api.UserAttributeResponse) int64 { return a.Id }),
		Groups:        groups,
		Permissions:   inIdOrder(parts.Permissions, permissionId),
		Consents:      inIdOrder(parts.Consents, func(c api.UserConsentResponse) int64 { return c.Id }),
		Sessions:      inIdOrder(parts.Sessions, func(s api.UserSessionDetailResponse) int64 { return s.Id }),
		RefreshTokens: []json.RawMessage{},
		LegalDocumentAcceptances: inIdOrder(parts.LegalDocumentAcceptances,
			func(a api.LegalDocumentAcceptanceResponse) int64 { return a.Id }),
		ProfilePicture: picture,
		AuditEvents:    []json.RawMessage{},
	}
}

func permissionId(p api.PermissionResponse) int64 { return p.Id }

// inIdOrder is a copy of entries sorted by id, ascending, and never nil.
func inIdOrder[T any](entries []T, id func(T) int64) []T {
	sorted := make([]T, len(entries))
	copy(sorted, entries)
	slices.SortStableFunc(sorted, func(a, b T) int { return cmp.Compare(id(a), id(b)) })
	return sorted
}

// FileName is the name the document is saved under: user-<id>-<date>.json, the date being
// exportedAt's in UTC, as in user-42-2026-11-05.json. The id keeps the email address out of
// download folders and mail attachments (#781 decision 6).
func FileName(userId int64, exportedAt time.Time) string {
	return fmt.Sprintf("user-%d-%s.json", userId, exportedAt.UTC().Format(time.DateOnly))
}
