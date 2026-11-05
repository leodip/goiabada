// Package userexport builds the document that holds everything the auth server holds about one
// user (#781): what an operator hands a person who asked for a copy of their data. The admin API's
// export route answers it, and the account API's own copy (#782) calls the same builder, so the
// document is one thing whoever asks.
package userexport

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/leodip/goiabada/authserver/internal/apimapping"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/hashutil"
)

// FormatVersion is the document's format version. It goes up only for a change that breaks a
// reader; a field added to a reused entry is additive and leaves it (#781 decision 3).
const FormatVersion = 1

// Build is the document for user, exported at exportedAt by the auth server whose issuer is issuer.
//
// Each part is the entry the matching admin API read answers, inside the versioned wrapper, so
// nothing secret reaches it: the user is GET /api/v1/admin/users/{id}'s projection, which carries
// no password hash, two-factor secret or pending code. Every list is [] rather than null when it
// is empty, so a reader never tells "none" from "not read".
func Build(user *record.User, issuer string, exportedAt time.Time) api.UserExportResponse {
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
		User:                     *apimapping.ToUserResponse(user),
		Attributes:               []api.UserAttributeResponse{},
		Groups:                   []json.RawMessage{},
		Permissions:              []api.PermissionResponse{},
		Consents:                 []api.UserConsentResponse{},
		Sessions:                 []api.UserSessionDetailResponse{},
		RefreshTokens:            []json.RawMessage{},
		LegalDocumentAcceptances: []api.LegalDocumentAcceptanceResponse{},
		AuditEvents:              []json.RawMessage{},
	}
}

// FileName is the name the document is saved under: user-<id>-<date>.json, the date being
// exportedAt's in UTC, as in user-42-2026-11-05.json. The id keeps the email address out of
// download folders and mail attachments (#781 decision 6).
func FileName(userId int64, exportedAt time.Time) string {
	return fmt.Sprintf("user-%d-%s.json", userId, exportedAt.UTC().Format(time.DateOnly))
}
