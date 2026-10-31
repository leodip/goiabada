package api

import "time"

// The admin API's legal documents (#622): privacy notices and terms of use, drafted, then published
// as numbered versions, in the settings domain.

// LegalDocumentResponse is a legal document as listed: what stays the same across its versions,
// and its current version's number, title and publish date. A never-published document has
// currentVersion 0, no publishedAt, and its draft's title. AppliesTo is all_apps or selected_apps;
// ClientIds are the apps a document set to selected apps lists, never null, and empty for all apps.
// A document set to selected apps with no client ids applies to nobody.
type LegalDocumentResponse struct {
	Id             int64      `json:"id"`
	CreatedAt      *time.Time `json:"createdAt"`
	UpdatedAt      *time.Time `json:"updatedAt"`
	ShortName      string     `json:"shortName"`
	Kind           string     `json:"kind"`
	Title          string     `json:"title"`
	CurrentVersion int        `json:"currentVersion"`
	PublishedAt    *time.Time `json:"publishedAt"`
	HasDraft       bool       `json:"hasDraft"`
	Retired        bool       `json:"retired"`
	RetiredAt      *time.Time `json:"retiredAt"`
	AppliesTo      string     `json:"appliesTo"`
	ClientIds      []int64    `json:"clientIds"`
}

// LegalDocumentDraftResponse is a document's one unpublished draft.
type LegalDocumentDraftResponse struct {
	Title    string `json:"title"`
	Markdown string `json:"markdown"`
}

// LegalDocumentVersionSummaryResponse is one published version, as a document's versions list
// shows it.
type LegalDocumentVersionSummaryResponse struct {
	Version     int        `json:"version"`
	Title       string     `json:"title"`
	PublishedAt *time.Time `json:"publishedAt"`
}

// LegalDocumentVersionResponse is one published version with its text.
type LegalDocumentVersionResponse struct {
	Version     int        `json:"version"`
	Title       string     `json:"title"`
	Markdown    string     `json:"markdown"`
	PublishedAt *time.Time `json:"publishedAt"`
}

type GetLegalDocumentsResponse struct {
	LegalDocuments []LegalDocumentResponse `json:"legalDocuments"`
}

// LegalDocumentDetailResponse is one document with its draft, null when it has none, and its
// versions, the first first. Every operation on one document answers it.
type LegalDocumentDetailResponse struct {
	LegalDocument LegalDocumentResponse                 `json:"legalDocument"`
	Draft         *LegalDocumentDraftResponse           `json:"draft"`
	Versions      []LegalDocumentVersionSummaryResponse `json:"versions"`
}

type GetLegalDocumentVersionResponse struct {
	LegalDocument LegalDocumentResponse        `json:"legalDocument"`
	Version       LegalDocumentVersionResponse `json:"version"`
}

// CreateLegalDocumentRequest creates a document holding a draft. Its kind is fixed from then on.
type CreateLegalDocumentRequest struct {
	Kind      string `json:"kind"`
	ShortName string `json:"shortName"`
	Title     string `json:"title"`
	Markdown  string `json:"markdown"`
}

// SaveLegalDocumentDraftRequest replaces the document's draft, or starts one. ShortName empty
// keeps the document's short name; another one is taken only until the first publish.
type SaveLegalDocumentDraftRequest struct {
	ShortName string `json:"shortName"`
	Title     string `json:"title"`
	Markdown  string `json:"markdown"`
}

// PreviewLegalDocumentRequest is Markdown to render as a published page would.
type PreviewLegalDocumentRequest struct {
	Markdown string `json:"markdown"`
}

type PreviewLegalDocumentResponse struct {
	Html string `json:"html"`
}

// UpdateLegalDocumentAppsRequest sets a document's Applies to: all_apps, or selected_apps with the
// client ids it applies to, which all_apps leaves empty. It replaces the whole list as a list save
// does: ExpectedClientIds is the list as the caller last read it, [] when it was empty, and a
// stored list that differs from it refuses the save.
type UpdateLegalDocumentAppsRequest struct {
	AppliesTo         string  `json:"appliesTo"`
	ClientIds         []int64 `json:"clientIds"`
	ExpectedClientIds []int64 `json:"expectedClientIds"`
}

// GetClientLegalDocumentsResponse is the client and the documents that apply to it: every document
// not retired that applies to all apps or lists the client, published or not, in id order.
type GetClientLegalDocumentsResponse struct {
	Client         ClientResponse          `json:"client"`
	LegalDocuments []LegalDocumentResponse `json:"legalDocuments"`
}
