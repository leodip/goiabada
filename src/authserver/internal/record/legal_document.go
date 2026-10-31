package record

import (
	"database/sql"
	"time"
)

// The two kinds of legal document, as stored in legal_documents.kind and answered by the admin
// API. A document's kind is fixed when it is created, so a version always meant the same thing to
// the users who saw it (#622 decision 2).
const (
	// LegalDocumentKindMustAccept is terms of use: users must accept the current version.
	LegalDocumentKindMustAccept = "must_accept"
	// LegalDocumentKindForInformation is a privacy notice: shown and linked, never accepted.
	LegalDocumentKindForInformation = "for_information"
)

// The bounds of a legal document's text, in inputvalidation.TextLength's unit, and of its short
// name, which is ASCII. The columns are as wide as the first and the last; the Markdown columns are
// unbounded on every engine, so the Markdown bound is the API's alone.
const (
	LegalDocumentTitleMaxLength     = 200
	LegalDocumentMarkdownMaxLength  = 100_000
	LegalDocumentShortNameMaxLength = 64
)

// LegalDocument is a privacy notice or terms of use (#622). Its published text lives in
// LegalDocumentVersion rows; the row here holds what stays the same across versions and the one
// unpublished draft. DraftTitle and DraftMarkdown are both set while there is a draft and both null
// once Publish has frozen it as a version. A document with no version has never been published. A
// retired document keeps its versions but applies to no one (decision 2).
//
// ShortName is the document's public address, /legal/<short-name>. It is unique among documents
// and fixed once the document is first published (decision 5).
type LegalDocument struct {
	Id            int64          `db:"id" fieldtag:"pk"`
	CreatedAt     sql.NullTime   `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt     sql.NullTime   `db:"updated_at"`
	ShortName     string         `db:"short_name"`
	Kind          string         `db:"kind" fieldtag:"dont-update"`
	DraftTitle    sql.NullString `db:"draft_title"`
	DraftMarkdown sql.NullString `db:"draft_markdown"`
	RetiredAt     sql.NullTime   `db:"retired_at"`
}

// HasDraft reports whether the document has an unpublished draft.
func (d *LegalDocument) HasDraft() bool {
	return d.DraftTitle.Valid && d.DraftMarkdown.Valid
}

// IsRetired reports whether the document has been retired.
func (d *LegalDocument) IsRetired() bool {
	return d.RetiredAt.Valid
}

// LegalDocumentVersion is one published version of a legal document: its title and Markdown as
// they were frozen by Publish, numbered from 1 within the document. A version is written once and
// never rewritten, so what a user accepted is what the row still says (decision 1).
type LegalDocumentVersion struct {
	Id              int64     `db:"id" fieldtag:"pk"`
	PublishedAt     time.Time `db:"published_at"`
	LegalDocumentId int64     `db:"legal_document_id"`
	VersionNumber   int       `db:"version_number"`
	Title           string    `db:"title"`
	Markdown        string    `db:"markdown"`
}
