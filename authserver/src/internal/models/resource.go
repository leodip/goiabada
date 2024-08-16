package models

import (
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/constants"
)

type Resource struct {
	Id                 int64        `db:"id" fieldtag:"pk"`
	CreatedAt          sql.NullTime `db:"created_at" fieldtag:"dont-update"`
	UpdatedAt          sql.NullTime `db:"updated_at"`
	ResourceIdentifier string       `db:"resource_identifier"`
	Description        string       `db:"description"`
}

func (r *Resource) IsSystemLevelResource() bool {
	systemLevelResources := []string{
		constants.AuthServerResourceIdentifier,
		constants.AdminConsoleResourceIdentifier,
	}
	for _, systemLevelResource := range systemLevelResources {
		if r.ResourceIdentifier == systemLevelResource {
			return true
		}
	}
	return false
}
