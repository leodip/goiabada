package apihandlers

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

// groupMemberCounter is what countGroupMembers needs: the one count every group response carries.
type groupMemberCounter interface {
	CountGroupMembers(ctx context.Context, tx *sql.Tx, groupId int64) (int, error)
}

// countGroupMembers counts the members of every group given, or answers the first count that
// failed, wrapped with that group's id, and counts no further group.
//
// It is the one spelling of the member counts on this surface. Four of the six sites it replaced
// swallowed a failed count and published 0, which renders a group as empty when the server never
// learned how many members it has; the other two answered 500. A page never shows a number the
// server did not compute, so every caller answers 500 on the error (#425 decision 4).
func countGroupMembers(ctx context.Context, database groupMemberCounter, groups []models.Group) (map[int64]int, error) {
	counts := make(map[int64]int, len(groups))
	for _, group := range groups {
		count, err := database.CountGroupMembers(ctx, nil, group.Id)
		if err != nil {
			return nil, errs.Wrapf(err, "unable to count the members of group %d", group.Id)
		}
		counts[group.Id] = count
	}
	return counts, nil
}
