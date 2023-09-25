package core

import (
	"context"

	"github.com/leodip/goiabada/internal/entities"
	"github.com/leodip/goiabada/internal/enums"
)

type codeIssuer interface {
	CreateAuthCode(ctx context.Context, input *CreateCodeInput) (*entities.Code, error)
	GetUserSessionAcrLevel(ctx context.Context, userSession *entities.UserSession) enums.AcrLevel
}
