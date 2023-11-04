package core

import (
	"context"

	"github.com/leodip/goiabada/internal/entities"
)

type codeIssuer interface {
	CreateAuthCode(ctx context.Context, input *CreateCodeInput) (*entities.Code, error)
}
