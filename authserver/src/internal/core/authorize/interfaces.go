package core

import (
	"context"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

type codeIssuer interface {
	CreateAuthCode(ctx context.Context, input *CreateCodeInput) (*entitiesv2.Code, error)
}
