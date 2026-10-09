package middleware

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
)

func TestSettingsReader_Issuer(t *testing.T) {
	ctx := reqctx.WithSettings(context.Background(), &api.PublicSettingsResponse{
		Issuer: "https://sentinel.example",
	})

	assert.Equal(t, "https://sentinel.example", SettingsReader{}.Issuer(ctx))
}

// Without settings the reader answers "" rather than panicking. The ID-token parser refuses an
// empty expected issuer outright, so a request that reached it without the settings middleware is
// refused there, as a token it cannot verify, and not answered with a crash (#440 decision 3).
func TestSettingsReader_IssuerWithoutSettingsIsEmpty(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "nothing written", ctx: context.Background()},
		{name: "a nil pointer written", ctx: reqctx.WithSettings(context.Background(), nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.Empty(t, SettingsReader{}.Issuer(tt.ctx))
			})
		})
	}
}
