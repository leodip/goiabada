package middleware

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSettingsReader_LayoutSettings(t *testing.T) {
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
		AppName:     "sentinel app",
		UITheme:     "sentinel theme",
		SMTPEnabled: true,
	})

	settings := SettingsReader{}.LayoutSettings(ctx)

	assert.Equal(t, handlerhelpers.LayoutSettings{
		AppName:     "sentinel app",
		UITheme:     "sentinel theme",
		SMTPEnabled: true,
	}, settings)
}

func TestSettingsReader_Issuer(t *testing.T) {
	ctx := context.WithValue(context.Background(), constants.ContextKeySettings, &models.Settings{
		Issuer: "https://sentinel.example",
	})

	assert.Equal(t, "https://sentinel.example", SettingsReader{}.Issuer(ctx))
}

func TestSettingsReader_PanicsWithoutSettings(t *testing.T) {
	tests := []struct {
		name string
		read func()
	}{
		{
			name: "issuer",
			read: func() { SettingsReader{}.Issuer(context.Background()) },
		},
		{
			name: "layout settings",
			read: func() { SettingsReader{}.LayoutSettings(context.Background()) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Panics(t, tt.read)
		})
	}
}
