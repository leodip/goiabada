package middleware

import (
	"context"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/handlerhelpers"
	"github.com/leodip/goiabada/authserver/internal/models"
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

func TestSettingsReader_LayoutSettingsPanicsWithoutSettings(t *testing.T) {
	require.Panics(t, func() {
		SettingsReader{}.LayoutSettings(context.Background())
	})
}
