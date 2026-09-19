package middleware

import (
	"context"

	"github.com/leodip/goiabada/authserver/internal/constants"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/handlerhelpers"
)

type SettingsReader struct{}

func (SettingsReader) LayoutSettings(ctx context.Context) handlerhelpers.LayoutSettings {
	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)
	return handlerhelpers.LayoutSettings{
		AppName:     settings.AppName,
		UITheme:     settings.UITheme,
		SMTPEnabled: settings.SMTPEnabled,
	}
}
