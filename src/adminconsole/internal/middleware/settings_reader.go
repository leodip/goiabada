package middleware

import (
	"context"

	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/handlerhelpers"
	"github.com/leodip/goiabada/core/models"
)

type SettingsReader struct{}

func (SettingsReader) Issuer(ctx context.Context) string {
	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)
	return settings.Issuer
}

func (SettingsReader) LayoutSettings(ctx context.Context) handlerhelpers.LayoutSettings {
	settings := ctx.Value(constants.ContextKeySettings).(*models.Settings)
	return handlerhelpers.LayoutSettings{
		AppName:     settings.AppName,
		UITheme:     settings.UITheme,
		SMTPEnabled: settings.SMTPEnabled,
	}
}
