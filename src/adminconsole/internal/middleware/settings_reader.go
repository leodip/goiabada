package middleware

import (
	"context"

	"github.com/leodip/goiabada/adminconsole/internal/constants"
	"github.com/leodip/goiabada/adminconsole/internal/handlerhelpers"
	"github.com/leodip/goiabada/core/api"
)

type SettingsReader struct{}

func (SettingsReader) Issuer(ctx context.Context) string {
	settings := ctx.Value(constants.ContextKeySettings).(*api.PublicSettingsResponse)
	return settings.Issuer
}

func (SettingsReader) LayoutSettings(ctx context.Context) handlerhelpers.LayoutSettings {
	settings := ctx.Value(constants.ContextKeySettings).(*api.PublicSettingsResponse)
	return handlerhelpers.LayoutSettings{
		AppName:     settings.AppName,
		UITheme:     settings.UITheme,
		SMTPEnabled: settings.SMTPEnabled,
	}
}
