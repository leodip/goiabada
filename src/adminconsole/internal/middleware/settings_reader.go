package middleware

import (
	"context"

	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
)

// SettingsReader is where the ID-token parser reads the issuer it expects, from the settings the
// settings-cache middleware put on the request.
type SettingsReader struct{}

// Issuer answers "" when the request carries no settings, which only a wiring defect produces. The
// parser refuses an empty expected issuer outright, so such a request is refused there rather than
// answered with a panic here (#440 decision 3).
func (SettingsReader) Issuer(ctx context.Context) string {
	settings, ok := reqctx.SettingsFrom(ctx)
	if !ok {
		return ""
	}
	return settings.Issuer
}
