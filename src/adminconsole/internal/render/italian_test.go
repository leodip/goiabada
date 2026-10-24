package render

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

func TestItalian_DatesAndRelativeTimes(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "it-CH")
	now := time.Date(2026, time.October, 24, 16, 5, 0, 0, time.UTC)
	assert.Equal(t, "24/10/2026 16:05", formatDateTime(ctx, &now))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{-time.Minute, "proprio ora"},
		{0, "proprio ora"},
		{time.Second / 2, "proprio ora"},
		{time.Second, "1 secondo fa"},
		{2 * time.Second, "2 secondi fa"},
		{time.Minute, "1 minuto fa"},
		{2 * time.Minute, "2 minuti fa"},
		{time.Hour, "1 ora fa"},
		{2 * time.Hour, "2 ore fa"},
		{24 * time.Hour, "1 giorno fa"},
		{48 * time.Hour, "2 giorni fa"},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			then := now.Add(-tc.age)
			assert.Equal(t, tc.want, formatSince(ctx, &then, now))
		})
	}
}
