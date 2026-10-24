package render

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

func TestGerman_DatesAndRelativeTimes(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "de-AT")
	now := time.Date(2026, time.October, 24, 16, 5, 0, 0, time.UTC)
	assert.Equal(t, "24.10.2026 16:05", formatDateTime(ctx, &now))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{-time.Minute, "gerade eben"},
		{0, "gerade eben"},
		{time.Second / 2, "gerade eben"},
		{time.Second, "vor 1 Sekunde"},
		{2 * time.Second, "vor 2 Sekunden"},
		{time.Minute, "vor 1 Minute"},
		{2 * time.Minute, "vor 2 Minuten"},
		{time.Hour, "vor 1 Stunde"},
		{2 * time.Hour, "vor 2 Stunden"},
		{24 * time.Hour, "vor 1 Tag"},
		{48 * time.Hour, "vor 2 Tagen"},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			then := now.Add(-tc.age)
			assert.Equal(t, tc.want, formatSince(ctx, &then, now))
		})
	}
}
