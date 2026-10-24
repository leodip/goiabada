package render

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

func TestFrench_DatesAndRelativeTimes(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "fr-CA")
	now := time.Date(2026, time.October, 24, 16, 5, 0, 0, time.UTC)
	assert.Equal(t, "24/10/2026 16:05", formatDateTime(ctx, &now))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{-time.Minute, "à l’instant"},
		{0, "à l’instant"},
		{time.Second / 2, "à l’instant"},
		{time.Second, "il y a 1 seconde"},
		{2 * time.Second, "il y a 2 secondes"},
		{time.Minute, "il y a 1 minute"},
		{2 * time.Minute, "il y a 2 minutes"},
		{time.Hour, "il y a 1 heure"},
		{2 * time.Hour, "il y a 2 heures"},
		{24 * time.Hour, "il y a 1 jour"},
		{48 * time.Hour, "il y a 2 jours"},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			then := now.Add(-tc.age)
			assert.Equal(t, tc.want, formatSince(ctx, &then, now))
		})
	}
}
