package render

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// The console writes dates day first on a 24-hour clock, and relative times as whole Indonesian
// phrases, one form for one and for many (#668).
func TestIndonesian_DatesAndRelativeTimes(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "id-ID")
	now := time.Date(2026, time.October, 24, 16, 5, 0, 0, time.UTC)
	assert.Equal(t, "24/10/2026 16:05", formatDateTime(ctx, &now))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{-time.Minute, "baru saja"},
		{0, "baru saja"},
		{time.Second / 2, "baru saja"},
		{time.Second, "1 detik yang lalu"},
		{2 * time.Second, "2 detik yang lalu"},
		{time.Minute, "1 menit yang lalu"},
		{2 * time.Minute, "2 menit yang lalu"},
		{time.Hour, "1 jam yang lalu"},
		{2 * time.Hour, "2 jam yang lalu"},
		{24 * time.Hour, "1 hari yang lalu"},
		{48 * time.Hour, "2 hari yang lalu"},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			then := now.Add(-tc.age)
			assert.Equal(t, tc.want, formatSince(ctx, &then, now))
		})
	}
}
