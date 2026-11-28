package render

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// A page read in Japanese writes its dates year/month/day on a 24-hour clock, and its relative
// times in Japanese's one form, with a half-width space between the count and its unit: the same
// phrase at 1, 2 and 11 (#662).
func TestJapanese_DatesAndRelativeTimes(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "ja-JP")
	now := time.Date(2026, time.October, 24, 16, 5, 0, 0, time.UTC)
	assert.Equal(t, "2026/10/24 16:05", formatDateTime(ctx, &now))
	morning := time.Date(2026, time.March, 2, 9, 7, 0, 0, time.UTC)
	assert.Equal(t, "2026/03/02 09:07", formatDateTime(ctx, &morning))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{-time.Minute, "たった今"},
		{0, "たった今"},
		{time.Second / 2, "たった今"},
		{time.Second, "1 秒前"},
		{2 * time.Second, "2 秒前"},
		{11 * time.Second, "11 秒前"},
		{time.Minute, "1 分前"},
		{2 * time.Minute, "2 分前"},
		{11 * time.Minute, "11 分前"},
		{time.Hour, "1 時間前"},
		{2 * time.Hour, "2 時間前"},
		{11 * time.Hour, "11 時間前"},
		{24 * time.Hour, "1 日前"},
		{48 * time.Hour, "2 日前"},
		{11 * 24 * time.Hour, "11 日前"},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			then := now.Add(-tc.age)
			assert.Equal(t, tc.want, formatSince(ctx, &then, now))
		})
	}
}
