package render

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// A page read in Simplified Chinese writes its dates year-month-day on a 24-hour clock, and its
// relative times in Chinese's one form, the count joined to its unit: the same phrase at 1, 2 and
// 11 (#663 decision 4).
func TestSimplifiedChinese_DatesAndRelativeTimes(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "zh-CN")
	now := time.Date(2026, time.October, 24, 16, 5, 0, 0, time.UTC)
	assert.Equal(t, "2026-10-24 16:05", formatDateTime(ctx, &now))
	morning := time.Date(2026, time.March, 2, 9, 7, 0, 0, time.UTC)
	assert.Equal(t, "2026-03-02 09:07", formatDateTime(ctx, &morning))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{-time.Minute, "刚刚"},
		{0, "刚刚"},
		{time.Second / 2, "刚刚"},
		{time.Second, "1秒前"},
		{2 * time.Second, "2秒前"},
		{11 * time.Second, "11秒前"},
		{time.Minute, "1分钟前"},
		{2 * time.Minute, "2分钟前"},
		{11 * time.Minute, "11分钟前"},
		{time.Hour, "1小时前"},
		{2 * time.Hour, "2小时前"},
		{11 * time.Hour, "11小时前"},
		{24 * time.Hour, "1天前"},
		{48 * time.Hour, "2天前"},
		{11 * 24 * time.Hour, "11天前"},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			then := now.Add(-tc.age)
			assert.Equal(t, tc.want, formatSince(ctx, &then, now))
		})
	}
}
