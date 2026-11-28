package render

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// A page read in Russian writes its dates day.month.year on a 24-hour clock, and its relative times
// in the form the count takes: one for 1 and 21, few for 2 to 4 and 22 to 24, many for 5 to 20 and
// 25 on, the teens included (#666).
func TestRussian_DatesAndRelativeTimes(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "ru-RU")
	now := time.Date(2026, time.October, 24, 16, 5, 0, 0, time.UTC)
	assert.Equal(t, "24.10.2026 16:05", formatDateTime(ctx, &now))
	morning := time.Date(2026, time.March, 2, 9, 7, 0, 0, time.UTC)
	assert.Equal(t, "02.03.2026 09:07", formatDateTime(ctx, &morning))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{-time.Minute, "только что"},
		{0, "только что"},
		{time.Second / 2, "только что"},
		{time.Second, "1 секунду назад"},
		{2 * time.Second, "2 секунды назад"},
		{5 * time.Second, "5 секунд назад"},
		{11 * time.Second, "11 секунд назад"},
		{21 * time.Second, "21 секунду назад"},
		{22 * time.Second, "22 секунды назад"},
		{25 * time.Second, "25 секунд назад"},
		{time.Minute, "1 минуту назад"},
		{2 * time.Minute, "2 минуты назад"},
		{5 * time.Minute, "5 минут назад"},
		{11 * time.Minute, "11 минут назад"},
		{21 * time.Minute, "21 минуту назад"},
		{22 * time.Minute, "22 минуты назад"},
		{25 * time.Minute, "25 минут назад"},
		{time.Hour, "1 час назад"},
		{2 * time.Hour, "2 часа назад"},
		{5 * time.Hour, "5 часов назад"},
		{11 * time.Hour, "11 часов назад"},
		{21 * time.Hour, "21 час назад"},
		{22 * time.Hour, "22 часа назад"},
		{24 * time.Hour, "1 день назад"},
		{48 * time.Hour, "2 дня назад"},
		{5 * 24 * time.Hour, "5 дней назад"},
		{11 * 24 * time.Hour, "11 дней назад"},
		{21 * 24 * time.Hour, "21 день назад"},
		{22 * 24 * time.Hour, "22 дня назад"},
		{25 * 24 * time.Hour, "25 дней назад"},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			then := now.Add(-tc.age)
			assert.Equal(t, tc.want, formatSince(ctx, &then, now))
		})
	}
}
