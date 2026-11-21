package render

import (
	"context"
	"testing"
	"time"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
)

// A page read in Polish writes its dates day.month.year on a 24-hour clock, and its relative times
// in the form the count takes: one for 1, few for 2 to 4 and 22 to 24, many for 5 to 21 and 25 on
// (#665).
func TestPolish_DatesAndRelativeTimes(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "pl-PL")
	now := time.Date(2026, time.October, 24, 16, 5, 0, 0, time.UTC)
	assert.Equal(t, "24.10.2026 16:05", formatDateTime(ctx, &now))
	morning := time.Date(2026, time.March, 2, 9, 7, 0, 0, time.UTC)
	assert.Equal(t, "02.03.2026 09:07", formatDateTime(ctx, &morning))
	for _, tc := range []struct {
		age  time.Duration
		want string
	}{
		{-time.Minute, "przed chwilą"},
		{0, "przed chwilą"},
		{time.Second / 2, "przed chwilą"},
		{time.Second, "1 sekundę temu"},
		{2 * time.Second, "2 sekundy temu"},
		{5 * time.Second, "5 sekund temu"},
		{22 * time.Second, "22 sekundy temu"},
		{time.Minute, "1 minutę temu"},
		{2 * time.Minute, "2 minuty temu"},
		{5 * time.Minute, "5 minut temu"},
		{12 * time.Minute, "12 minut temu"},
		{22 * time.Minute, "22 minuty temu"},
		{25 * time.Minute, "25 minut temu"},
		{time.Hour, "1 godzinę temu"},
		{2 * time.Hour, "2 godziny temu"},
		{5 * time.Hour, "5 godzin temu"},
		{22 * time.Hour, "22 godziny temu"},
		{24 * time.Hour, "1 dzień temu"},
		{48 * time.Hour, "2 dni temu"},
		{5 * 24 * time.Hour, "5 dni temu"},
		{22 * 24 * time.Hour, "22 dni temu"},
	} {
		t.Run(tc.age.String(), func(t *testing.T) {
			then := now.Add(-tc.age)
			assert.Equal(t, tc.want, formatSince(ctx, &then, now))
		})
	}
}
