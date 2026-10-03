package record

import (
	"math"
	"strconv"
	"testing"
	"time"
)

// TestUserSession_IsValid owns the session validity table: the idle and lifetime bounds, the
// reference instant max_age is measured from, and the values too large to become a Duration.
// Every row runs on one fixed now, so a boundary is exact rather than a race with the clock (#243).
func TestUserSession_IsValid(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }

	// A session that started a day ago, was last used a minute ago, and whose user signed in
	// again five minutes ago. Idle and lifetime bounds are distinct so a swap of the two fails a row.
	const idle = 3600
	const lifetime = 2 * 86400
	fresh := UserSession{
		Started:      ago(24 * time.Hour),
		LastAccessed: ago(time.Minute),
		AuthTime:     ago(5 * time.Minute),
	}

	tests := []struct {
		name     string
		us       UserSession
		idle     int
		lifetime int
		maxAge   *int64
		want     bool
	}{
		{name: "within idle and lifetime, no max_age", us: fresh, idle: idle, lifetime: lifetime, want: true},

		// Idle, measured from LastAccessed.
		{name: "idle exactly at the bound is valid",
			us:   UserSession{Started: ago(time.Hour), LastAccessed: ago(idle * time.Second), AuthTime: ago(time.Hour)},
			idle: idle, lifetime: lifetime, want: true},
		{name: "idle one nanosecond past the bound is not",
			us:   UserSession{Started: ago(time.Hour), LastAccessed: ago(idle*time.Second + 1), AuthTime: ago(time.Hour)},
			idle: idle, lifetime: lifetime, want: false},

		// Lifetime, measured from Started.
		{name: "lifetime exactly at the bound is valid",
			us:   UserSession{Started: ago(lifetime * time.Second), LastAccessed: ago(time.Minute), AuthTime: ago(time.Minute)},
			idle: idle, lifetime: lifetime, want: true},
		{name: "lifetime one nanosecond past the bound is not",
			us:   UserSession{Started: ago(lifetime*time.Second + 1), LastAccessed: ago(time.Minute), AuthTime: ago(time.Minute)},
			idle: idle, lifetime: lifetime, want: false},
		{name: "the idle value is not applied to Started",
			us:   UserSession{Started: ago(2 * idle * time.Second), LastAccessed: ago(time.Minute), AuthTime: ago(time.Minute)},
			idle: idle, lifetime: lifetime, want: true},
		{name: "the lifetime value is not applied to LastAccessed",
			us:   UserSession{Started: ago(time.Hour), LastAccessed: ago(2 * idle * time.Second), AuthTime: ago(time.Hour)},
			idle: idle, lifetime: lifetime, want: false},

		// max_age, measured from AuthTime (#243 defect 1).
		{name: "a day-old session re-authenticated five minutes ago satisfies max_age=3600",
			us: fresh, idle: idle, lifetime: lifetime, maxAge: int64Ptr(3600), want: true},
		{name: "a session authenticated two hours ago fails max_age=3600 however recently it started",
			us:   UserSession{Started: ago(time.Minute), LastAccessed: ago(time.Minute), AuthTime: ago(2 * time.Hour)},
			idle: idle, lifetime: lifetime, maxAge: int64Ptr(3600), want: false},
		{name: "AuthTime earlier than Started is measured from AuthTime",
			us:   UserSession{Started: ago(10 * time.Minute), LastAccessed: ago(time.Minute), AuthTime: ago(2 * time.Hour)},
			idle: idle, lifetime: lifetime, maxAge: int64Ptr(3600), want: false},
		{name: "a zero AuthTime falls back to Started, which satisfies it",
			us:   UserSession{Started: ago(30 * time.Minute), LastAccessed: ago(time.Minute)},
			idle: idle, lifetime: lifetime, maxAge: int64Ptr(3600), want: true},
		{name: "a zero AuthTime falls back to Started, which fails it",
			us:   UserSession{Started: ago(2 * time.Hour), LastAccessed: ago(time.Minute)},
			idle: idle, lifetime: lifetime, maxAge: int64Ptr(3600), want: false},
		{name: "elapsed equal to max_age is valid",
			us:   UserSession{Started: ago(time.Hour), LastAccessed: ago(time.Minute), AuthTime: ago(3600 * time.Second)},
			idle: idle, lifetime: lifetime, maxAge: int64Ptr(3600), want: true},
		{name: "elapsed one second beyond max_age is not",
			us:   UserSession{Started: ago(time.Hour), LastAccessed: ago(time.Minute), AuthTime: ago(3600 * time.Second)},
			idle: idle, lifetime: lifetime, maxAge: int64Ptr(3599), want: false},
		{name: "max_age=0 refuses a session authenticated one nanosecond ago",
			us:   UserSession{Started: ago(time.Hour), LastAccessed: ago(time.Minute), AuthTime: ago(1)},
			idle: idle, lifetime: lifetime, maxAge: int64Ptr(0), want: false},
		{name: "max_age does not rescue a session past its idle timeout",
			us:   UserSession{Started: ago(time.Hour), LastAccessed: ago(2 * idle * time.Second), AuthTime: ago(time.Minute)},
			idle: idle, lifetime: lifetime, maxAge: int64Ptr(math.MaxInt64), want: false},
	}

	// The huge values of the #243 probe, against a session authenticated 24 hours ago, inside a
	// lifetime long enough that only max_age decides. Before the change 9223372037 and
	// math.MaxInt64 wrapped to a deadline in the past and refused the session.
	dayOld := UserSession{Started: ago(24 * time.Hour), LastAccessed: ago(time.Minute), AuthTime: ago(24 * time.Hour)}
	for _, row := range []struct {
		maxAge int64
		want   bool
	}{
		{0, false},
		{3600, false},
		{86400, true},
		{90000, true},
		{9223372036, true},
		{9223372037, true},
		{99999999999, true},
		{math.MaxInt64, true},
	} {
		tests = append(tests, struct {
			name     string
			us       UserSession
			idle     int
			lifetime int
			maxAge   *int64
			want     bool
		}{
			name: "day-old authentication, max_age=" + strconv.FormatInt(row.maxAge, 10),
			us:   dayOld, idle: idle, lifetime: lifetime, maxAge: int64Ptr(row.maxAge), want: row.want,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.us.IsValid(now, tt.idle, tt.lifetime, tt.maxAge); got != tt.want {
				t.Errorf("UserSession.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func int64Ptr(i int64) *int64 {
	return &i
}
