package models

import (
	"testing"
	"time"
)

func TestUserSession_IsValid(t *testing.T) {
	tests := []struct {
		name                            string
		us                              UserSession
		userSessionIdleTimeoutInSeconds int
		userSessionMaxLifetimeInSeconds int
		requestedMaxAgeInSeconds        *int
		want                            bool
	}{
		{
			name: "Valid session",
			us: UserSession{
				Started:      time.Now().Add(-30 * time.Minute),
				LastAccessed: time.Now().Add(-5 * time.Minute),
			},
			userSessionIdleTimeoutInSeconds: 3600, // 1 hour
			userSessionMaxLifetimeInSeconds: 7200, // 2 hours
			requestedMaxAgeInSeconds:        nil,
			want:                            true,
		},
		{
			name: "Expired idle timeout",
			us: UserSession{
				Started:      time.Now().Add(-30 * time.Minute),
				LastAccessed: time.Now().Add(-25 * time.Minute),
			},
			userSessionIdleTimeoutInSeconds: 300,  // 5 minutes
			userSessionMaxLifetimeInSeconds: 7200, // 2 hours
			requestedMaxAgeInSeconds:        nil,
			want:                            false,
		},
		{
			name: "Expired max lifetime",
			us: UserSession{
				Started:      time.Now().Add(-3 * time.Hour),
				LastAccessed: time.Now().Add(-5 * time.Minute),
			},
			userSessionIdleTimeoutInSeconds: 3600, // 1 hour
			userSessionMaxLifetimeInSeconds: 7200, // 2 hours
			requestedMaxAgeInSeconds:        nil,
			want:                            false,
		},
		{
			name: "Valid with requested max age",
			us: UserSession{
				Started:      time.Now().Add(-30 * time.Minute),
				LastAccessed: time.Now().Add(-5 * time.Minute),
			},
			userSessionIdleTimeoutInSeconds: 3600,         // 1 hour
			userSessionMaxLifetimeInSeconds: 7200,         // 2 hours
			requestedMaxAgeInSeconds:        intPtr(3600), // 1 hour
			want:                            true,
		},
		{
			name: "Invalid due to requested max age",
			us: UserSession{
				Started:      time.Now().Add(-2 * time.Hour),
				LastAccessed: time.Now().Add(-5 * time.Minute),
			},
			userSessionIdleTimeoutInSeconds: 3600,         // 1 hour
			userSessionMaxLifetimeInSeconds: 7200,         // 2 hours
			requestedMaxAgeInSeconds:        intPtr(3600), // 1 hour
			want:                            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.us.IsValid(tt.userSessionIdleTimeoutInSeconds, tt.userSessionMaxLifetimeInSeconds, tt.requestedMaxAgeInSeconds); got != tt.want {
				t.Errorf("UserSession.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func intPtr(i int) *int {
	return &i
}
