package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionWireTypes_JSONRepresentation(t *testing.T) {
	lastAccessed := time.Date(2026, 9, 13, 12, 34, 56, 0, time.UTC)
	expiresAt := time.Date(2026, 9, 14, 1, 23, 45, 0, time.UTC)

	tests := []struct {
		name     string
		want     any
		newValue func() any
		literal  string
	}{
		{
			name:     "SessionLoadRequest",
			want:     &SessionLoadRequest{Id: "session-id"},
			newValue: func() any { return &SessionLoadRequest{} },
			literal:  `{"id":"session-id"}`,
		},
		{
			name: "SessionWriteRequest",
			want: &SessionWriteRequest{
				Id:            "session-id",
				Data:          "sealed-data",
				Authenticated: true,
			},
			newValue: func() any { return &SessionWriteRequest{} },
			literal:  `{"id":"session-id","data":"sealed-data","authenticated":true}`,
		},
		{
			name: "SessionTouchRequest",
			want: &SessionTouchRequest{
				Id:            "session-id",
				Authenticated: true,
			},
			newValue: func() any { return &SessionTouchRequest{} },
			literal:  `{"id":"session-id","authenticated":true}`,
		},
		{
			name: "SessionLoadResponse",
			want: &SessionLoadResponse{
				Data:         "sealed-data",
				LastAccessed: lastAccessed,
				ExpiresAt:    expiresAt,
			},
			newValue: func() any { return &SessionLoadResponse{} },
			literal:  `{"data":"sealed-data","lastAccessed":"2026-09-13T12:34:56Z","expiresAt":"2026-09-14T01:23:45Z"}`,
		},
		{
			name:     "SessionWriteResponse",
			want:     &SessionWriteResponse{ExpiresAt: expiresAt},
			newValue: func() any { return &SessionWriteResponse{} },
			literal:  `{"expiresAt":"2026-09-14T01:23:45Z"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.want)
			require.NoError(t, err)
			assert.Equal(t, tc.literal, string(encoded))

			decoded := tc.newValue()
			require.NoError(t, json.Unmarshal([]byte(tc.literal), decoded))
			assert.Equal(t, tc.want, decoded)
		})
	}
}
