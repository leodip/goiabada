package auditlog

import (
	"log/slog"
	"testing"

	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The console audit record used to be a JSON document in the message field, which is what
// decision 7 of #320 replaced. The properties below are what a collector depends on, so each is
// a case rather than a reading of the one line the function is.

func TestLogToConsole_WritesOneInfoRecordCarryingTheEventAndTheDetails(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	details := map[string]any{"userId": int64(42), "reason": "email_collision_backfill"}
	LogToConsole("revoked_user_auth_state", details)

	records := logs.Records()
	require.Len(t, records, 1, "one audit event must produce exactly one record")

	assert.Equal(t, slog.LevelInfo, records[0].Level,
		"an audit event is a record of something that happened, not a failure")
	assert.Equal(t, "audit event", records[0].Message,
		"the message is what a reader greps for, so it is the same for every event")
	assert.Equal(t, "revoked_user_auth_state", records[0].Attrs["event"],
		"the event name is an attribute a collector can filter on, not part of the message")
	assert.Equal(t, details, records[0].Attrs["details"],
		"the details reach the record as the map itself, so a JSON collector gets an object it can query inside rather than a string it has to parse a second time")
}

// The empty map is its own case because it is the shape that most easily degrades into absent:
// an event with nothing to say about itself must still carry the field, or a consumer reading
// details has to tell "no details" from "this writer does not send details".
func TestLogToConsole_KeepsAnEmptyDetailsMapAsAnEmptyMap(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	LogToConsole("system_startup", map[string]any{})

	records := logs.Records()
	require.Len(t, records, 1)
	require.Contains(t, records[0].Attrs, "details", "the attribute must be written even when empty")
	assert.Equal(t, map[string]any{}, records[0].Attrs["details"])
}

// Nested values are the reason the details go in as a value rather than as text. The four
// credential sites and the backfill all send slices, and the backfill sends two of them.
func TestLogToConsole_KeepsNestedValuesAsValues(t *testing.T) {
	logs := testutil.CaptureSlog(t)

	details := map[string]any{
		"terminatedSessionIdentifiers": []string{"sid-1", "sid-2"},
		"user":                         map[string]any{"id": "456", "name": "Jane"},
	}
	LogToConsole("data_update", details)

	records := logs.Records()
	require.Len(t, records, 1)

	written, ok := records[0].Attrs["details"].(map[string]any)
	require.True(t, ok, "details must arrive as a map, not as a rendering of one")
	assert.Equal(t, []string{"sid-1", "sid-2"}, written["terminatedSessionIdentifiers"])
	assert.Equal(t, map[string]any{"id": "456", "name": "Jane"}, written["user"])
}
