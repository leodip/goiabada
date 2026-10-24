package web

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGerman_DurationHintsAndVerificationWait(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "de-AT")
	messages, err := json.Marshal(map[string]string{
		"durationInvalid": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_invalid"),
		"durationTooLong": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_too_long"),
		"durationZero":    i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_zero"),
		"durationGlobal":  "5400",
	})
	require.NoError(t, err)
	cases := []durationCase{
		formatIn("de", "0", settingsUnits, "0 Sekunden"),
		formatIn("de", "1", settingsUnits, "1 Sekunde"),
		formatIn("de", "2", settingsUnits, "2 Sekunden"),
		formatIn("de", "5400", settingsUnits, "1 Stunde, 30 Minuten"),
		formatIn("de", "86400", settingsUnits, "1 Tag"),
		formatIn("de", "90061", waitUnits, "25 Stunden, 1 Minute und 1 Sekunde"),
		formatIn("de", "59.6", waitUnits, "1 Minute"),
		describeIn("de", `"0"`, string(messages), "Verwendet die globale Einstellung (1 Stunde, 30 Minuten)"),
		describeIn("de", `"x"`, string(messages), "Geben Sie eine ganze Anzahl von Sekunden ein."),
		describeIn("de", `"160000001"`, string(messages), "Die Dauer ist zu lang. Geben Sie eine kürzere Dauer ein."),
	}
	input, err := json.Marshal(map[string]any{"utils": utilsJS(t), "cases": cases})
	require.NoError(t, err)
	cmd := exec.CommandContext(t.Context(), "node", "-e", durationRun)
	cmd.Env = append(os.Environ(), "LC_ALL=fr_FR.UTF-8")
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	require.NoError(t, err)
	var answer struct {
		Answers []struct{ Type, Value string }
	}
	require.NoError(t, json.Unmarshal(output, &answer))
	require.Len(t, answer.Answers, len(cases))
	for i, tc := range cases {
		assert.Equal(t, "string", answer.Answers[i].Type, tc.Call)
		assert.Equal(t, tc.want, answer.Answers[i].Value, tc.Call)
	}
	assert.Equal(t, "Warten Sie 1 Minute, bevor Sie einen neuen Code anfordern.",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[6].Value}))
}
