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

// The console's duration hints and the verification wait read Polish for a page asking for pl-PL:
// the browser writes each unit in the nominative, by the count's category (1 sekunda, 2 sekundy, 5
// sekund, 22 sekundy), and the one sentence that embeds a duration puts it after a colon (#665
// decision 3).
func TestPolish_DurationHintsAndVerificationWait(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "pl-PL")
	messages, err := json.Marshal(map[string]string{
		"durationInvalid": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_invalid"),
		"durationTooLong": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_too_long"),
		"durationZero":    i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_zero"),
		"durationGlobal":  "5400",
	})
	require.NoError(t, err)
	cases := []durationCase{
		formatIn("pl", "0", settingsUnits, "0 sekund"),
		formatIn("pl", "1", settingsUnits, "1 sekunda"),
		formatIn("pl", "2", settingsUnits, "2 sekundy"),
		formatIn("pl", "5", settingsUnits, "5 sekund"),
		formatIn("pl", "22", settingsUnits, "22 sekundy"),
		formatIn("pl", "5400", settingsUnits, "1 godzina i 30 minut"),
		formatIn("pl", "86400", settingsUnits, "1 dzień"),
		formatIn("pl", "90061", waitUnits, "25 godzin, 1 minuta i 1 sekunda"),
		formatIn("pl", "59.6", waitUnits, "1 minuta"),
		describeIn("pl", `"0"`, string(messages), "Używa ustawienia globalnego (1 godzina i 30 minut)"),
		describeIn("pl", `"x"`, string(messages), "Wpisz całkowitą liczbę sekund."),
		describeIn("pl", `"160000001"`, string(messages), "To za długo. Wpisz krótszy czas."),
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
	assert.Equal(t, "Czas do wysłania kolejnego kodu: 1 minuta.",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[8].Value}))
}
