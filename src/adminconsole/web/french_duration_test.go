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

func TestFrench_DurationHintsAndVerificationWait(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "fr-CA")
	messages, err := json.Marshal(map[string]string{
		"durationInvalid": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_invalid"),
		"durationTooLong": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_too_long"),
		"durationZero":    i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_zero"),
		"durationGlobal":  "5400",
	})
	require.NoError(t, err)
	cases := []durationCase{
		formatIn("fr", "0", settingsUnits, "0\u00a0seconde"),
		formatIn("fr", "1", settingsUnits, "1\u00a0seconde"),
		formatIn("fr", "2", settingsUnits, "2\u00a0secondes"),
		formatIn("fr", "5400", settingsUnits, "1\u00a0heure et 30 minutes"),
		formatIn("fr", "86400", settingsUnits, "1\u00a0jour"),
		formatIn("fr", "90061", waitUnits, "25\u00a0heures, 1 minute et 1\u00a0seconde"),
		formatIn("fr", "59.6", waitUnits, "1 minute"),
		describeIn("fr", `"0"`, string(messages), "Utilise le paramètre global (1\u00a0heure et 30 minutes)"),
		describeIn("fr", `"x"`, string(messages), "Saisissez un nombre entier de secondes."),
		describeIn("fr", `"160000001"`, string(messages), "Cette durée est trop longue. Saisissez une durée plus courte."),
	}
	input, err := json.Marshal(map[string]any{"utils": utilsJS(t), "cases": cases})
	require.NoError(t, err)
	cmd := exec.CommandContext(t.Context(), "node", "-e", durationRun)
	cmd.Env = append(os.Environ(), "LC_ALL=de_DE.UTF-8")
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
	assert.Equal(t, "Patientez 1 minute avant de demander un nouveau code.",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[6].Value}))
}
