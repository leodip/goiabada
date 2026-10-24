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

func TestItalian_DurationHintsAndVerificationWait(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "it-CH")
	messages, err := json.Marshal(map[string]string{
		"durationInvalid": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_invalid"),
		"durationTooLong": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_too_long"),
		"durationZero":    i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_zero"),
		"durationGlobal":  "5400",
	})
	require.NoError(t, err)
	cases := []durationCase{
		formatIn("it", "0", settingsUnits, "0 secondi"),
		formatIn("it", "1", settingsUnits, "1 secondo"),
		formatIn("it", "2", settingsUnits, "2 secondi"),
		formatIn("it", "5400", settingsUnits, "1 ora e 30 minuti"),
		formatIn("it", "86400", settingsUnits, "1 giorno"),
		formatIn("it", "90061", waitUnits, "25 ore, 1 minuto e 1 secondo"),
		formatIn("it", "59.6", waitUnits, "1 minuto"),
		describeIn("it", `"0"`, string(messages), "Usa l'impostazione globale (1 ora e 30 minuti)"),
		describeIn("it", `"x"`, string(messages), "Inserisci un numero intero di secondi."),
		describeIn("it", `"160000001"`, string(messages), "La durata è troppo lunga. Inseriscine una più breve."),
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
	assert.Equal(t, "Attendi 1 minuto prima di richiedere un altro codice.",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[6].Value}))
}
