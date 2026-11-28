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

// The console's duration hints and the verification wait read Russian for a page asking for ru-RU:
// the browser writes each unit in the nominative, by the count's category (1 секунда, 2 секунды,
// 5 секунд, 11 секунд, 21 секунда, 22 секунды, 25 секунд), with no conjunction between the units,
// and the one sentence that embeds a duration puts it after a colon (#666 decision 5).
func TestRussian_DurationHintsAndVerificationWait(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "ru-RU")
	messages, err := json.Marshal(map[string]string{
		"durationInvalid": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_invalid"),
		"durationTooLong": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_too_long"),
		"durationZero":    i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_zero"),
		"durationGlobal":  "5400",
	})
	require.NoError(t, err)
	cases := []durationCase{
		formatIn("ru", "0", settingsUnits, "0 секунд"),
		formatIn("ru", "1", settingsUnits, "1 секунда"),
		formatIn("ru", "2", settingsUnits, "2 секунды"),
		formatIn("ru", "5", settingsUnits, "5 секунд"),
		formatIn("ru", "11", settingsUnits, "11 секунд"),
		formatIn("ru", "21", settingsUnits, "21 секунда"),
		formatIn("ru", "22", settingsUnits, "22 секунды"),
		formatIn("ru", "25", settingsUnits, "25 секунд"),
		formatIn("ru", "5400", settingsUnits, "1 час 30 минут"),
		formatIn("ru", "86400", settingsUnits, "1 день"),
		formatIn("ru", "1814400", settingsUnits, "21 день"),
		formatIn("ru", "90061", waitUnits, "25 часов 1 минута 1 секунда"),
		formatIn("ru", "59.6", waitUnits, "1 минута"),
		formatIn("ru", "1260", waitUnits, "21 минута"),
		describeIn("ru", `"0"`, string(messages), "Используется глобальная настройка (1 час 30 минут)"),
		describeIn("ru", `"x"`, string(messages), "Введите целое число секунд."),
		describeIn("ru", `"160000001"`, string(messages), "Слишком долго. Введите меньшую длительность."),
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
	assert.Equal(t, "До следующего запроса кода: 1 минута.",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[12].Value}))
	assert.Equal(t, "До следующего запроса кода: 21 минута.",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[13].Value}))
}
