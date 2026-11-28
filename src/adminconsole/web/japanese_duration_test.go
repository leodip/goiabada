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

// The console's duration hints and the verification wait read Japanese for a page asking for
// ja-JP: the browser writes each unit with a half-width space after its number and between the
// units (1 時間 30 分), the same unit at 1, 2 and 11, and the two sentences that embed a duration
// meet it with no space, as a Japanese word or a full-width mark meets a Japanese word: the wait
// puts it before 後に and the global setting's hint inside full-width parentheses (#662 decision 6).
func TestJapanese_DurationHintsAndVerificationWait(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "ja-JP")
	messages, err := json.Marshal(map[string]string{
		"durationInvalid": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_invalid"),
		"durationTooLong": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_too_long"),
		"durationZero":    i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_zero"),
		"durationZeroGlobal": i18n.T(ctx, "adminconsole.admin_clients.tokens.duration_zero_global",
			map[string]any{"duration": "{duration}"}),
		"durationGlobal": "5400",
	})
	require.NoError(t, err)
	cases := []durationCase{
		formatIn("ja", "0", settingsUnits, "0 秒"),
		formatIn("ja", "1", settingsUnits, "1 秒"),
		formatIn("ja", "2", settingsUnits, "2 秒"),
		formatIn("ja", "11", settingsUnits, "11 秒"),
		formatIn("ja", "5400", settingsUnits, "1 時間 30 分"),
		formatIn("ja", "86400", settingsUnits, "1 日"),
		formatIn("ja", "950400", settingsUnits, "11 日"),
		formatIn("ja", "90061", waitUnits, "25 時間 1 分 1 秒"),
		formatIn("ja", "59.6", waitUnits, "1 分"),
		formatIn("ja", "660", waitUnits, "11 分"),
		describeIn("ja", `"0"`, string(messages), "グローバル設定を使用（1 時間 30 分）"),
		describeIn("ja", `"x"`, string(messages), "秒数を整数で入力してください。"),
		describeIn("ja", `"160000001"`, string(messages), "長すぎます。より短い期間を入力してください。"),
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
	assert.Equal(t, "1 分後に、もう一度コードをリクエストできます。",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[8].Value}))
	assert.Equal(t, "11 分後に、もう一度コードをリクエストできます。",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[9].Value}))
}
