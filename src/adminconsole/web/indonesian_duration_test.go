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

func TestIndonesian_DurationHintsAndVerificationWait(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "id-ID")
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
		formatIn("id", "0", settingsUnits, "0 detik"),
		formatIn("id", "1", settingsUnits, "1 detik"),
		formatIn("id", "2", settingsUnits, "2 detik"),
		formatIn("id", "5400", settingsUnits, "1 jam, 30 menit"),
		formatIn("id", "86400", settingsUnits, "1 hari"),
		formatIn("id", "90061", waitUnits, "25 jam, 1 menit, 1 detik"),
		formatIn("id", "59.6", waitUnits, "1 menit"),
		describeIn("id", `"0"`, string(messages), "Menggunakan pengaturan global (1 jam, 30 menit)"),
		describeIn("id", `"x"`, string(messages), "Masukkan bilangan bulat dalam detik."),
		describeIn("id", `"160000001"`, string(messages), "Itu terlalu lama. Masukkan durasi yang lebih pendek."),
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
	assert.Equal(t, "Tunggu 1 menit sebelum meminta kode lain.",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[6].Value}))
}
