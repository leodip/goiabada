package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/leodip/goiabada/core/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The console's duration hints, the token tab's hint and the verification wait read Simplified
// Chinese for a page asking for zh-CN: the browser writes each unit joined to its number and the
// units joined to each other (1小时30分钟), the same unit at 1, 2 and 11, and the two sentences
// that embed a duration meet it with no space, as a number meets Chinese: the wait puts it after 等待
// and the global setting's hint inside full-width parentheses (#663 decision 4).
func TestSimplifiedChinese_DurationHintsTokenHintAndVerificationWait(t *testing.T) {
	ctx := i18n.WithLocale(context.Background(), true, "zh-CN")
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
		formatIn("zh-Hans", "0", settingsUnits, "0秒钟"),
		formatIn("zh-Hans", "1", settingsUnits, "1秒钟"),
		formatIn("zh-Hans", "2", settingsUnits, "2秒钟"),
		formatIn("zh-Hans", "11", settingsUnits, "11秒钟"),
		formatIn("zh-Hans", "5400", settingsUnits, "1小时30分钟"),
		formatIn("zh-Hans", "86400", settingsUnits, "1天"),
		formatIn("zh-Hans", "950400", settingsUnits, "11天"),
		formatIn("zh-Hans", "90061", waitUnits, "25小时1分钟1秒钟"),
		formatIn("zh-Hans", "59.6", waitUnits, "1分钟"),
		formatIn("zh-Hans", "660", waitUnits, "11分钟"),
		describeIn("zh-Hans", `"0"`, string(messages), "使用全局设置（1小时30分钟）"),
		describeIn("zh-Hans", `"x"`, string(messages), "请输入整数秒数。"),
		describeIn("zh-Hans", `"160000001"`, string(messages), "时长过长。请输入更短的时长。"),
		describeIn("zh-Hans", `"3600"`, string(messages), "1小时"),
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
	assert.Equal(t, "请等待1分钟后再请求新的验证码。",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[8].Value}))
	assert.Equal(t, "请等待11分钟后再请求新的验证码。",
		i18n.T(ctx, "adminconsole.account.email_verification.wait", map[string]any{"wait": answer.Answers[9].Value}))
}

// A searchable select's status in Simplified Chinese has one form, the count joined to its
// measure word, at zero as at 1, 2 and 11 (#663 decision 4).
func TestUtilsJS_SearchableStatusCountsTheMatchesInSimplifiedChinese(t *testing.T) {
	// Eleven zones. Each threshold's token marks the first that many of them, so the query for a
	// token matches exactly that many, and "zone" matches all 11.
	thresholds := []struct {
		token string
		count int
	}{{"qa", 1}, {"qb", 2}}
	options := []string{"请选择"}
	for i := 1; i <= 11; i++ {
		option := fmt.Sprintf("Asia/Zone %02d", i)
		for _, threshold := range thresholds {
			if i <= threshold.count {
				option += " " + threshold.token
			}
		}
		options = append(options, option)
	}
	runPlural(t, map[string]map[string]string{"zh-Hans": comboboxStrings("zh-Hans")}, []pluralCase{{
		Kind: "status", CatalogLang: tag("zh-Hans"), Strings: "zh-Hans", Options: options,
		Queries: []string{"zzz", "qa", "qb", "zone"},
		want:    []string{"0个匹配项", "1个匹配项", "2个匹配项", "11个匹配项"},
	}})
}
