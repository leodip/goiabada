package personname

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFullName holds the rule of #662 decision 1: a name whose given and family names are each
// written in Han, Hiragana, Katakana or Hangul reads family name first with no space, and every
// other name reads given, middle, family, joined by spaces, as it did before. Each expected name
// is written out by hand.
func TestFullName(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		givenName, middleName, familyName string
		want                              string
	}{
		// Family name first, with no space.
		{"kanji", "太郎", "", "山田", "山田太郎"},
		{"the kanji iteration mark", "希", "", "佐々木", "佐々木希"},
		{"a kana iteration mark", "みすゞ", "", "金子", "金子みすゞ"},
		{"a katakana letter in a kanji name", "光", "", "一ノ瀬", "一ノ瀬光"},
		{"the shime mark", "健", "", "〆木", "〆木健"},
		{"the prolonged sound mark", "ゆーり", "", "鈴木", "鈴木ゆーり"},
		{"the small ke", "千ヶ代", "", "田中", "田中千ヶ代"},
		{"the small ka", "太郎", "", "三ヵ尻", "三ヵ尻太郎"},
		{"a decomposed kana", "し\u3099ゅん", "", "山田", "山田し\u3099ゅん"},
		{"a kanji family name and a katakana given name", "マリア", "", "高橋", "高橋マリア"},
		{"a half-width katakana given name", "ｼﾞｭﾝ", "", "山田", "山田ｼﾞｭﾝ"},
		{"the half-width prolonged sound mark", "ﾙｰｼｰ", "", "山田", "山田ﾙｰｼｰ"},
		{"hangul", "민준", "", "김", "김민준"},
		{"chinese", "小明", "", "王", "王小明"},
		{"all three parts in the scripts", "太郎", "一", "山田", "山田太郎一"},
		// Only a part's letters are asked about: punctuation, a mark and a joiner the name rule
		// accepts leave it in the scripts.
		{"a hyphen and an apostrophe", "太-郎", "", "山'田", "山'田太-郎"},
		{"a katakana middle dot", "太郎・次郎", "", "山田", "山田太郎・次郎"},
		{"a middle dot", "小·明", "", "王", "王小·明"},
		{"a zero-width joiner and non-joiner", "太\u200d郎", "", "山\u200c田", "山\u200c田太\u200d郎"},

		// Two katakana names keep today's order, with their space.
		{"two katakana names", "ジョン", "", "スミス", "ジョン スミス"},
		{"two katakana names with a middle dot", "ジョン・ポール", "", "スミス", "ジョン・ポール スミス"},
		{"two half-width katakana names", "ｼﾞｮﾝ", "", "ｽﾐｽ", "ｼﾞｮﾝ ｽﾐｽ"},
		{"two katakana names with prolonged sound marks", "ジョージ", "", "ルーカス", "ジョージ ルーカス"},

		// Every other name reads as before.
		{"latin", "John", "", "Smith", "John Smith"},
		{"latin with a middle name", "Jane", "Q", "Doe", "Jane Q Doe"},
		{"latin with marks", "José", "", "García", "José García"},
		{"cyrillic", "Иван", "", "Петров", "Иван Петров"},
		{"scripts mixed between the parts", "太郎", "", "Yamada", "太郎 Yamada"},
		{"a latin given name and a kanji family name", "Taro", "", "山田", "Taro 山田"},
		{"a latin middle name between two kanji parts", "太郎", "John", "山田", "太郎 John 山田"},
		{"a part with a latin letter among the kanji", "太郎", "", "山田A", "太郎 山田A"},
		{"a given name alone", "太郎", "", "", "太郎"},
		{"a family name alone", "", "", "山田", "山田"},
		{"a middle name with a kanji family name", "", "一", "山田", "一 山田"},
		{"a latin given name alone", "Jane", "", "", "Jane"},
		{"a latin family name alone", "", "", "Doe", "Doe"},
		{"a latin middle name alone", "", "Q", "", "Q"},
		{"no name", "", "", "", ""},
		{"a part with no letter", "太郎", "", "・", "太郎 ・"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, FullName(tc.givenName, tc.middleName, tc.familyName))
		})
	}
}
