package brandkit

import "strings"

// FooterLinkLabel answers the label a brand's footer link is drawn with on a page written in lang,
// the tag its html element's lang attribute names: the link's own label for that language, else its
// fallback label (#814 decisions 5 and 9). A language the link has no label for, a language only an
// override catalog adds among them, takes the fallback, and the tag is compared exactly, as the
// labels are stored under the built-in catalogs' own tags. The auth server's pages and the admin
// console's pick a label by it, so a link reads alike on both.
func FooterLinkLabel(label string, labels map[string]string, lang string) string {
	if own := labels[lang]; strings.TrimSpace(own) != "" {
		return own
	}
	return label
}

// MailtoAddress answers address as the "to" of a mailto: URI carries it, a page linking it as
// "mailto:" followed by the answer (#814 decision 1). RFC 6068 section 2 says the characters of an
// addr-spec that cannot appear in a URI MUST be percent-encoded, as must "%", the gen-delims but "@"
// and ":", and "&", ";" and "="; every byte but those of an unreserved character and the remaining
// some-delims ("!", "$", "'", "(", ")", "*", "+", ",", ":" and "@") is therefore written as %XX,
// UTF-8 bytes included. An account's address may hold "%", which a mail program would otherwise read
// as the start of an escape.
func MailtoAddress(address string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(address); i++ {
		c := address[i]
		if mailtoKeeps(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0x0f])
	}
	return b.String()
}

// mailtoKeeps reports whether c is written as itself in a mailto: URI's addr-spec: an unreserved
// character (RFC 3986 section 2.3) or one of RFC 6068's some-delims but ";".
func mailtoKeeps(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~!$'()*+,:@", c) >= 0
}
