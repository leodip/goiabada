package emaildelivery

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/hostport/hostporttest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// greetings is every EHLO and HELO line the client sent, in order.
func (f *fakeSMTP) greetings() []string {
	var out []string
	for _, l := range f.lines() {
		up := strings.ToUpper(l)
		if strings.HasPrefix(up, "EHLO") || strings.HasPrefix(up, "HELO") {
			out = append(out, l)
		}
	}
	return out
}

// TestSendEmail_EHLOName is #718 decision 9 on the wire: the client introduces itself by the name
// the sender was built with, or, without one, by the address of its own end of the connection
// written as an RFC 5321 section 4.1.3 address literal. The name is the same in the first EHLO, in
// the EHLO RFC 3207 section 4.2 has the client repeat after STARTTLS, and in the HELO a relay that
// refuses EHLO is greeted with (RFC 5321 section 4.1.4).
func TestSendEmail_EHLOName(t *testing.T) {

	cert := newFakeCert(t)

	tests := []struct {
		name       string
		host       string
		ehloName   string
		encryption string
		ext        []string
		tlsExt     []string
		refuseEHLO bool
		want       []string
	}{
		{
			name: "a configured domain", host: "127.0.0.1", ehloName: "mail.example.com",
			encryption: "none", ext: []string{"8BITMIME"},
			want: []string{"EHLO mail.example.com"},
		},
		{
			name: "a configured domain keeps the case typed", host: "127.0.0.1", ehloName: "Relay-1.Example.COM",
			encryption: "none", ext: []string{"8BITMIME"},
			want: []string{"EHLO Relay-1.Example.COM"},
		},
		{
			name: "a configured address literal", host: "127.0.0.1", ehloName: "[192.0.2.10]",
			encryption: "none", ext: []string{"8BITMIME"},
			want: []string{"EHLO [192.0.2.10]"},
		},
		{
			name: "a configured domain, again after STARTTLS", host: "127.0.0.1", ehloName: "mail.example.com",
			encryption: "starttls", ext: []string{"STARTTLS", "8BITMIME"}, tlsExt: []string{"8BITMIME"},
			want: []string{"EHLO mail.example.com", "EHLO mail.example.com"},
		},
		{
			name: "a configured domain, in HELO when the relay refuses EHLO", host: "127.0.0.1", ehloName: "mail.example.com",
			encryption: "none", refuseEHLO: true,
			want: []string{"EHLO mail.example.com", "HELO mail.example.com"},
		},
		{
			name: "unset, the local IPv4 address", host: "127.0.0.1",
			encryption: "none", ext: []string{"8BITMIME"},
			want: []string{"EHLO [127.0.0.1]"},
		},
		{
			name: "unset, the local address again after STARTTLS", host: "127.0.0.1",
			encryption: "starttls", ext: []string{"STARTTLS", "8BITMIME"}, tlsExt: []string{"8BITMIME"},
			want: []string{"EHLO [127.0.0.1]", "EHLO [127.0.0.1]"},
		},
		{
			name: "unset, the local address in HELO when the relay refuses EHLO", host: "127.0.0.1",
			encryption: "none", refuseEHLO: true,
			want: []string{"EHLO [127.0.0.1]", "HELO [127.0.0.1]"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := &fakeSMTP{ext: test.ext, tlsExt: test.tlsExt, refuseEHLO: test.refuseEHLO, cert: cert}
			port := f.start(t)

			sender := NewSender(testDataCipher, test.ehloName)
			sender.rootCAs = cert.pool

			err := sendTo(t, sender, relayConfig(t, test.host, port, test.encryption, "", "", "Goiabada"))
			require.NoError(t, err)

			assert.Equal(t, test.want, f.greetings())
			assert.NotEmpty(t, f.data(), "the message reached the relay")
		})
	}
}

// TestSendEmail_EHLONameOverIPv6 is the default's IPv6 form: RFC 5321 section 4.1.3's IPv6 tag
// before the address, which ::1 makes `[IPv6:::1]`.
func TestSendEmail_EHLONameOverIPv6(t *testing.T) {
	hostporttest.SkipWithoutIPv6Loopback(t)

	f := &fakeSMTP{ext: []string{"8BITMIME"}}
	port := f.start(t)

	err := sendTo(t, NewSender(testDataCipher, ""), relayConfig(t, "::1", port, "none", "", "", "Goiabada"))
	require.NoError(t, err)

	assert.Equal(t, []string{"EHLO [IPv6:::1]"}, f.greetings())
}
