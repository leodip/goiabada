package ratelimit

import "testing"

// TestCanonicalizeIP is the table go-chi/httprate's CanonicalizeIP was probed against
// before it was retired. Every row matches what httprate answered except the three
// marked, which are the deliberate departures (#276).
func TestCanonicalizeIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
		note string
	}{
		{in: "203.0.113.7", want: "203.0.113.7"},
		{in: "2001:db8:1:2:3:4:5:6", want: "2001:db8:1:2::"},
		{in: "2001:db8:1:2::", want: "2001:db8:1:2::"},
		{in: "::1", want: "::"},
		{in: "2001:DB8::1", want: "2001:db8::"},
		{in: "[2001:db8::1]", want: "[2001:db8::1]", note: "brackets do not parse, so the value keys as itself"},
		{in: "", want: "", note: "an absent address keys as itself, not as a shared bucket"},
		{in: "not-an-ip", want: "not-an-ip"},
		{
			in:   "::ffff:203.0.113.7",
			want: "203.0.113.7",
			note: "departure: unmapped first, so it shares the bucket of the dotted form. httprate gave ::",
		},
		{
			in:   "::FFFF:203.0.113.7",
			want: "203.0.113.7",
			note: "departure: the same address in uppercase hex reaches the same bucket",
		},
		{
			in:   "fe80::1%eth0",
			want: "fe80::",
			note: "departure: the zone is dropped. httprate left the whole string untouched",
		},
		{
			in:   "::ffff:0:203.0.113.7",
			want: "::",
			note: "the translated prefix ::ffff:0:0/96, not the mapped one, so it is not unmapped",
		},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := CanonicalizeIP(tc.in)
			if got != tc.want {
				if tc.note != "" {
					t.Errorf("CanonicalizeIP(%q) = %q, want %q (%s)", tc.in, got, tc.want, tc.note)
					return
				}
				t.Errorf("CanonicalizeIP(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
