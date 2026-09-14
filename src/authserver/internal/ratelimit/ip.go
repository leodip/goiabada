package ratelimit

import "net/netip"

// CanonicalizeIP returns the rate-limiting key for a client address: an IPv4 address as
// itself, and an IPv6 address masked to its /64, so that a client cannot walk through a
// budget by moving within the prefix its ISP handed it.
//
// Anything that does not parse as an IP address is returned unchanged, the empty string
// included. Callers rely on that: the address reaching this function comes from a
// header or a socket peer and may be anything, and an unparseable value has to key as
// itself rather than collapse into one shared bucket with every other unparseable value.
//
// Two results differ from go-chi/httprate, which this replaced (#276):
//
//   - An IPv4-mapped address is unmapped first, so ::ffff:203.0.113.7 keys as
//     203.0.113.7 -- the same bucket the client gets when the proxy reports it in dotted
//     form. httprate masked it to ::, where every IPv4 client behind a dual-stack proxy
//     shared one bucket with loopback and with each other.
//   - A zone is dropped, so fe80::1%eth0 and fe80::1%eth1 share the fe80:: /64 where
//     httprate gave each zone string its own bucket. That is reachable only for a direct
//     link-local peer, whose RemoteAddr arrives here unparsed; a zoned entry in a
//     forwarded header is dropped before it gets this far.
//
// Note that ::ffff:0:203.0.113.7 is in the translated prefix ::ffff:0:0/96, not the
// mapped one, so it is not unmapped and still keys as ::, exactly as it did before.
func CanonicalizeIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr.WithZone(""), 64).Masked().Addr().String()
}
