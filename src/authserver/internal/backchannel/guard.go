package backchannel

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// notPublic is every range, beyond what netip classifies itself, that a delivery to a self-registered
// client may not dial (#784 decision 7): each block of the IANA IPv4 and IPv6 Special-Purpose Address
// Registries that is not globally reachable, the blocks that carry an IPv4 address into another
// network, and the deprecated blocks some networks still route. Loopback, private, link-local,
// unspecified, multicast and broadcast addresses are refused by publicUnicast directly.
//
// 192.0.0.0/24 and 2001::/23 are refused whole, though the registry marks a few anycast and
// identifier blocks inside them globally reachable: no app's receiver is at one of those.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" (RFC 791)
	netip.MustParsePrefix("100.64.0.0/10"),   // the shared address space of carrier-grade NAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments (RFC 6890)
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation (RFC 5737)
	netip.MustParsePrefix("192.88.99.0/24"),  // the retired 6to4 relay anycast (RFC 7526)
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // documentation (RFC 5737)
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation (RFC 5737)
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved (RFC 1112), which some networks use internally
	netip.MustParsePrefix("::/96"),           // IPv4-compatible, deprecated (RFC 4291)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use IPv4/IPv6 translation (RFC 8215)
	netip.MustParsePrefix("100::/64"),        // discard-only (RFC 6666)
	netip.MustParsePrefix("100:0:0:1::/64"),  // dummy prefix (RFC 9780)
	netip.MustParsePrefix("2001::/23"),       // IETF protocol assignments: Teredo, benchmarking, ORCHID (RFC 2928)
	netip.MustParsePrefix("2001:db8::/32"),   // documentation (RFC 3849)
	netip.MustParsePrefix("2002::/16"),       // 6to4, which carries an IPv4 address (RFC 3056)
	netip.MustParsePrefix("3fff::/20"),       // documentation (RFC 9637)
	netip.MustParsePrefix("5f00::/16"),       // SRv6 segment identifiers (RFC 9602)
	netip.MustParsePrefix("fec0::/10"),       // site-local, deprecated (RFC 3879)
}

// nat64 is the IPv4/IPv6 translation well-known prefix (RFC 6052). An address in it reaches, through
// a NAT64 gateway, the IPv4 address in its last 32 bits, so it is judged as that address: a
// deployment on IPv6 alone, with DNS64, reaches every IPv4-only app this way, and a gateway may
// translate to a private address as readily as to a public one.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// publicUnicast reports whether addr is a public unicast address, the only kind a delivery to a
// self-registered client may dial. An IPv4-mapped IPv6 address is judged as the IPv4 address it
// carries, so ::ffff:127.0.0.1 is loopback, and so is a NAT64 address, so 64:ff9b::a00:1 is private.
func publicUnicast(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if nat64.Contains(addr) {
		carried := addr.As16()
		addr = netip.AddrFrom4([4]byte(carried[12:]))
	}
	// IsGlobalUnicast is false for the unspecified, loopback, link-local, multicast and IPv4
	// broadcast addresses; IsPrivate is RFC 1918 and fc00::/7.
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range notPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// blockedAddressError is a dial the guard refused: the address a self-registered client's URI led
// to is not public unicast. It is final, since the same name leads there again.
type blockedAddressError struct {
	address string
}

func (e *blockedAddressError) Error() string {
	return fmt.Sprintf("the address %s is not a public unicast address, which a self-registered client's "+
		"back-channel logout URI must reach", e.address)
}

// addressBlocked reports whether err is the guard refusing the address dialed.
func addressBlocked(err error) bool {
	var blocked *blockedAddressError
	return errors.As(err, &blocked)
}

// guard is a dialer's Control: it runs once the name has been resolved, for each address the dialer
// is about to connect to, so the address checked is the address dialed and a name that resolves to
// a public address once and an internal one the next time (DNS rebinding) gains nothing.
func guard(permitted func(netip.Addr) bool) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		addrPort, err := netip.ParseAddrPort(address)
		if err != nil || !permitted(addrPort.Addr()) {
			return &blockedAddressError{address: address}
		}
		return nil
	}
}

// newDeliveryClients builds the two HTTP clients deliveries use, neither of which ever follows a
// redirect, since a 3xx is the app's answer (#784 decision 5), nor has a client-wide timeout, since
// each attempt has its own deadline. admin, for an administrator's client, reaches any address
// through proxy, the environment's, as the Turnstile client does. selfRegistered, for a client
// created through dynamic client registration, uses no proxy, so the address dialed is the app's,
// and dials only an address permitted admits (#784 decision 7).
func newDeliveryClients(proxy func(*http.Request) (*url.URL, error),
	permitted func(netip.Addr) bool) (admin, selfRegistered *http.Client) {

	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	adminTransport := http.DefaultTransport.(*http.Transport).Clone()
	adminTransport.Proxy = proxy

	// Its own transport, so no connection is ever shared with an administrator's client's; the
	// dialer is the default transport's but for its Control.
	guardedTransport := http.DefaultTransport.(*http.Transport).Clone()
	guardedTransport.Proxy = nil
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: guard(permitted)}
	guardedTransport.DialContext = dialer.DialContext

	return &http.Client{Transport: adminTransport, CheckRedirect: noRedirect},
		&http.Client{Transport: guardedTransport, CheckRedirect: noRedirect}
}
