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
// client may not dial (#784 decision 7): the shared address space of carrier-grade NAT (RFC 6598),
// and the documentation ranges (RFC 5737, RFC 3849 and RFC 9637). Loopback, private, link-local,
// unspecified, multicast and broadcast addresses are refused by publicUnicast directly.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("3fff::/20"),
}

// publicUnicast reports whether addr is a public unicast address, the only kind a delivery to a
// self-registered client may dial. An IPv4-mapped IPv6 address is judged as the IPv4 address it
// carries, so ::ffff:127.0.0.1 is loopback.
func publicUnicast(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
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
