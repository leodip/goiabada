package backchannel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/core/logging/logtest"
)

// TestPublicUnicast_RefusesEveryAddressThatIsNotPublicUnicast is #784 decision 7's list, each range
// at its edges, and the IPv4-mapped form of each: a delivery to a self-registered client reaches
// only a public unicast address. A NAT64 address is judged by the IPv4 address it carries.
func TestPublicUnicast_RefusesEveryAddressThatIsNotPublicUnicast(t *testing.T) {
	refused := map[string][]string{
		"loopback":                  {"127.0.0.1", "127.255.255.254", "::1"},
		"private (RFC 1918)":        {"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255"},
		"unique local (fc00::/7)":   {"fc00::", "fd12:3456:789a::1", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		"link-local":                {"169.254.0.0", "169.254.169.254", "169.254.255.255", "fe80::", "fe80::1", "febf:ffff::1"},
		"shared address space":      {"100.64.0.0", "100.100.100.200", "100.127.255.255"},
		"unspecified":               {"0.0.0.0", "::"},
		"multicast":                 {"224.0.0.1", "239.255.255.255", "ff02::1", "ff0e::1"},
		"broadcast":                 {"255.255.255.255"},
		"documentation":             {"192.0.2.1", "198.51.100.1", "203.0.113.255", "2001:db8::1", "3fff::1"},
		"this network (0.0.0.0/8)":  {"0.0.0.1", "0.1.2.3", "0.255.255.255"},
		"IETF protocol assignments": {"192.0.0.0", "192.0.0.8", "192.0.0.170", "192.0.0.255"},
		"6to4 relay anycast":        {"192.88.99.0", "192.88.99.255"},
		"benchmarking":              {"198.18.0.0", "198.18.0.1", "198.19.255.255", "2001:2::", "2001:2:0:ffff::1"},
		"reserved (240.0.0.0/4)":    {"240.0.0.0", "240.0.0.1", "255.255.255.254"},
		"IPv4-compatible":           {"::a00:1", "::808:808", "::ffff:ffff"},
		"local-use translation":     {"64:ff9b:1::", "64:ff9b:1::a00:1", "64:ff9b:1::808:808", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff"},
		"NAT64 to a non-public address": {
			"64:ff9b::", "64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::6440:1",
			"64:ff9b::c612:1", "64:ff9b::f000:1",
		},
		"discard-only and dummy":           {"100::", "100::ffff:ffff:ffff:ffff", "100:0:0:1::", "100:0:0:1:ffff:ffff:ffff:ffff"},
		"IETF protocol assignments (IPv6)": {"2001::", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:10::1", "2001:1ff:ffff:ffff::1"},
		"6to4":                             {"2002::", "2002:a00:1::1", "2002:808:808::1", "2002:ffff:ffff:ffff::1"},
		"SRv6 segment identifiers":         {"5f00::", "5f00::1", "5f00:ffff:ffff:ffff::1"},
		"site-local":                       {"fec0::", "fec0::1", "feff:ffff:ffff:ffff::1"},
		"IPv4-mapped loopback":             {"::ffff:127.0.0.1"},
		"IPv4-mapped private":              {"::ffff:10.0.0.1", "::ffff:172.16.0.1", "::ffff:192.168.1.1"},
		"IPv4-mapped link-local":           {"::ffff:169.254.169.254"},
		"IPv4-mapped shared":               {"::ffff:100.64.0.1"},
		"IPv4-mapped unspecified":          {"::ffff:0.0.0.0"},
		"IPv4-mapped multicast":            {"::ffff:224.0.0.1"},
		"IPv4-mapped broadcast":            {"::ffff:255.255.255.255"},
		"IPv4-mapped documentation":        {"::ffff:192.0.2.1", "::ffff:198.51.100.1", "::ffff:203.0.113.1"},
		"IPv4-mapped special-purpose": {
			"::ffff:0.1.2.3", "::ffff:192.0.0.8", "::ffff:192.88.99.1", "::ffff:198.18.0.1", "::ffff:240.0.0.1",
		},
	}
	for name, addresses := range refused {
		for _, address := range addresses {
			t.Run(name+" "+address, func(t *testing.T) {
				assert.False(t, publicUnicast(netip.MustParseAddr(address)), "%s is not public unicast", address)
			})
		}
	}

	// Just outside each range, and addresses on the internet.
	public := []string{
		"8.8.8.8", "1.1.1.1", "93.184.215.14",
		"11.0.0.0", "9.255.255.255",
		"172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0",
		"169.253.255.255", "169.255.0.0",
		"100.63.255.255", "100.128.0.0",
		"192.0.3.1", "198.51.101.1", "203.0.114.1",
		"1.0.0.0", "192.0.1.0", "192.88.98.255", "192.88.100.0", "198.17.255.255", "198.20.0.0",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
		"2001:200::1", "2001:1c00::1", "2003::1", "2001:db9::1",
		"::ffff:8.8.8.8",
		// NAT64 to a public IPv4 address, as DNS64 answers for an IPv4-only app.
		"64:ff9b::808:808", "64:ff9b::101:101",
	}
	for _, address := range public {
		t.Run("public "+address, func(t *testing.T) {
			assert.True(t, publicUnicast(netip.MustParseAddr(address)), "%s is public unicast", address)
		})
	}
}

// selfRegisteredTo is a delivery to a client created through dynamic client registration at uri.
func selfRegisteredTo(uri string) Delivery {
	delivery := confidential(uri)
	delivery.CreatedViaDCR = true
	return delivery
}

// tlsReceiver is the app's endpoint over https on 127.0.0.1, answering 200, and whether anything
// reached it.
type tlsReceiver struct {
	server  *httptest.Server
	mu      sync.Mutex
	reached int
}

func newTLSReceiver(t *testing.T) *tlsReceiver {
	t.Helper()
	rc := &tlsReceiver{}
	rc.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		rc.mu.Lock()
		rc.reached++
		rc.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(rc.server.Close)
	return rc
}

func (rc *tlsReceiver) count() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.reached
}

// trustReceiver makes the sender's clients trust rc's certificate, so only the address guard stands
// between a delivery and the receiver.
func (h *harness) trustReceiver(rc *tlsReceiver) {
	trusted := rc.server.Client().Transport.(*http.Transport).TLSClientConfig
	h.sender.client.Transport.(*http.Transport).TLSClientConfig = trusted.Clone()
	h.sender.selfRegisteredClient.Transport.(*http.Transport).TLSClientConfig = trusted.Clone()
}

// TestSend_ASelfRegisteredClientsInternalAddressIsBlocked: a delivery to a self-registered client
// whose URI dials loopback, by its literal or by a name that resolves to it, is refused at connect
// time, once and finally: nothing reaches the app, nothing is retried, and the delivery is recorded,
// counted and logged as blocked (#784 decisions 7 and 8).
func TestSend_ASelfRegisteredClientsInternalAddressIsBlocked(t *testing.T) {
	rc := newTLSReceiver(t)
	_, port, err := net.SplitHostPort(rc.server.Listener.Addr().String())
	require.NoError(t, err)

	for name, uri := range map[string]string{
		"an address":                   "https://127.0.0.1:" + port + "/backchannel-logout",
		"a name resolving to loopback": "https://localhost:" + port + "/backchannel-logout",
	} {
		t.Run(name, func(t *testing.T) {
			capture := logtest.CaptureSlog(t)
			h := newHarness(t)
			h.trustReceiver(rc)
			before := rc.count()

			h.sender.Send(context.Background(), testIssuer, []Delivery{selfRegisteredTo(uri)})

			assert.Equal(t, before, rc.count(), "the guard refuses the address before anything is sent")
			assert.Equal(t, "blocked", h.sent(t)["outcome"])
			assert.Equal(t, 1, h.sent(t)["attempts"])
			assert.Empty(t, h.slept, "a blocked address is final")
			assert.Contains(t, h.samples(t), `goiabada_backchannel_logout_deliveries_total{outcome="blocked"} 1`)

			var warns []logtest.CapturedRecord
			for _, rec := range capture.Records() {
				if rec.Level == slog.LevelWarn {
					warns = append(warns, rec)
				}
			}
			require.Len(t, warns, 1)
			assert.Equal(t, "blocked", warns[0].Attrs["outcome"])
			assert.Contains(t, fmt.Sprint(warns[0].Attrs["error"]), "is not a public unicast address")
		})
	}
}

// TestSend_AnAdministratorsClientReachesAnInternalAddress: the same https URI on loopback reaches an
// administrator's client, whose choice of address is trusted (#784 decision 7).
func TestSend_AnAdministratorsClientReachesAnInternalAddress(t *testing.T) {
	rc := newTLSReceiver(t)
	h := newHarness(t)
	h.trustReceiver(rc)

	h.sender.Send(context.Background(), testIssuer, []Delivery{confidential(rc.server.URL + "/backchannel-logout")})

	assert.Equal(t, 1, rc.count())
	assert.Equal(t, "delivered", h.sent(t)["outcome"])
}

// TestSend_ARecoverySenderGuardsSelfRegisteredClientsToo: the recover command's sender applies the
// same guard (#784 decision 11).
func TestSend_ARecoverySenderGuardsSelfRegisteredClientsToo(t *testing.T) {
	rc := newTLSReceiver(t)
	h := newHarness(t)
	sender := NewCommandSender(h.sender.database, h.sender.dataCipher, h.audit)
	h.sender = sender
	h.trustReceiver(rc)

	var got Outcome
	sender.SendAndWait(context.Background(), testIssuer, []Delivery{selfRegisteredTo(rc.server.URL)},
		func(_ Delivery, o Outcome) { got = o })

	assert.Equal(t, Blocked, got)
	assert.Equal(t, 0, rc.count())
}

// TestSend_SelfRegisteredDeliveriesNeverUseAProxy: an administrator's client is reached through the
// environment's proxy, and a self-registered client's never is, so the guard sees the address
// actually dialed (#784 decision 7). The guard admits loopback here, standing in for a public
// address the test cannot reach.
func TestSend_SelfRegisteredDeliveriesNeverUseAProxy(t *testing.T) {
	var mu sync.Mutex
	var proxied []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxied = append(proxied, r.Method+" "+r.Host)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)

	rc := newTLSReceiver(t)
	plain := newReceiver(t, http.StatusOK)
	h := newHarness(t)
	h.sender.client, h.sender.selfRegisteredClient = newDeliveryClients(http.ProxyURL(proxyURL),
		func(netip.Addr) bool { return true })
	h.trustReceiver(rc)

	h.sender.Send(context.Background(), testIssuer, []Delivery{
		confidential(plain.server.URL + "/backchannel-logout"),
		selfRegisteredTo(rc.server.URL + "/backchannel-logout"),
	})

	plainHost := strings.TrimPrefix(plain.server.URL, "http://")
	mu.Lock()
	assert.Equal(t, []string{"POST " + plainHost}, proxied, "only the administrator's client goes through the proxy")
	mu.Unlock()
	assert.Empty(t, plain.received(), "the proxy answered for it")
	assert.Equal(t, 1, rc.count(), "the self-registered client is dialed directly")
	require.Len(t, h.audit.events, 2)
	for _, event := range h.audit.events {
		assert.Equal(t, "delivered", event.details["outcome"])
	}
}
