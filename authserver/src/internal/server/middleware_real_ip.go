package server

import (
	"net"
	"net/http"
	"strings"

	"github.com/leodip/goiabada/internal/lib"
)

func MiddlewareRealIp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
			addresses := strings.Split(r.Header.Get(h), ",")
			// march from right to left until we get a public address
			// that will be the address right before our proxy.
			for i := len(addresses) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(addresses[i])
				if ip == "" {
					continue
				}
				// header can contain spaces too, strip those out.
				realIP := net.ParseIP(ip)
				if !realIP.IsGlobalUnicast() || lib.IsPrivateSubnet(realIP) {
					// bad address, go to next
					continue
				}

				if len(ip) > 0 {
					r.RemoteAddr = ip
					break
				}

			}
		}
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}
