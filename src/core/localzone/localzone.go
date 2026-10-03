// Package localzone resolves the process's local time zone from TZ, and is the one place in this
// tree that does.
//
// Go resolves TZ once, the first time anything asks for the local zone, and both servers embed
// the zone database (time/tzdata) so that a name resolves on a host without one. The embedded
// copy registers itself during package initialization, and github.com/BurntSushi/toml, which
// core/i18n imports, asks for the local zone in a package-level initializer that runs first. So
// on a host with no zone database the local zone would be fixed at UTC whatever TZ said, and a TZ
// the runtime could not load would give UTC in silence everywhere (#331).
//
// Install, called by each server's main before its first record, resolves TZ again once the
// embedded database is reachable, and refuses a value that names no zone.
package localzone

import (
	"os"
	"strings"
	"time"

	"github.com/leodip/goiabada/core/errs"
)

// Install reads TZ the way Go's runtime does and installs the zone it names as time.Local, or
// answers why it cannot.
//
//   - Unset, it leaves the local zone as the runtime read it from the host, as before. Empty, or a
//     lone colon, it installs UTC: the Unix runtime already reads it so, but the Windows one reads
//     the zone from the operating system and never consults TZ.
//   - One leading colon is dropped, the implementation-defined POSIX form (XBD 8.3) Go accepts.
//   - A value starting with "/" is a zone file on the host's filesystem, never looked up in the
//     embedded database, where it means nothing. One that does not load is refused, where Go's
//     runtime falls back to UTC.
//   - Anything else is a zone name, found in the host's database or the embedded one. Local, which
//     time.LoadLocation accepts but which names no zone, is refused like any name that is no zone.
//
// It is called before the first record, so a refusal is one line on stderr and exit 2, which is
// what a malformed configuration variable gets.
func Install() error {
	tz, ok := os.LookupEnv("TZ")
	if !ok {
		return nil
	}
	name := strings.TrimPrefix(tz, ":")
	if name == "" {
		time.Local = time.UTC
		return nil
	}

	if strings.HasPrefix(name, "/") {
		data, err := os.ReadFile(name) //nolint:gosec // G304: the path is the operator's own TZ, which Go's runtime reads the same way
		if err != nil {
			return errs.Errorf("TZ is %q, a zone file that does not load: %v", tz, err)
		}
		// The name Go's runtime gives the same file, so the zone the process reports is unchanged.
		locationName := name
		if name == "/etc/localtime" {
			locationName = "Local"
		}
		location, err := time.LoadLocationFromTZData(locationName, data)
		if err != nil {
			return errs.Errorf("TZ is %q, a zone file that does not load: %v", tz, err)
		}
		time.Local = location
		return nil
	}

	if name == "Local" {
		return errs.Errorf("TZ is %q, which names no time zone", tz)
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return errs.Errorf("TZ is %q, which names no time zone", tz)
	}
	time.Local = location
	return nil
}
