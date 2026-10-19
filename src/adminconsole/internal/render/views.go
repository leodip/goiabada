package render

import (
	"sort"
	"time"

	"github.com/leodip/goiabada/core/api"
)

// SessionInfo is one row of the account sessions page and of the admin user sessions page, which
// render the same fields. The client sessions page keeps its own, because its rows also name the
// user each session belongs to (#440).
type SessionInfo struct {
	UserSessionId int64
	IsCurrent     bool
	// Started and LastAccessed are the instants themselves rather than pre-rendered text: the
	// page formats them with the DateTime and Since template functions, which read the layout
	// and the relative phrase from the viewer's catalog. Formatting them here produced an
	// English RFC1123 date beside a Go duration string under every locale, because Go's
	// time.Format has no locale and Duration.String() is not anybody's language (#373).
	Started      *time.Time
	LastAccessed *time.Time
	IpAddress    string
	DeviceName   string
	DeviceType   string
	DeviceOS     string
	// UserAgent is the raw header, shown as the Device cell's tooltip so two sessions
	// whose labels read alike can still be told apart (#281).
	UserAgent string
	// Clients are the identifiers, which the admin page shows; ClientNames the same clients as
	// their user is shown them, which the account page shows.
	Clients     []string
	ClientNames []ClientName
}

// ClientName is a client as its user is shown it, by the consent screen: the name, and whether
// that name is the client's own claim about itself, which a page marks as unverified (#108).
type ClientName struct {
	Name       string
	Unverified bool
}

// SessionInfos maps the API's sessions to the rows both session pages render: the session of the
// device in use first, then the others by when each was last active, the most recent first, a
// newer session first between two last active at once. IsCurrent is the response's: the auth server computes it from the sid of the very token the
// console forwards, so there is one place that decides it (#373).
func SessionInfos(sessions []api.UserSessionDetailResponse) []SessionInfo {
	infos := make([]SessionInfo, 0, len(sessions))
	for _, s := range sessions {
		infos = append(infos, SessionInfo{
			UserSessionId: s.Id,
			IsCurrent:     s.IsCurrent,
			Started:       s.Started,
			LastAccessed:  s.LastAccessed,
			IpAddress:     s.IpAddress,
			DeviceName:    s.DeviceName,
			DeviceType:    s.DeviceType,
			DeviceOS:      s.DeviceOS,
			UserAgent:     s.UserAgent,
			Clients:       s.ClientIdentifiers,
			ClientNames:   clientNames(s.Clients),
		})
	}

	sort.Slice(infos, func(i, j int) bool {
		a, b := infos[i], infos[j]
		if a.IsCurrent != b.IsCurrent {
			return a.IsCurrent
		}
		if !lastAccessed(a).Equal(lastAccessed(b)) {
			return lastAccessed(a).After(lastAccessed(b))
		}
		return a.UserSessionId > b.UserSessionId
	})

	return infos
}

// lastAccessed is when a session was last active, the zero instant when the response did not say,
// which sorts it last.
func lastAccessed(s SessionInfo) time.Time {
	if s.LastAccessed == nil {
		return time.Time{}
	}
	return *s.LastAccessed
}

// clientNames maps a session's clients to the names their user is shown for them.
func clientNames(clients []api.SessionClientResponse) []ClientName {
	names := make([]ClientName, 0, len(clients))
	for _, c := range clients {
		names = append(names, ClientName{Name: c.Name, Unverified: c.NameUnverified})
	}
	return names
}

// ConsentInfo is one row of the account consents page and of the admin user consents page. Client
// is the identifier, which the admin page shows; ClientName and ClientNameUnverified are the name
// the consent screen showed the user, which the account page shows.
type ConsentInfo struct {
	ConsentId            int64
	Client               string
	ClientName           string
	ClientNameUnverified bool
	ClientDescription    string
	// GrantedAt is the instant rather than pre-rendered text, for the reason SessionInfo's
	// two carry theirs: formatting here produced an English RFC1123 date under every
	// locale, because Go's time.Format has no locale of its own (#373).
	GrantedAt *time.Time
	Scope     string
}

// ConsentInfos maps the API's consents to the rows both consent pages render, in the API's order.
func ConsentInfos(consents []api.UserConsentResponse) []ConsentInfo {
	infos := make([]ConsentInfo, 0, len(consents))
	for _, c := range consents {
		infos = append(infos, ConsentInfo{
			ConsentId:            c.Id,
			Client:               c.ClientIdentifier,
			ClientName:           c.ClientName,
			ClientNameUnverified: c.ClientNameUnverified,
			ClientDescription:    c.ClientDescription,
			Scope:                c.Scope,
			// grantedAt is nullable on the wire, where the column it comes from is not:
			// a consent row always records when it was granted, so an absent value is a
			// response this console cannot date rather than an ungranted consent (#350).
			GrantedAt: c.GrantedAt,
		})
	}

	return infos
}
