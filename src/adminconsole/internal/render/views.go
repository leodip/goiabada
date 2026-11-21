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
	UserSessionID int64
	IsCurrent     bool
	// Started and LastAccessed are the instants themselves rather than pre-rendered text: the
	// page formats them with the DateTime and Since template functions, which read the layout
	// and the relative phrase from the viewer's catalog. Formatting them here produced an
	// English RFC1123 date beside a Go duration string under every locale, because Go's
	// time.Format has no locale and Duration.String() is not anybody's language (#373).
	Started      *time.Time
	LastAccessed *time.Time
	IPAddress    string
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
			UserSessionID: s.ID,
			IsCurrent:     s.IsCurrent,
			Started:       s.Started,
			LastAccessed:  s.LastAccessed,
			IPAddress:     s.IPAddress,
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
		return SessionListedBefore(a.IsCurrent, a.LastAccessed, a.UserSessionID, b.IsCurrent, b.LastAccessed, b.UserSessionID)
	})

	return infos
}

// SessionListedBefore says whether session a goes before session b in a list of sessions, as every
// session page lists them: the session of the device in use first, then the others by when each was
// last active, the most recent first, a newer session first between two last active at once.
func SessionListedBefore(aCurrent bool, aLastAccessed *time.Time, aID int64, bCurrent bool, bLastAccessed *time.Time, bID int64) bool {
	if aCurrent != bCurrent {
		return aCurrent
	}
	if !lastAccessed(aLastAccessed).Equal(lastAccessed(bLastAccessed)) {
		return lastAccessed(aLastAccessed).After(lastAccessed(bLastAccessed))
	}
	return aID > bID
}

// lastAccessed is when a session was last active, the zero instant when the response did not say,
// which sorts it last.
func lastAccessed(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// clientNames maps a session's clients to the names their user is shown for them.
func clientNames(clients []api.SessionClientResponse) []ClientName {
	names := make([]ClientName, 0, len(clients))
	for _, c := range clients {
		names = append(names, ClientName{Name: c.Name, Unverified: c.NameUnverified})
	}
	return names
}

// ConnectedClientInfo is one row of the account Applications page and of a user's Connected
// clients tab: a client the user holds a stored consent with, a live refresh token with, or both
// (#135 decision 4). Client is the identifier; ClientName and ClientNameUnverified are the name the
// consent screen shows the user, which the account page shows, and the admin tab shows beside the
// identifier when it is neither the identifier nor the description.
// HasConsent says whether the client has a stored consent, ConsentScope and GrantedAt being that
// consent's; GrantScope is the scopes the user's live refresh tokens with it record. The page shows
// each scope list under its own label, since either can hold a scope the other lacks (decision 7).
// IsCurrent marks the client the caller's own token was issued to, on the caller's own user, which
// neither page offers a Disconnect for (decision 5).
type ConnectedClientInfo struct {
	ClientID             int64
	Client               string
	ClientName           string
	ClientNameUnverified bool
	ClientDescription    string
	HasConsent           bool
	ConsentScope         string
	// GrantedAt is the instant rather than pre-rendered text, for the reason SessionInfo's two
	// carry theirs: Go's time.Format has no locale of its own (#373). It is nil for a consent
	// that recorded no time, which the page renders as an empty cell (#350).
	GrantedAt  *time.Time
	GrantScope string
	IsCurrent  bool
}

// ConnectedClientInfos maps the API's connected clients to the rows the page renders, in the API's
// order.
func ConnectedClientInfos(clients []api.ConnectedClientResponse) []ConnectedClientInfo {
	infos := make([]ConnectedClientInfo, 0, len(clients))
	for _, c := range clients {
		info := ConnectedClientInfo{
			ClientID:             c.ClientID,
			Client:               c.ClientIdentifier,
			ClientName:           c.ClientName,
			ClientNameUnverified: c.ClientNameUnverified,
			ClientDescription:    c.ClientDescription,
			GrantScope:           c.GrantScope,
			IsCurrent:            c.IsCurrent,
		}
		if c.Consent != nil {
			info.HasConsent = true
			info.ConsentScope = c.Consent.Scope
			info.GrantedAt = c.Consent.GrantedAt
		}
		infos = append(infos, info)
	}

	return infos
}
