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
	Clients   []string
}

// SessionInfos maps the API's sessions to the rows both session pages render, newest id first.
// IsCurrent is the response's: the auth server computes it from the sid of the very token the
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
		})
	}

	sort.Slice(infos, func(i, j int) bool {
		return infos[i].UserSessionId > infos[j].UserSessionId
	})

	return infos
}

// ConsentInfo is one row of the account consents page and of the admin user consents page.
type ConsentInfo struct {
	ConsentId         int64
	Client            string
	ClientDescription string
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
			ConsentId:         c.Id,
			Client:            c.ClientIdentifier,
			ClientDescription: c.ClientDescription,
			Scope:             c.Scope,
			// grantedAt is nullable on the wire, where the column it comes from is not:
			// a consent row always records when it was granted, so an absent value is a
			// response this console cannot date rather than an ungranted consent (#350).
			GrantedAt: c.GrantedAt,
		})
	}

	return infos
}
