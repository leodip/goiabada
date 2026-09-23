package models

import "github.com/leodip/goiabada/core/errs"

// KeyState is where a signing key sits in the rotation, carried on key_pairs.state as its String
// value. It is here rather than in signingkeys, which performs the rotation, because
// data/commondb/key_pair.go builds a SQL WHERE from KeyStateCurrent, and data imports nothing
// above models (#385).
type KeyState int

const (
	KeyStateCurrent KeyState = iota
	KeyStatePrevious
	KeyStateNext
)

// String returns the wire value, or "" for a KeyState outside the declared range, rather than
// panicking on the slice index. Not reachable from any int conversion today -- every production
// value is one of the three constants -- but the guard goes on the type so the next caller that
// converts a column or a form value cannot step on it (#385).
func (ks KeyState) String() string {
	if ks < KeyStateCurrent || ks > KeyStateNext {
		return ""
	}
	return []string{"current", "previous", "next"}[ks]
}

func KeyStateFromString(s string) (KeyState, error) {
	switch s {
	case KeyStateCurrent.String():
		return KeyStateCurrent, nil
	case KeyStatePrevious.String():
		return KeyStatePrevious, nil
	case KeyStateNext.String():
		return KeyStateNext, nil
	}
	return KeyStateCurrent, errs.New("invalid key state " + s)
}
