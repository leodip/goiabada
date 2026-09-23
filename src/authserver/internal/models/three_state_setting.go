package models

import "github.com/leodip/goiabada/core/errs"

// ThreeStateSetting is a per-client override of a global setting: on, off, or defer to the global
// value. It is carried as its String value on the client columns that can be overridden. It is
// here rather than in core because no admin console file names one in production (#385), and
// rather than in any one consumer because it is the vocabulary of two Client columns that four
// packages name: the client API handlers and the DCR handler write it, bootstrap seeds it, and
// issuance reads it (#424).
type ThreeStateSetting int

const (
	ThreeStateSettingOn ThreeStateSetting = iota
	ThreeStateSettingOff
	ThreeStateSettingDefault
)

// String returns the wire value, or "" for a ThreeStateSetting outside the declared range, rather
// than panicking on the slice index. Not reachable from any int conversion today, but the guard
// goes on the type so the next caller that converts a column or a form value cannot step on it
// (#385).
func (tss ThreeStateSetting) String() string {
	if tss < ThreeStateSettingOn || tss > ThreeStateSettingDefault {
		return ""
	}
	return []string{"on", "off", "default"}[tss]
}

func ThreeStateSettingFromString(s string) (ThreeStateSetting, error) {
	switch s {
	case ThreeStateSettingOn.String():
		return ThreeStateSettingOn, nil
	case ThreeStateSettingOff.String():
		return ThreeStateSettingOff, nil
	case ThreeStateSettingDefault.String():
		return ThreeStateSettingDefault, nil
	}
	return ThreeStateSettingOn, errs.New("invalid three state setting " + s)
}
