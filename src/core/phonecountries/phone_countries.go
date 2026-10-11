// Package phonecountries is the phone-country vocabulary the auth server
// validates and stores: one entry per (country, E.164 calling code), built once
// at package initialization from core/countries.
//
// An entry's UniqueId is "<alpha3>_<index>", the index being the code's
// position in that country's calling codes. It is persisted on the user row
// (users.phone_number_country_uniqueid), so the order of a country's codes is
// part of the stored contract. Lookups are exact and case-sensitive (#432).
package phonecountries

import (
	"fmt"
	"slices"
	"sort"

	"github.com/leodip/goiabada/core/countries"
)

type PhoneCountry struct {
	UniqueId    string
	Alpha2      string
	Emoji       string
	CallingCode string
	Name        string
}

// phoneCountries is the whole list, sorted by country name, and byUniqueID
// indexes it. Both are built once and never written after initialization.
var (
	phoneCountries = build(countries.All())
	byUniqueID     = indexByUniqueID(phoneCountries)
)

// build turns countries into phone entries: sorted by name, then one entry per
// calling code in stored order. Nothing bounds the number of codes a country
// may have; the id column holds any index this dataset could produce.
func build(allCountries []countries.Country) []PhoneCountry {
	sort.Slice(allCountries, func(i, j int) bool {
		return allCountries[i].Name < allCountries[j].Name
	})

	list := []PhoneCountry{}
	for _, c := range allCountries {
		for i, code := range c.CallingCodes {
			// countries.Country stores calling codes as digits without '+';
			// prepend it so labels, the API callingCode, and the persisted
			// User.PhoneNumberCountryCallingCode all keep the "+NN" form.
			callingCode := "+" + code
			list = append(list, PhoneCountry{
				UniqueId:    fmt.Sprintf("%v_%v", c.Alpha3, i),
				Alpha2:      c.Alpha2,
				Emoji:       c.Emoji,
				CallingCode: callingCode,
				Name:        fmt.Sprintf("%v - %v (%v)", c.Emoji, c.Name, callingCode),
			})
		}
	}
	return list
}

func indexByUniqueID(list []PhoneCountry) map[string]PhoneCountry {
	index := make(map[string]PhoneCountry, len(list))
	for _, pc := range list {
		index[pc.UniqueId] = pc
	}
	return index
}

// All returns every phone country, sorted by country name. The slice is a
// fresh copy on every call, so a caller may sort or modify it freely.
func All() []PhoneCountry {
	return slices.Clone(phoneCountries)
}

// ByUniqueID returns the phone country with that UniqueId, and false when none
// has it.
func ByUniqueID(id string) (PhoneCountry, bool) {
	pc, ok := byUniqueID[id]
	return pc, ok
}
