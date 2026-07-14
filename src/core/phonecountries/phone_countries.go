package phonecountries

import (
	"fmt"
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

func Get() []PhoneCountry {
	phoneCountries := []PhoneCountry{}

	allCountries := countries.AllInfo()
	sort.Slice(allCountries, func(i, j int) bool {
		return allCountries[i].Name < allCountries[j].Name
	})

	for _, c := range allCountries {
		if len(c.CallingCodes) > 5 {
			panic(fmt.Sprintf("Unsupported: country %v has more than 5 calling codes", c.Name))
		}

		for i, code := range c.CallingCodes {
			// countries.Country stores calling codes as digits without '+';
			// prepend it so labels, the API callingCode, and the persisted
			// User.PhoneNumberCountryCallingCode all keep the "+NN" form.
			callingCode := "+" + code
			phoneCountries = append(phoneCountries, PhoneCountry{
				UniqueId:    fmt.Sprintf("%v_%v", c.Alpha3, i),
				Alpha2:      c.Alpha2,
				Emoji:       c.Emoji,
				CallingCode: callingCode,
				Name:        fmt.Sprintf("%v - %v (%v)", c.Emoji, c.Name, callingCode),
			})
		}
	}

	return phoneCountries
}
