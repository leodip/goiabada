package phonecountries

import (
	"fmt"
	"sort"

	"github.com/biter777/countries"
)

type PhoneCountry struct {
	UniqueId    string
	CallingCode string
	Name        string
}

func Get() []PhoneCountry {
	phoneCountries := []PhoneCountry{}

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

	for _, c := range countries {
		if len(c.CallCodes) > 5 {
			panic(fmt.Sprintf("Unsupported: country %v has more than 5 call codes", c.Name))
		}

		for i, callCode := range c.CallCodes {
			if i < 5 {
				phoneCountries = append(phoneCountries, PhoneCountry{
					UniqueId:    fmt.Sprintf("%v_%v", c.Alpha3, i),
					CallingCode: callCode.String(),
					Name:        fmt.Sprintf("%v - %v (%v)", c.Emoji, c.Name, callCode.String()),
				})
			}
		}
	}

	return phoneCountries
}
