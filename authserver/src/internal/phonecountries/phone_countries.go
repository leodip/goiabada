package phonecountries

import (
	"fmt"
	"sort"

	"github.com/biter777/countries"
)

type PhoneCountry struct {
	Code string
	Name string
}

func Get() []PhoneCountry {
	phoneCountries := []PhoneCountry{}

	countries := countries.AllInfo()
	sort.Slice(countries, func(i, j int) bool {
		return countries[i].Name < countries[j].Name
	})

	for _, c := range countries {
		if len(c.CallCodes) == 1 {
			phoneCountries = append(phoneCountries, PhoneCountry{
				Code: c.CallCodes[0].String(),
				Name: fmt.Sprintf("%v - %v (%v)", c.Emoji, c.Name, c.CallCodes[0].String()),
			})
		} else if len(c.CallCodes) == 2 {
			phoneCountries = append(phoneCountries, PhoneCountry{
				Code: c.CallCodes[0].String(),
				Name: fmt.Sprintf("%v - %v (%v)", c.Emoji, c.Name, c.CallCodes[0].String()),
			})

			phoneCountries = append(phoneCountries, PhoneCountry{
				Code: c.CallCodes[1].String(),
				Name: fmt.Sprintf("%v - %v (%v)", c.Emoji, c.Name, c.CallCodes[1].String()),
			})
		}
	}

	return phoneCountries
}
