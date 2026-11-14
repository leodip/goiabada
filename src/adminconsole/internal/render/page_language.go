package render

import (
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/locales"
)

// PageLanguageOption is one language the Page language select offers after Automatic: the tag of a
// built-in catalog, which the select posts, and its English name, which the template
// labels as Language and region labels a locale, in itself and then in English (LocaleLabel).
type PageLanguageOption struct {
	Tag  string
	Name string
}

// PageLanguageOptions lists every built-in catalog, in the order i18n.CatalogTags gives them, which
// are the languages a user can choose for Goiabada's own pages (#631 decision 3). The auth server
// refuses a tag that names none of them. A tag the locale list does not name is its own English
// name.
func PageLanguageOptions() []PageLanguageOption {
	tags := i18n.CatalogTags()
	options := make([]PageLanguageOption, 0, len(tags))
	for _, tag := range tags {
		name := tag
		if l, ok := locales.ByID(tag); ok {
			name = l.Name
		}
		options = append(options, PageLanguageOption{Tag: tag, Name: name})
	}
	return options
}

// SelectedPageLanguage is the value the Page language select shows selected for a stored or
// submitted page language: the tag when it names a built-in catalog, else Automatic's empty value.
// A stored tag naming a language Goiabada doesn't ship therefore shows Automatic, which the next
// save writes (decision 3).
func SelectedPageLanguage(pageLanguage string) string {
	if i18n.IsCatalogTag(pageLanguage) {
		return pageLanguage
	}
	return ""
}
