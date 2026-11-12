package record

import (
	"database/sql/driver"
	"encoding/json"

	"github.com/leodip/goiabada/core/errs"
)

// BrandFooterLink is one link drawn under a brand's card (#814 decision 5): the URL it opens, the
// fallback label, and the label for each built-in language that has its own, by language tag.
// Labels is nil when no language has one.
type BrandFooterLink struct {
	URL    string            `json:"url"`
	Label  string            `json:"label"`
	Labels map[string]string `json:"labels,omitempty"`
}

// BrandFooterLinks is a brand's footer links in the order they are drawn, stored whole as JSON
// text on brands.footer_links (#814 decision 8): a list of {"url", "label", "labels"} objects, and
// [] for none. The links are never looked up by a URL or a label, so one column holds them.
//
// The engine cannot check the text's shape: what is written is validated before the write, and a
// read holds the stored text to ParseBrandFooterLinks.
type BrandFooterLinks []BrandFooterLink

// Value is the list as brands.footer_links stores it: its JSON text, [] for none.
func (l BrandFooterLinks) Value() (driver.Value, error) {
	if len(l) == 0 {
		return "[]", nil
	}
	text, err := json.Marshal([]BrandFooterLink(l))
	if err != nil {
		return nil, errs.Wrap(err, "unable to encode the brand's footer links")
	}
	return string(text), nil
}

// ParseBrandFooterLinks reads brands.footer_links as Value wrote it: a JSON list of links, each
// an object with a non-empty url and label and, when present, labels mapping a language tag to a
// label. The empty list reads as nil. Anything else does not parse and answers an error with nil,
// so a reader draws no links rather than a link with no URL or no label.
func ParseBrandFooterLinks(text string) (BrandFooterLinks, error) {
	var links []BrandFooterLink
	if err := json.Unmarshal([]byte(text), &links); err != nil {
		return nil, errs.Wrap(err, "the brand's footer links are not a JSON list of links")
	}
	for i, link := range links {
		if link.URL == "" || link.Label == "" {
			return nil, errs.Errorf("the brand's footer link %d has no url or no label", i+1)
		}
	}
	if len(links) == 0 {
		return nil, nil
	}
	return links, nil
}
