package render

import (
	"context"

	"github.com/leodip/goiabada/core/brandkit"
	"github.com/leodip/goiabada/core/i18n"
)

// PageFooter is the footer a card page draws under its card, its own footer landmark outside main
// (#814 decisions 1 to 6): the brand's links, then "Need help?" with its support contact. Both
// layouts and the form_post page draw it from FooterOf, so the three agree.
//
// Panel is whether it is drawn on a panel in the card's color, which it is while the brand has a
// background image, whose colors are unknown; otherwise it is small text on the page's background
// color. Links are in the brand's order, each with the label of the page's language.
// SupportEmail, SupportPhone and SupportURL are each empty when unset; SupportMailto is the address
// as its mailto: link carries it, percent-encoded where RFC 6068 says it must be. A page draws
// SupportEmail and SupportPhone as themselves and SupportURL under the built-in "Support page"
// (decision 4).
type PageFooter struct {
	Panel         bool
	Links         []PageFooterLink
	SupportEmail  string
	SupportMailto string
	SupportPhone  string
	SupportURL    string
}

// PageFooterLink is one footer link as a page draws it: the URL it opens in a new tab, and its label
// in the page's language, else its fallback label.
type PageFooterLink struct {
	URL   string
	Label string
}

// HasContact reports whether the footer draws the "Need help?" line: whether the brand sets any
// of its three contact values.
func (f *PageFooter) HasContact() bool {
	return f.SupportEmail != "" || f.SupportPhone != "" || f.SupportURL != ""
}

// FooterOf answers the footer a page drawn in ctx takes from brand, or nil for a brand with no links
// and no contact, which draws no footer at all (#814 decision 6): a brand nobody has given either is
// drawn as before, and so is one that cannot be read. Each link's label is the one for the language
// the page is written in, the catalog its lang attribute names (brandkit.FooterLinkLabel).
//
// The values are the brand's own, with no fallback to another brand's (decision 3). They were
// validated when written, and the page still escapes every one: a label or an address is drawn as
// text, and a URL that is not one a page may link is not linked.
func FooterOf(ctx context.Context, brand PageBrand) *PageFooter {
	if len(brand.FooterLinks) == 0 && brand.SupportEmail == "" && brand.SupportURL == "" && brand.SupportPhone == "" {
		return nil
	}
	lang := i18n.CatalogTag(ctx)
	footer := &PageFooter{
		Panel:        brand.Background,
		SupportEmail: brand.SupportEmail,
		SupportPhone: brand.SupportPhone,
		SupportURL:   brand.SupportURL,
	}
	if brand.SupportEmail != "" {
		footer.SupportMailto = brandkit.MailtoAddress(brand.SupportEmail)
	}
	for _, link := range brand.FooterLinks {
		footer.Links = append(footer.Links, PageFooterLink{
			URL:   link.URL,
			Label: brandkit.FooterLinkLabel(link.Label, link.Labels, lang),
		})
	}
	return footer
}
