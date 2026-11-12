package render

import (
	"context"

	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/brandkit"
	"github.com/leodip/goiabada/core/i18n"
)

// PageFooter is the footer an end-user page of the console draws: the brand's links, then "Need
// help?" with its support contact (#814 decisions 1 to 7). A card page draws it under its card, and
// an Account page at the foot of its content; either is the page's own footer landmark after main.
// An admin page draws none.
//
// Panel is whether the brand has a background image, which only a card page draws. The card page's
// footer then sits on a panel in the card's color (decision 6, D1); an Account page ignores it.
// Links are in the brand's order, each with the label of the page's language. SupportEmail,
// SupportPhone and SupportURL are each empty when unset. SupportMailto is the address as its mailto:
// link carries it, percent-encoded where RFC 6068 says it must be. The page draws SupportEmail and
// SupportPhone as themselves and SupportURL under the built-in "Support page" (decision 4).
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

// HasContact reports whether the footer draws the "Need help?" line: whether the brand sets any of
// its three contact values.
func (f *PageFooter) HasContact() bool {
	return f.SupportEmail != "" || f.SupportPhone != "" || f.SupportURL != ""
}

// footerOf answers the footer a page drawn in ctx takes from brand, as the public settings carry it.
// It answers nil for no brand, as from an auth server older than brands, and for a brand with no
// links and no contact, which draws no footer at all (#814 decision 6). Each link's label is the one
// for the language the page is written in, the catalog its lang attribute names, by the rule the
// auth server's pages use (brandkit.FooterLinkLabel, decision 9).
//
// The values are the brand's own (decision 3). The auth server validated them when they were
// written, and the page still escapes every one.
func footerOf(ctx context.Context, brand *api.PublicBrandResponse) *PageFooter {
	if brand == nil {
		return nil
	}
	if len(brand.FooterLinks) == 0 && brand.SupportEmail == "" && brand.SupportURL == "" && brand.SupportPhone == "" {
		return nil
	}
	lang := i18n.CatalogTag(ctx)
	footer := &PageFooter{
		Panel:        brand.HasBackground,
		SupportEmail: brand.SupportEmail,
		SupportPhone: brand.SupportPhone,
		SupportURL:   brand.SupportURL,
	}
	if brand.SupportEmail != "" {
		footer.SupportMailto = brandkit.MailtoAddress(brand.SupportEmail)
	}
	for _, link := range brand.FooterLinks {
		footer.Links = append(footer.Links, PageFooterLink{
			URL:   link.Url,
			Label: brandkit.FooterLinkLabel(link.Label, link.Labels, lang),
		})
	}
	return footer
}
