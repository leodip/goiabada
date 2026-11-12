package apihandlers

import (
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/accountvalidation"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/inputvalidation"
)

// A brand's footer links and support contact (#814 decisions 1, 5 and 9), validated before they are
// written: the engine cannot check the links column's shape (decision 8). A footer link's refusal
// names the member of the request body it is about in the error answer's error_field (decision 10);
// a contact value's refusal is one code per field, as every other brand field's.

const (
	// brandFooterLinksMax is how many footer links a brand has at most. A further link is refused,
	// never dropped (decision 5).
	brandFooterLinksMax = 3
	// brandFooterLabelMaxLength bounds a footer link's label and each of its language labels, in
	// inputvalidation.TextLength's characters.
	brandFooterLabelMaxLength = 40
	// brandURLMaxLength bounds a footer link's URL and the support page URL, in
	// inputvalidation.TextLength's characters: the bound of a client's website URL, and the width of
	// the support_url column.
	brandURLMaxLength = clientURLMaxLength
)

// brandFooterFields are the footer links and the support contact as a create or an update names them.
type brandFooterFields struct {
	footerLinks                            []api.BrandFooterLink
	supportEmail, supportURL, supportPhone string
}

// validateBrandFooter holds the footer links and the contact to decisions 1, 5 and 9 and writes them
// on brand as stored: the links in the order sent, nil for none, each value trimmed and each blank
// language label dropped; the contact trimmed, "" for a value unset, and the phone number without
// its separators.
func validateBrandFooter(fields brandFooterFields, brand *record.Brand) error {
	links, err := validateBrandFooterLinks(fields.footerLinks)
	if err != nil {
		return err
	}
	email, err := validateSupportEmail(fields.supportEmail)
	if err != nil {
		return err
	}
	supportURL, err := validateSupportURL(fields.supportURL)
	if err != nil {
		return err
	}
	phone, err := validateSupportPhone(fields.supportPhone)
	if err != nil {
		return err
	}
	brand.FooterLinks = links
	brand.SupportEmail = email
	brand.SupportURL = supportURL
	brand.SupportPhone = phone
	return nil
}

// validateBrandFooterLinks answers the links as stored, nil for none, or the refusal of the first
// link that breaks a rule, at the member it breaks. A fourth link is refused at itself.
func validateBrandFooterLinks(links []api.BrandFooterLink) (record.BrandFooterLinks, error) {
	if len(links) > brandFooterLinksMax {
		return nil, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinksTooMany,
			map[string]any{"max": brandFooterLinksMax}), "footerLinks", strconv.Itoa(brandFooterLinksMax))
	}
	var stored record.BrandFooterLinks
	for i, link := range links {
		one, err := validateBrandFooterLink(i, link)
		if err != nil {
			return nil, err
		}
		stored = append(stored, one)
	}
	return stored, nil
}

// validateBrandFooterLink holds the link at index i to decision 5: a label, trimmed, required, at
// most brandFooterLabelMaxLength characters and without angle brackets; a URL, trimmed, required and
// a brand URL; and a label per built-in language under the label's bounds, a blank one dropped and
// any other tag refused. A refusal names the link by its number, i+1, for a person.
func validateBrandFooterLink(i int, link api.BrandFooterLink) (record.BrandFooterLink, error) {
	index := strconv.Itoa(i)
	number := i + 1

	label := strings.TrimSpace(link.Label)
	switch {
	case label == "":
		return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkLabelRequired,
			map[string]any{"link": number}), "footerLinks", index, "label")
	case inputvalidation.TextLength(label) > brandFooterLabelMaxLength:
		return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkLabelTooLong,
			map[string]any{"link": number, "max": brandFooterLabelMaxLength}), "footerLinks", index, "label")
	case inputvalidation.ContainsAngleBrackets(label):
		return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkLabelAngleBrackets,
			map[string]any{"link": number}), "footerLinks", index, "label")
	}

	linkURL := strings.TrimSpace(link.Url)
	if linkURL == "" {
		return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkURLRequired,
			map[string]any{"link": number}), "footerLinks", index, "url")
	}
	switch brandURLFaultOf(linkURL) {
	case brandURLTooLong:
		return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkURLTooLong,
			map[string]any{"link": number, "max": brandURLMaxLength}), "footerLinks", index, "url")
	case brandURLNotHTTPS:
		return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkURLInvalid,
			map[string]any{"link": number}), "footerLinks", index, "url")
	}

	// The tags in order, so the refusal of a link with several faults is the same on every request.
	var labels map[string]string
	for _, tag := range slices.Sorted(maps.Keys(link.Labels)) {
		if !i18n.IsBuiltInCatalogTag(tag) {
			return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkLanguageInvalid,
				map[string]any{"link": number, "language": tag}), "footerLinks", index, "labels", tag)
		}
		value := strings.TrimSpace(link.Labels[tag])
		switch {
		case value == "":
			continue
		case inputvalidation.TextLength(value) > brandFooterLabelMaxLength:
			return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkLanguageLabelTooLong,
				map[string]any{"link": number, "language": tag, "max": brandFooterLabelMaxLength}), "footerLinks", index, "labels", tag)
		case inputvalidation.ContainsAngleBrackets(value):
			return record.BrandFooterLink{}, refusalAt(i18n.NewLocalizedError(i18n.ErrCodeBrandFooterLinkLanguageLabelAngleBrackets,
				map[string]any{"link": number, "language": tag}), "footerLinks", index, "labels", tag)
		}
		if labels == nil {
			labels = map[string]string{}
		}
		labels[tag] = value
	}

	return record.BrandFooterLink{URL: linkURL, Label: label, Labels: labels}, nil
}

// brandURLFault is what is wrong with a footer link's URL or the support page URL, if anything.
type brandURLFault int

const (
	brandURLFine brandURLFault = iota
	brandURLTooLong
	brandURLNotHTTPS
)

// brandURLFaultOf holds a trimmed, non-empty URL to decision 5: at most brandURLMaxLength
// characters, https: only, absolute with a host, and with no user name or password, since
// https://acme.com@other.example shows one site and opens another.
func brandURLFaultOf(value string) brandURLFault {
	if inputvalidation.TextLength(value) > brandURLMaxLength {
		return brandURLTooLong
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" {
		return brandURLNotHTTPS
	}
	return brandURLFine
}

// validateSupportEmail answers the support address trimmed, "" for none, or its refusal: an account
// address's 254-character bound, then its shape.
func validateSupportEmail(value string) (string, error) {
	email := strings.TrimSpace(value)
	if email == "" {
		return "", nil
	}
	if inputvalidation.TextLength(email) > accountvalidation.MaxEmailLength {
		return "", i18n.NewLocalizedError(i18n.ErrCodeBrandSupportEmailTooLong, map[string]any{"max": accountvalidation.MaxEmailLength})
	}
	if accountvalidation.NewEmailValidator(nil).ValidateEmailAddress(email) != nil {
		return "", i18n.NewLocalizedError(i18n.ErrCodeBrandSupportEmailInvalid, nil)
	}
	return email, nil
}

// validateSupportURL answers the support page URL trimmed, "" for none, or its refusal, under a
// footer link's URL rule.
func validateSupportURL(value string) (string, error) {
	supportURL := strings.TrimSpace(value)
	if supportURL == "" {
		return "", nil
	}
	switch brandURLFaultOf(supportURL) {
	case brandURLTooLong:
		return "", i18n.NewLocalizedError(i18n.ErrCodeBrandSupportURLTooLong, map[string]any{"max": brandURLMaxLength})
	case brandURLNotHTTPS:
		return "", i18n.NewLocalizedError(i18n.ErrCodeBrandSupportURLInvalid, nil)
	}
	return supportURL, nil
}

// e164Number is a phone number as it is stored: a "+" and up to 15 digits, the first not zero, a
// tel: URI's global number as it stands (RFC 3966 section 5.1.4).
var e164Number = regexp.MustCompile(`^\+[1-9][0-9]{0,14}$`)

// validateSupportPhone answers the support phone number as stored, "" for none, or its refusal. It is
// taken as typed, with spaces, hyphens, dots and parentheses anywhere, and stored without them
// (decision 11); what is left must be an e164Number.
func validateSupportPhone(value string) (string, error) {
	typed := strings.TrimSpace(value)
	if typed == "" {
		return "", nil
	}
	number := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '.', '(', ')':
			return -1
		}
		return r
	}, typed)
	if !e164Number.MatchString(number) {
		return "", i18n.NewLocalizedError(i18n.ErrCodeBrandSupportPhoneInvalid, nil)
	}
	return number, nil
}

// brandFooterAudit adds to an audit event's details the contact values and each link's URL, in
// order, that brand holds after the save, so an auditor can see a link added under a sign-in card
// (decision 9). A value unset, and the links when there are none, are left out, as an empty slot is.
func brandFooterAudit(brand *record.Brand, details map[string]interface{}) {
	if brand.SupportEmail != "" {
		details["support_email"] = brand.SupportEmail
	}
	if brand.SupportURL != "" {
		details["support_url"] = brand.SupportURL
	}
	if brand.SupportPhone != "" {
		details["support_phone"] = brand.SupportPhone
	}
	if len(brand.FooterLinks) > 0 {
		urls := make([]string, 0, len(brand.FooterLinks))
		for _, link := range brand.FooterLinks {
			urls = append(urls, link.URL)
		}
		details["footer_link_urls"] = urls
	}
}
