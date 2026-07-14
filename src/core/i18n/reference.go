package i18n

import (
	"context"

	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

// RefCountry returns the localized country name for an ISO 3166-1 alpha-2
// code, resolved from CLDR (golang.org/x/text/language/display) for the
// active locale. Falls back to `fallback` (typically the English struct
// field) when the code or active-locale tag is unparseable, or CLDR has no
// name for the pair.
func RefCountry(ctx context.Context, alpha2, fallback string) string {
	return localizedRegionName(ctx, alpha2, fallback)
}

// RefPhoneCountry returns the localized phone-country label for an
// ISO 3166-1 alpha-2 code, formatted "<emoji> - <country> (<code>)". The
// country name is rendered in the active locale via CLDR; the emoji and
// calling code are locale-independent and pass through verbatim. Falls back
// to the pre-assembled English label when the code or active-locale tag is
// unparseable, or CLDR has no name.
func RefPhoneCountry(ctx context.Context, emoji, alpha2, callingCode, fallback string) string {
	if name := localizedRegionName(ctx, alpha2, ""); name != "" {
		return emoji + " - " + name + " (" + callingCode + ")"
	}
	return fallback
}

// RefTimezone returns the timezone display label keyed by IANA zone ID,
// assembled as "<country> - <zone>[ - <comments>]". The country name is
// rendered in the active locale via CLDR; the zone identifier and IANA
// comments stay in their original (English) form.
//
// countryCode is the ISO 3166-1 alpha-2 code from the timezones table;
// countryName is the English name kept as a final fallback when CLDR has no
// name for the active locale + region pair. comments may be empty.
func RefTimezone(ctx context.Context, zoneID, countryCode, countryName, comments string) string {
	name := localizedRegionName(ctx, countryCode, countryName)
	out := name + " - " + zoneID
	if comments != "" {
		out += " - " + comments
	}
	return out
}

// localizedRegionName returns the country name for an ISO 3166-1 alpha-2
// region code rendered in the active locale, sourced from CLDR data
// bundled in golang.org/x/text/language/display.
//
// Falls back to the supplied fallback (typically the English country name
// from the static struct) if the code is unparseable, the active locale
// tag is unparseable, or CLDR has no name for the pair.
func localizedRegionName(ctx context.Context, alpha2, fallback string) string {
	if alpha2 == "" {
		return fallback
	}
	region, err := language.ParseRegion(alpha2)
	if err != nil {
		return fallback
	}
	tag, err := language.Parse(LocaleTag(ctx))
	if err != nil {
		return fallback
	}
	name := display.Regions(tag).Name(region)
	if name == "" {
		return fallback
	}
	return name
}
