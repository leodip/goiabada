package i18n

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

// loadOverrideCatalogs walks $GOIABADA_I18N_OVERRIDES_DIR/catalogs/ and
// merges each *.toml message file on top of the embedded set. Override
// files win on conflict (this is by design — self-hosters need to be able
// to fix typos or ship locales without rebuilding the binary).
//
// Returns the language tags parsed from override files so the caller can
// merge them into Bundle.tags. A locale that's only present via the
// override directory must still surface from SupportedTags() so callers
// like the locale picker see it.
//
// Only message catalogs are overridable this way — Goiabada consults only a
// `catalogs/` subdirectory under GOIABADA_I18N_OVERRIDES_DIR. There is no
// reference-data layer: country and phone-country names come from CLDR, and
// timezone labels are assembled from the CLDR-localized country name, IANA
// zone ID, and optional English comment (see RefCountry/RefPhoneCountry/RefTimezone).
func loadOverrideCatalogs(b *i18n.Bundle, dir string) ([]language.Tag, error) {
	catalogsDir := filepath.Join(dir, "catalogs")
	info, err := os.Stat(catalogsDir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("i18n: override directory has no catalogs/ subdir, skipping",
				slog.String("dir", catalogsDir))
			return nil, nil
		}
		return nil, fmt.Errorf("i18n: stat override catalogs dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("i18n: override catalogs path %s is not a directory", catalogsDir)
	}
	entries, err := os.ReadDir(catalogsDir)
	if err != nil {
		return nil, fmt.Errorf("i18n: read override catalogs dir: %w", err)
	}
	var tags []language.Tag
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		path := filepath.Join(catalogsDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("i18n: read override catalog %s: %w", path, err)
		}
		mf, err := b.ParseMessageFileBytes(data, e.Name())
		if err != nil {
			return nil, fmt.Errorf("i18n: parse override catalog %s: %w", path, err)
		}
		if mf != nil {
			tags = append(tags, mf.Tag)
		}
		slog.Info("i18n: loaded override catalog (overrides win over embedded)",
			slog.String("path", path))
	}
	return tags, nil
}
