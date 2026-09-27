package i18n

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// loadOverrideCatalogs walks dir/catalogs/ and returns each *.toml message
// file in directory order, for the caller to merge on top of the embedded set.
// dir is the overrides directory main passes to LoadBundle, which each
// application's configuration reads from GOIABADA_I18N_OVERRIDES_DIR. Override
// files win on conflict (this is by design — self-hosters need to be able to
// fix typos or ship locales without rebuilding the binary), and an empty value
// removes the embedded translation so the key renders English.
//
// The language tags come back on the returned catalogs so the caller can
// merge them into the bundle's tags. A locale that's only present via the
// override directory must still reach the matcher, or a request asking for it
// would be answered in English.
//
// Only message catalogs are overridable this way — Goiabada consults only a
// `catalogs/` subdirectory under the overrides directory. There is no
// reference-data layer: country and phone-country names come from CLDR, and
// timezone labels are assembled from the CLDR-localized country name, IANA
// zone ID, and optional English comment (see RefCountry/RefPhoneCountry/RefTimezone).
func loadOverrideCatalogs(dir string) ([]catalogFile, error) {
	catalogsDir := filepath.Join(dir, "catalogs")
	info, err := os.Stat(catalogsDir)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("override directory has no catalogs subdirectory, skipping it",
				slog.String("dir", catalogsDir))
			return nil, nil
		}
		return nil, errs.Errorf("i18n: stat override catalogs dir: %w", err)
	}
	if !info.IsDir() {
		return nil, errs.Errorf("i18n: override catalogs path %s is not a directory", catalogsDir)
	}
	entries, err := os.ReadDir(catalogsDir)
	if err != nil {
		return nil, errs.Errorf("i18n: read override catalogs dir: %w", err)
	}
	var out []catalogFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		path := filepath.Join(catalogsDir, e.Name())
		//nolint:gosec // G304: a file listed in the operator's own override directory, read once at startup
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, errs.Errorf("i18n: read override catalog %s: %w", path, err)
		}
		tag, messages, err := parseCatalog(path, data)
		if err != nil {
			return nil, err
		}
		out = append(out, catalogFile{tag: tag, messages: messages})
		slog.Info("loaded an override catalog, which wins over the embedded one",
			slog.String("path", path))
	}
	return out, nil
}
