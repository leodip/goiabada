package adminsettingshandlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/adminconsole/internal/render"
	"github.com/leodip/goiabada/adminconsole/internal/reqctx"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/brandkit"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/i18n"
	"github.com/leodip/goiabada/core/sessionstore"
)

// The Branding pages, under /admin/settings/branding (#810): the brands, each with how many clients
// are drawn in it, one of them the default a client with no brand of its own is drawn in (#812
// decision 3); a brand created and edited, its appearance and theme chosen on option cards whose
// swatches are drawn from the auth server's own palettes (GET /brand-themes), its corners, font
// family, background fit and the switch hiding the app name chosen beside them (#813), made the
// default, and deleted, its clients moving to the default. Every write drops the cached public
// settings, whose brand is the console's own client's, which may be the brand written or follow the
// default.

// brandingPath is the list, which a creation and a deletion go back to.
const brandingPath = "/admin/settings/branding"

// The kit's choices a new brand's form starts with, which draw it as a brand nobody has changed is
// drawn (#813 decision 2): rounded corners, the System UI family and a background drawn as cover, the
// app name shown.
const (
	newBrandCorners       = "rounded"
	newBrandFont          = "system-ui"
	newBrandBackgroundFit = "cover"
)

// BrandRow is a brand as the list and the delete page draw it: the brand, with its appearance and
// its theme in words.
type BrandRow struct {
	api.BrandResponse
	AppearanceName string
	ThemeName      string
}

// BrandForm is what the brand form holds: the stored brand, the defaults of a new one, or what was
// sent when the auth server refused it. Corners, Font and BackgroundFit are the kit's choices, by the
// value a brand stores, and HideAppName the switch hiding the app name beside a logo (#813).
type BrandForm struct {
	Name          string
	Appearance    string
	Theme         string
	Corners       string
	Font          string
	BackgroundFit string
	HideAppName   bool
}

// brandCornerShapes and brandFontFamilies are the corner shapes and the font families the form
// offers, by the value a brand stores.
var (
	brandCornerShapes = []string{"square", "rounded", "pill"}
	brandFontFamilies = []string{"system-ui", "humanist", "geometric", "serif", "neo-grotesque", "rounded", "uploaded"}
)

// BrandKitStyles is what each corner shape and font family draws, which the editor hands its preview
// script in a JSON data block so the sample takes them as they are picked (#813): the radii of each
// shape and the font-family list of each family that sets any, by the value the form sends. They are
// brandkit's, as the auth server's stylesheet draws them. Rounded and System UI, today's look, are
// absent, since they set nothing.
type BrandKitStyles struct {
	Corners map[string]brandkit.Radii `json:"corners"`
	Fonts   map[string]string         `json:"fonts"`
}

// BrandThemeOption is one theme card: the key the form sends, the theme's name in words, and the
// light and dark palettes its swatch is drawn in, as the auth server answered them. The editor
// hands the list to its preview script in a JSON data block (#811), each theme as its key and its
// two palettes; the name is the card's alone.
type BrandThemeOption struct {
	Key   string            `json:"key"`
	Name  string            `json:"-"`
	Light map[string]string `json:"light"`
	Dark  map[string]string `json:"dark"`
}

// brandErrorFields maps the refusals a brand's save can meet to the field each is about: the four
// about the name to the name; the appearance, theme, corners and background fit choices to theirs;
// and an unknown family and the uploaded font without a regular font file to the font family (#813
// decision 7).
var brandErrorFields = map[string]string{
	i18n.ErrCodeBrandNameRequired:                "name",
	i18n.ErrCodeBrandNameTooLong:                 "name",
	i18n.ErrCodeBrandNameAngleBrackets:           "name",
	i18n.ErrCodeBrandNameInUse:                   "name",
	i18n.ErrCodeBrandAppearanceInvalid:           "appearance",
	i18n.ErrCodeBrandThemeInvalid:                "theme",
	i18n.ErrCodeBrandCornersInvalid:              "corners",
	i18n.ErrCodeBrandFontInvalid:                 "font",
	i18n.ErrCodeBrandUploadedFontRegularRequired: "font",
	i18n.ErrCodeBrandBackgroundFitInvalid:        "backgroundFit",
}

// brandThemeNames are the message IDs of the built-in themes' names, by key. A theme missing here,
// as a newer auth server's could be, is named by its key.
var brandThemeNames = map[string]string{
	"blueberry":     "adminconsole.admin_branding.theme.blueberry",
	"blackberry":    "adminconsole.admin_branding.theme.blackberry",
	"avocado":       "adminconsole.admin_branding.theme.avocado",
	"plum":          "adminconsole.admin_branding.theme.plum",
	"tangerine":     "adminconsole.admin_branding.theme.tangerine",
	"guava":         "adminconsole.admin_branding.theme.guava",
	"coconut":       "adminconsole.admin_branding.theme.coconut",
	"high-contrast": "adminconsole.admin_branding.theme.high_contrast",
}

// brandAppearanceNames are the message IDs of the three appearances' names.
var brandAppearanceNames = map[string]string{
	"auto":  "adminconsole.admin_branding.appearance.auto",
	"light": "adminconsole.admin_branding.appearance.light",
	"dark":  "adminconsole.admin_branding.appearance.dark",
}

func nameIn(ctx context.Context, names map[string]string, key string) string {
	if id, ok := names[key]; ok {
		return i18n.T(ctx, id)
	}
	return key
}

// brandClientsNote says on a brand's page how many clients are drawn in it, a sentence for none,
// one and more.
func brandClientsNote(ctx context.Context, count int) string {
	return countSentence(ctx, "adminconsole.admin_branding.brand.clients.", count, nil)
}

// deleteClientsNote says on the delete confirmation how many clients use the brand and that they
// will move to the default brand, named, or that no client uses it.
func deleteClientsNote(ctx context.Context, count int, defaultBrand string) string {
	return countSentence(ctx, "adminconsole.admin_branding.delete.clients.", count, map[string]any{"defaultBrand": defaultBrand})
}

// countSentence is the message under prefix for count: its none form for zero, its one form for
// one and its other form for more. The plural is chosen by count == 1, as the console's other
// counted phrases are (render's relative times), which holds for every built-in catalog.
func countSentence(ctx context.Context, prefix string, count int, args map[string]any) string {
	form := "other"
	switch count {
	case 0:
		form = "none"
	case 1:
		form = "one"
	}
	data := map[string]any{"count": count}
	for key, value := range args {
		data[key] = value
	}
	return i18n.T(ctx, prefix+form, data)
}

func brandRow(ctx context.Context, brand api.BrandResponse) BrandRow {
	return BrandRow{
		BrandResponse:  brand,
		AppearanceName: nameIn(ctx, brandAppearanceNames, brand.Appearance),
		ThemeName:      nameIn(ctx, brandThemeNames, brand.Theme),
	}
}

func brandThemeOptions(ctx context.Context, themes []api.BrandThemeResponse) []BrandThemeOption {
	options := make([]BrandThemeOption, 0, len(themes))
	for _, theme := range themes {
		options = append(options, BrandThemeOption{
			Key:   theme.Key,
			Name:  nameIn(ctx, brandThemeNames, theme.Key),
			Light: theme.Light,
			Dark:  theme.Dark,
		})
	}
	return options
}

// appearanceTheme is the theme the appearance cards are drawn in: the one the form holds, or the
// first the auth server lists when it holds none of them.
func appearanceTheme(options []BrandThemeOption, key string) BrandThemeOption {
	for _, option := range options {
		if option.Key == key {
			return option
		}
	}
	if len(options) > 0 {
		return options[0]
	}
	return BrandThemeOption{}
}

// brandKitStyles is what each of the form's corner shapes and font families draws.
func brandKitStyles() BrandKitStyles {
	styles := BrandKitStyles{Corners: map[string]brandkit.Radii{}, Fonts: map[string]string{}}
	for _, corners := range brandCornerShapes {
		if radii, ok := brandkit.CornerRadii(corners); ok {
			styles.Corners[corners] = radii
		}
	}
	for _, font := range brandFontFamilies {
		if stack, ok := brandkit.FontStack(font); ok {
			styles.Fonts[font] = stack
		}
	}
	return styles
}

// brandFormFrom reads the brand form: the name trimmed, as the auth server stores it, and the
// appearance, theme and kit choices as sent, which the auth server compares exactly. The switch is a
// checkbox, which a browser sends only while it is on.
func brandFormFrom(r *http.Request) BrandForm {
	return BrandForm{
		Name:          strings.TrimSpace(r.PostFormValue("name")),
		Appearance:    r.PostFormValue("appearance"),
		Theme:         r.PostFormValue("theme"),
		Corners:       r.PostFormValue("corners"),
		Font:          r.PostFormValue("font"),
		BackgroundFit: r.PostFormValue("backgroundFit"),
		HideAppName:   r.PostFormValue("hideAppName") == "on",
	}
}

// brandIdFrom reads the brand's id from the path, answering the 404 page for one that is not a
// number.
func brandIdFrom(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("brandId"), 10, 64)
	if err != nil {
		httpHelper.NotFound(w, r)
		return 0, false
	}
	return id, true
}

func accessTokenFrom(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request) (string, bool) {
	jwtInfo, ok := reqctx.JwtInfoFrom(r.Context())
	if !ok {
		httpHelper.InternalServerError(w, r, reqctx.ErrNoJwtInfo)
		return "", false
	}
	return jwtInfo.TokenResponse.AccessToken, true
}

// renderBrandForm draws the brand form, new or of a stored brand, with the theme cards, and hands the
// preview what each theme, corner shape and font family draws.
func renderBrandForm(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, form BrandForm,
	themes []api.BrandThemeResponse, extra map[string]interface{}) {

	options := brandThemeOptions(r.Context(), themes)
	bind := map[string]interface{}{
		"brand":           form,
		"brandThemes":     options,
		"appearanceTheme": appearanceTheme(options, form.Theme),
		"brandKitStyles":  brandKitStyles(),
	}
	for key, value := range extra {
		bind[key] = value
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_branding_brand.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// brandingListAPI is what the list needs: the brands.
type brandingListAPI interface {
	GetAllBrands(ctx context.Context, accessToken string) ([]api.BrandResponse, error)
}

func HandleBrandingGet(
	httpHelper HttpHelper,
	apiClient brandingListAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := accessTokenFrom(httpHelper, w, r)
		if !ok {
			return
		}

		brands, err := apiClient.GetAllBrands(r.Context(), token)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		rows := make([]BrandRow, 0, len(brands))
		for _, brand := range brands {
			rows = append(rows, brandRow(r.Context(), brand))
		}

		bind := map[string]interface{}{
			"brands": rows,
		}
		if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_branding.html", bind); err != nil {
			httpHelper.InternalServerError(w, r, err)
		}
	}
}

// brandThemesAPI is what the new brand form needs to be drawn: the themes.
type brandThemesAPI interface {
	GetBrandThemes(ctx context.Context, accessToken string) ([]api.BrandThemeResponse, error)
}

// brandNewAPI is what the new brand form needs to be saved: the themes it is drawn again with, and
// the write.
type brandNewAPI interface {
	brandThemesAPI
	CreateBrand(ctx context.Context, accessToken string, request *api.CreateBrandRequest) (*api.BrandResponse, error)
}

// HandleBrandNewGet draws a new brand automatic, on the first theme the auth server lists, which is
// the built-in one.
func HandleBrandNewGet(
	httpHelper HttpHelper,
	apiClient brandThemesAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := accessTokenFrom(httpHelper, w, r)
		if !ok {
			return
		}

		themes, err := apiClient.GetBrandThemes(r.Context(), token)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		form := BrandForm{Appearance: "auto", Corners: newBrandCorners, Font: newBrandFont, BackgroundFit: newBrandBackgroundFit}
		if len(themes) > 0 {
			form.Theme = themes[0].Key
		}
		renderBrandForm(httpHelper, w, r, form, themes, map[string]interface{}{"isNew": true})
	}
}

func HandleBrandNewPost(
	httpHelper HttpHelper,
	apiClient brandNewAPI,
	settingsCache SettingsInvalidator,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := accessTokenFrom(httpHelper, w, r)
		if !ok {
			return
		}

		themes, err := apiClient.GetBrandThemes(r.Context(), token)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		form := brandFormFrom(r)
		_, err = apiClient.CreateBrand(r.Context(), token, &api.CreateBrandRequest{
			Name:          form.Name,
			Appearance:    form.Appearance,
			Theme:         form.Theme,
			Corners:       form.Corners,
			Font:          form.Font,
			BackgroundFit: form.BackgroundFit,
			HideAppName:   form.HideAppName,
		})
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderBrandForm(httpHelper, w, r, form, themes, map[string]interface{}{
					"isNew":      true,
					"error":      message,
					"errorField": render.ErrorField(err, brandErrorFields),
				})
			})
			return
		}

		settingsCache.Invalidate()
		http.Redirect(w, r, baseURL+brandingPath, http.StatusFound)
	}
}

// brandEditReadAPI is what a brand's page needs to be drawn: the brand and the themes.
type brandEditReadAPI interface {
	brandThemesAPI
	GetBrandById(ctx context.Context, accessToken string, brandId int64) (*api.BrandResponse, error)
}

// brandEditAPI is what a brand's page needs to be saved: what it is drawn with, and the write.
type brandEditAPI interface {
	brandEditReadAPI
	UpdateBrand(ctx context.Context, accessToken string, brandId int64, request *api.UpdateBrandRequest) (*api.BrandResponse, error)
}

// readBrandPage reads what a brand's page is drawn with, answering the page that says why when it
// cannot.
func readBrandPage(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient brandEditReadAPI,
	token string, id int64) (*api.BrandResponse, []api.BrandThemeResponse, bool) {

	brand, err := apiClient.GetBrandById(r.Context(), token, id)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return nil, nil, false
	}
	themes, err := apiClient.GetBrandThemes(r.Context(), token)
	if err != nil {
		render.HandleAPIError(httpHelper, w, r, err)
		return nil, nil, false
	}
	return brand, themes, true
}

// HandleBrandGet draws a brand's page: the form with what is stored, and Make default for a
// brand that is not the default. It says once that the brand was saved or made the default.
func HandleBrandGet(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient brandEditReadAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := brandIdFrom(httpHelper, w, r)
		if !ok {
			return
		}
		token, ok := accessTokenFrom(httpHelper, w, r)
		if !ok {
			return
		}
		brand, themes, ok := readBrandPage(httpHelper, w, r, apiClient, token, id)
		if !ok {
			return
		}

		sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
		if err != nil {
			httpHelper.InternalServerError(w, r, err)
			return
		}
		_, savedSuccessfully := sess.TakeFlash(r.URL.Path, "savedSuccessfully")
		_, madeDefault := sess.TakeFlash(r.URL.Path, "brandMadeDefault")
		if savedSuccessfully || madeDefault {
			if err := httpSession.Save(r, w, sess); err != nil {
				httpHelper.InternalServerError(w, r, err)
				return
			}
		}

		form := BrandForm{Name: brand.Name, Appearance: brand.Appearance, Theme: brand.Theme, Corners: brand.Corners,
			Font: brand.Font, BackgroundFit: brand.BackgroundFit, HideAppName: brand.HideAppName}
		renderBrandForm(httpHelper, w, r, form, themes, map[string]interface{}{
			"isNew":             false,
			"storedBrand":       *brand,
			"clientsNote":       brandClientsNote(r.Context(), brand.ClientCount),
			"savedSuccessfully": savedSuccessfully,
			"madeDefault":       madeDefault,
		})
	}
}

func HandleBrandPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient brandEditAPI,
	settingsCache SettingsInvalidator,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := brandIdFrom(httpHelper, w, r)
		if !ok {
			return
		}
		token, ok := accessTokenFrom(httpHelper, w, r)
		if !ok {
			return
		}
		brand, themes, ok := readBrandPage(httpHelper, w, r, apiClient, token, id)
		if !ok {
			return
		}

		// An update replaces every field (#813 decision 10), and the form has no field for the kit's
		// slots yet, so the brand's stored ones are sent back unchanged.
		form := brandFormFrom(r)
		_, err := apiClient.UpdateBrand(r.Context(), token, id, &api.UpdateBrandRequest{
			Name:          form.Name,
			Appearance:    form.Appearance,
			Theme:         form.Theme,
			Corners:       form.Corners,
			Font:          form.Font,
			BackgroundFit: form.BackgroundFit,
			HideAppName:   form.HideAppName,
			Logo:          storedSlot(brand.Logo),
			DarkLogo:      storedSlot(brand.DarkLogo),
			Favicon:       storedSlot(brand.Favicon),
			Background:    storedSlot(brand.Background),
			RegularFont:   storedSlot(brand.RegularFont),
			BoldFont:      storedSlot(brand.BoldFont),
		})
		if err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderBrandForm(httpHelper, w, r, form, themes, map[string]interface{}{
					"isNew":       false,
					"storedBrand": *brand,
					"clientsNote": brandClientsNote(r.Context(), brand.ClientCount),
					"error":       message,
					"errorField":  render.ErrorField(err, brandErrorFields),
				})
			})
			return
		}

		settingsCache.Invalidate()
		redirectToBrandWithFlash(httpHelper, httpSession, w, r, baseURL, id, "savedSuccessfully")
	}
}

// storedSlot names the asset a stored slot holds, as a write names it, or none for an empty slot.
func storedSlot(asset *api.BrandAssetResponse) *api.BrandAssetRef {
	if asset == nil {
		return nil
	}
	return &api.BrandAssetRef{Id: asset.Id}
}

// redirectToBrandWithFlash goes back to the brand's page, which says once what flash names.
func redirectToBrandWithFlash(httpHelper HttpHelper, httpSession sessionstore.Store, w http.ResponseWriter,
	r *http.Request, baseURL string, id int64, flash string) {

	sess, err := httpSession.Get(r, builtin.AdminConsoleSessionName)
	if err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}
	pagePath := fmt.Sprintf("%s/%d/edit", brandingPath, id)
	sess.SetFlash(pagePath, flash, "true")
	if err := httpSession.Save(r, w, sess); err != nil {
		httpHelper.InternalServerError(w, r, err)
		return
	}
	//nolint:gosec // G710: the configured base URL and a fixed path around the brand's numeric id
	http.Redirect(w, r, baseURL+pagePath, http.StatusFound)
}

// brandMakeDefaultAPI is what Make default needs: the write.
type brandMakeDefaultAPI interface {
	MakeBrandDefault(ctx context.Context, accessToken string, brandId int64) (*api.BrandResponse, error)
}

// HandleBrandMakeDefaultPost makes a brand the default, which draws in it at once every client with
// no brand of its own, and the pages that belong to no client.
func HandleBrandMakeDefaultPost(
	httpHelper HttpHelper,
	httpSession sessionstore.Store,
	apiClient brandMakeDefaultAPI,
	settingsCache SettingsInvalidator,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := brandIdFrom(httpHelper, w, r)
		if !ok {
			return
		}
		token, ok := accessTokenFrom(httpHelper, w, r)
		if !ok {
			return
		}

		if _, err := apiClient.MakeBrandDefault(r.Context(), token, id); err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		settingsCache.Invalidate()
		redirectToBrandWithFlash(httpHelper, httpSession, w, r, baseURL, id, "brandMadeDefault")
	}
}

// brandDeleteAPI is what the delete page needs: the brand, the brands it finds the default among,
// and the deletion.
type brandDeleteAPI interface {
	GetAllBrands(ctx context.Context, accessToken string) ([]api.BrandResponse, error)
	GetBrandById(ctx context.Context, accessToken string, brandId int64) (*api.BrandResponse, error)
	DeleteBrand(ctx context.Context, accessToken string, brandId int64) error
}

// renderBrandDelete draws the delete confirmation. For a brand that is not the default it says how
// many clients use it and, when any does, names the default brand they will move to, read from the
// brands the auth server marks it among.
func renderBrandDelete(httpHelper HttpHelper, w http.ResponseWriter, r *http.Request, apiClient brandDeleteAPI,
	token string, brand api.BrandResponse, message string) {

	bind := map[string]interface{}{
		"brand": brandRow(r.Context(), brand),
	}
	if !brand.IsDefault {
		defaultBrand := ""
		if brand.ClientCount > 0 {
			brands, err := apiClient.GetAllBrands(r.Context(), token)
			if err != nil {
				render.HandleAPIError(httpHelper, w, r, err)
				return
			}
			for _, candidate := range brands {
				if candidate.IsDefault {
					defaultBrand = candidate.Name
				}
			}
		}
		bind["clientsNote"] = deleteClientsNote(r.Context(), brand.ClientCount, defaultBrand)
	}
	if message != "" {
		bind["error"] = message
	}
	if err := httpHelper.RenderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_branding_delete.html", bind); err != nil {
		httpHelper.InternalServerError(w, r, err)
	}
}

// HandleBrandDeleteGet draws the delete confirmation, which for the default brand says it cannot
// be deleted.
func HandleBrandDeleteGet(
	httpHelper HttpHelper,
	apiClient brandDeleteAPI,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := brandIdFrom(httpHelper, w, r)
		if !ok {
			return
		}
		token, ok := accessTokenFrom(httpHelper, w, r)
		if !ok {
			return
		}

		brand, err := apiClient.GetBrandById(r.Context(), token, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}
		renderBrandDelete(httpHelper, w, r, apiClient, token, *brand, "")
	}
}

// HandleBrandDeletePost deletes the brand whose name is typed, exactly as stored, and the auth
// server moves the clients that use it to the default brand (#812 decision 1). It refuses deleting
// the default under the settings row's lock, so a brand made the default after the page was drawn
// is refused there, and the page says so.
func HandleBrandDeletePost(
	httpHelper HttpHelper,
	apiClient brandDeleteAPI,
	settingsCache SettingsInvalidator,
	baseURL string,
) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := brandIdFrom(httpHelper, w, r)
		if !ok {
			return
		}
		token, ok := accessTokenFrom(httpHelper, w, r)
		if !ok {
			return
		}

		brand, err := apiClient.GetBrandById(r.Context(), token, id)
		if err != nil {
			render.HandleAPIError(httpHelper, w, r, err)
			return
		}

		typed := r.PostFormValue("name")
		if typed == "" {
			renderBrandDelete(httpHelper, w, r, apiClient, token, *brand, i18n.T(r.Context(), "adminconsole.refusal.brand_delete.name_required"))
			return
		}
		if typed != brand.Name {
			renderBrandDelete(httpHelper, w, r, apiClient, token, *brand, i18n.T(r.Context(), "adminconsole.refusal.brand_delete.name_mismatch"))
			return
		}

		if err := apiClient.DeleteBrand(r.Context(), token, id); err != nil {
			render.HandleAPIErrorWithCallback(httpHelper, w, r, err, func(message string) {
				renderBrandDelete(httpHelper, w, r, apiClient, token, *brand, message)
			})
			return
		}

		settingsCache.Invalidate()
		http.Redirect(w, r, baseURL+brandingPath, http.StatusFound)
	}
}
