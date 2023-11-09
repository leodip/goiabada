package server

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/csrf"
	"github.com/leodip/goiabada/internal/common"
	"github.com/leodip/goiabada/internal/lib"
)

func (s *Server) handleAdminSettingsKeysGet() http.HandlerFunc {

	type keyInfo struct {
		Id               uint
		CreatedAt        time.Time
		IsCurrent        bool
		KeyIdentifier    string
		Type             string
		Algorithm        string
		PublicKeyASN1DER string
		PublicKeyPEM     string
		PublicKeyJson    string
	}

	return func(w http.ResponseWriter, r *http.Request) {

		allSigningKeys, err := s.database.GetAllSigningKeys()
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		keys := make([]keyInfo, 0, len(allSigningKeys))
		for _, signingKey := range allSigningKeys {
			ki := keyInfo{
				Id:            signingKey.Id,
				CreatedAt:     signingKey.CreatedAt,
				IsCurrent:     signingKey.IsCurrent,
				KeyIdentifier: signingKey.KeyIdentifier,
				Type:          signingKey.Type,
				Algorithm:     signingKey.Algorithm,
			}

			ki.PublicKeyASN1DER = base64.StdEncoding.EncodeToString(signingKey.PublicKeyASN1_DER)
			ki.PublicKeyPEM = string(signingKey.PublicKeyPEM)
			ki.PublicKeyJson = string(signingKey.PublicKeyJson)

			keys = append(keys, ki)
		}

		sess, err := s.sessionStore.Get(r, common.SessionName)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		savedSuccessfully := sess.Flashes("savedSuccessfully")
		err = sess.Save(r, w)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}

		bind := map[string]interface{}{
			"keys":              keys,
			"savedSuccessfully": len(savedSuccessfully) > 0,
			"csrfField":         csrf.TemplateField(r),
		}

		err = s.renderTemplate(w, r, "/layouts/menu_layout.html", "/admin_settings_keys.html", bind)
		if err != nil {
			s.internalServerError(w, r, err)
			return
		}
	}
}

func (s *Server) handleAdminSettingsKeysPost() http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {

		http.Redirect(w, r, fmt.Sprintf("%v/admin/settings/keys", lib.GetBaseUrl()), http.StatusFound)
	}
}
