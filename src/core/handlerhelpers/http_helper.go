package handlerhelpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/customerrors"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/pkg/errors"
)

type HttpHelper struct {
	templateFS fs.FS
	database   data.Database
}

func NewHttpHelper(templateFS fs.FS, database data.Database) *HttpHelper {
	return &HttpHelper{
		templateFS: templateFS,
		database:   database,
	}
}

func (h *HttpHelper) InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	requestId := middleware.GetReqID(r.Context())
	slog.Error(fmt.Sprintf("%+v\nrequest-id: %v", err, requestId))

	w.WriteHeader(http.StatusInternalServerError)

	// render the error in the UI
	err = h.RenderTemplate(w, r, "/layouts/no_menu_layout.html", "/error.html", map[string]interface{}{
		"requestId": requestId,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("unable to render the error page: %v", err.Error()), http.StatusInternalServerError)
	}
}

func (h *HttpHelper) RenderTemplate(w http.ResponseWriter, r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) error {

	buf, err := h.RenderTemplateToBuffer(r, layoutName, templateName, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")

	if data != nil && data["_httpStatus"] != nil {
		httpStatus, ok := data["_httpStatus"].(int)
		if !ok {
			return errors.WithStack(errors.New("unable to cast _httpStatus to int"))
		}
		w.WriteHeader(httpStatus)
	}

	_, err = buf.WriteTo(w)
	if err != nil {
		return errors.WithStack(errors.New("unable to write to response writer"))
	}
	return nil
}

func (h *HttpHelper) RenderTemplateToBuffer(r *http.Request, layoutName string, templateName string,
	data map[string]interface{}) (*bytes.Buffer, error) {

	settings := r.Context().Value(constants.ContextKeySettings).(*models.Settings)
	data["appName"] = settings.AppName
	data["uiTheme"] = settings.UITheme
	data["urlPath"] = r.URL.Path
	data["smtpEnabled"] = settings.SMTPEnabled

	var jwtInfo oauth.JwtInfo
	if r.Context().Value(constants.ContextKeyJwtInfo) != nil {
		var ok bool
		jwtInfo, ok = r.Context().Value(constants.ContextKeyJwtInfo).(oauth.JwtInfo)
		if !ok {
			return nil, errors.WithStack(errors.New("unable to cast jwtInfo to dtos.JwtInfo"))
		}
		if jwtInfo.IdToken != nil && jwtInfo.IdToken.Claims["sub"] != nil {
			sub := jwtInfo.IdToken.Claims["sub"].(string)
			user, err := h.database.GetUserBySubject(nil, sub)
			if err != nil {
				return nil, err
			}
			if user != nil {
				data["loggedInUser"] = user
			}
		}
	}

	name := filepath.Base(layoutName)

	templateName = strings.TrimPrefix(templateName, "/")
	layoutName = strings.TrimPrefix(layoutName, "/")

	templateFiles := []string{
		layoutName,
		templateName,
	}

	files, err := fs.ReadDir(h.templateFS, "partials")
	if err == nil && len(files) > 0 {
		// Partials directory exists and has files, so include them
		for _, file := range files {
			templateFiles = append(templateFiles, "partials/"+file.Name())
		}
	}

	templ, err := template.New(name).Funcs(templateFuncMap).ParseFS(h.templateFS, templateFiles...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to render template")
	}
	var buf bytes.Buffer
	err = templ.Execute(&buf, data)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute template")
	}
	return &buf, nil
}

func (h *HttpHelper) JsonError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")

	requestId := middleware.GetReqID(r.Context())

	errorStr := ""
	errorDescriptionStr := ""

	errorDetail, ok := err.(*customerrors.ErrorDetail)
	if ok {
		// error detail
		statusCode := errorDetail.GetHttpStatusCode()
		if statusCode == 0 {
			statusCode = http.StatusInternalServerError
		}
		w.WriteHeader(statusCode)
		errorStr = errorDetail.GetCode()
		errorDescriptionStr = errorDetail.GetDescription()
	} else {
		// any other error
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error(fmt.Sprintf("%+v\nrequest-id: %v", err, requestId))
		errorStr = "server_error"
		errorDescriptionStr = fmt.Sprintf("An unexpected server error has occurred. For additional information, refer to the server logs. Request Id: %v", requestId)
	}

	values := map[string]string{
		"error":             errorStr,
		"error_description": errorDescriptionStr,
	}
	err = json.NewEncoder(w).Encode(values)
	if err != nil {
		h.InternalServerError(w, r, err)
	}
}

func (h *HttpHelper) EncodeJson(w http.ResponseWriter, r *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		h.JsonError(w, r, err)
	}
}

func (h *HttpHelper) GetFromUrlQueryOrFormPost(r *http.Request, key string) string {
	value := r.URL.Query().Get(key)
	if len(value) == 0 {
		value = r.FormValue(key)
	}
	return value
}
