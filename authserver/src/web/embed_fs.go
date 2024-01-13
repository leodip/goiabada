package web

import (
	"embed"
	"io/fs"
	"log/slog"
)

//go:embed static
var staticFS embed.FS

//go:embed template
var templateFS embed.FS

func StaticFS() fs.FS {
	if retFS, err := fs.Sub(staticFS, "static"); err != nil {
		slog.Error(err.Error())
		return nil
	} else {
		return retFS
	}
}

func TemplateFS() fs.FS {
	if retFS, err := fs.Sub(templateFS, "template"); err != nil {
		slog.Error(err.Error())
		return nil
	} else {
		return retFS
	}
}
