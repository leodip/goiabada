package lib

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"

	"github.com/leodip/goiabada/internal/customerrors"
	"github.com/spf13/viper"
)

func GetRandomStaticFile(path string) (string, error) {
	staticDir := viper.GetString("StaticDir")
	dir := filepath.Join(staticDir, path)

	files, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	if len(files) == 0 {
		return "", customerrors.NewAppError(nil, "", fmt.Sprintf("dir %v is empty, can't select a random file", dir), http.StatusInternalServerError)
	}

	randomIndex := rand.Intn(len(files))
	randomFile := files[randomIndex]

	filename := randomFile.Name()
	return filepath.Join("/static", path, filename), nil
}
