package lib

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

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
		return "", fmt.Errorf("dir %v is empty, can't select a random file", dir)
	}

	randomIndex := rand.Intn(len(files))
	randomFile := files[randomIndex]

	filename := randomFile.Name()
	return filepath.Join("/static", path, filename), nil
}
