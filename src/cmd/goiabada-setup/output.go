package main

import (
	"os"
	"path/filepath"
)

// generatedConfiguration returns the file the configured deployment type is configured by, under
// its default name, from the type's generator.
func generatedConfiguration(config *Config) (filename, content string) {
	return config.Deployment.outputFile, config.Deployment.generate(config)
}

// writePrivateFile writes a generated file readable by its owner alone. Every file this wizard
// generates carries the admin password, the session keys and the AES key, and each was written
// 0644, readable by every account on the host (#426). The content goes into a new file that
// os.CreateTemp creates 0600 beside the destination, and that file is renamed over it, so the
// secrets are never in a file anyone else could open. Writing into the existing file and narrowing
// it afterwards is not enough on a re-run: an account that opened an earlier run's 0644 output
// keeps its descriptor through a chmod and would read the new secrets through it, and the old
// inode is what that descriptor names. Staging in the same directory keeps the rename on one
// filesystem.
func writePrivateFile(path, content string) error {
	staged, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	discard := func(err error) error {
		_ = staged.Close()
		_ = os.Remove(staged.Name())
		return err
	}
	if _, err := staged.WriteString(content); err != nil {
		return discard(err)
	}
	if err := staged.Close(); err != nil {
		return discard(err)
	}
	if err := os.Rename(staged.Name(), path); err != nil {
		return discard(err)
	}
	return nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}
