package main

import (
	"os"
	"path/filepath"
)

// generatedConfiguration returns the file a deployment type is configured by, under its default
// name: Kubernetes manifests for type 3, an environment file for native binaries (type 4), and a
// docker-compose file for the two Docker types.
func generatedConfiguration(deploymentType string, config *Config) (filename, content string) {
	switch deploymentType {
	case "3":
		return "goiabada-k8s.yaml", generateKubernetesManifests(config)
	case "4":
		return "goiabada.env", generateEnvFile(config)
	default:
		return "docker-compose.yml", generateDockerCompose(config)
	}
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
