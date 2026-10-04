package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Every file the wizard writes carries the admin password, the session keys and the AES key, and
// each was written 0644 (#426). The existing-file case is the one os.WriteFile alone gets wrong: it
// applies its mode only when it creates the file, so a re-run over an earlier 0644 output would
// leave the new secrets world-readable. The file staged beside the destination must not outlive
// the write either, since it holds the same secrets.
func TestWritePrivateFile_LeavesTheFileReadableByItsOwnerAlone(t *testing.T) {
	testCases := []struct {
		name         string
		existingMode os.FileMode
	}{
		{name: "a new file"},
		{name: "an existing 0644 file", existingMode: 0644},
		{name: "an existing 0666 file", existingMode: 0666},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "goiabada.env")
			if testCase.existingMode != 0 {
				if err := os.WriteFile(path, []byte("yesterday's secrets, and more of them"), 0600); err != nil {
					t.Fatal(err)
				}
				// Set apart from the write, so the umask cannot narrow the mode being overwritten.
				if err := os.Chmod(path, testCase.existingMode); err != nil {
					t.Fatal(err)
				}
			}

			if err := writePrivateFile(path, "today's secrets"); err != nil {
				t.Fatalf("writePrivateFile: %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Errorf("mode is %v, want -rw-------", got)
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(contents) != "today's secrets" {
				t.Errorf("contents are %q, want the new content alone", contents)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "goiabada.env" {
				t.Errorf("the directory holds %v, want goiabada.env alone", entryNames(entries))
			}
		})
	}
}

// Narrowing a file does not revoke a descriptor opened while it was readable, so a re-run that
// wrote into an earlier run's 0644 output and then chmodded it would hand the new secrets to any
// account that had opened the old file (#426). The new content has to land in a new inode, and
// the old descriptor must go on reading what it could already read. Run over each of the three
// files the wizard generates, with its real content.
func TestWritePrivateFile_AnEarlierReaderDoesNotSeeTheNewSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows refuses to replace a file another handle holds open, so the write fails rather than leaks")
	}
	config := testConfig()

	for _, kind := range []deploymentType{deploymentLocal, deploymentKubernetes, deploymentNative} {
		config.Deployment = deployments[kind]
		_, secrets := generatedConfiguration(config)
		filename, content := secrets.name, secrets.content
		t.Run(filename, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), filename)
			const yesterday = "yesterday's secrets"
			if err := os.WriteFile(path, []byte(yesterday), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			earlierReader, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = earlierReader.Close() }()

			if err = writePrivateFile(path, content); err != nil {
				t.Fatalf("writePrivateFile: %v", err)
			}

			seen, err := io.ReadAll(earlierReader)
			if err != nil {
				t.Fatal(err)
			}
			if string(seen) != yesterday {
				t.Errorf("the earlier reader sees %d bytes that are not the earlier content, want %q alone", len(seen), yesterday)
			}
			written, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(written) != content {
				t.Errorf("%s does not carry the generated content", filename)
			}
		})
	}
}

// A write that cannot replace its destination leaves no staged copy of the secrets behind. A
// directory standing at the destination path is a replace every platform refuses.
func TestWritePrivateFile_LeavesNothingBehindWhenTheReplaceFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "goiabada.env"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := writePrivateFile(filepath.Join(dir, "goiabada.env"), "today's secrets"); err == nil {
		t.Fatal("writePrivateFile replaced a directory, want an error")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "goiabada.env" || !entries[0].IsDir() {
		t.Errorf("the directory holds %v, want the goiabada.env directory alone", entryNames(entries))
	}
}

func entryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// main has one write, of whatever this returns, so each deployment type reaching writePrivateFile
// comes down to each type's file coming from here.
func TestGeneratedConfiguration_NamesEachDeploymentTypesFile(t *testing.T) {
	config := testConfig()

	testCases := []struct {
		deployment   deploymentType
		wantFilename string
		generator    func(*Config) string
	}{
		{deployment: deploymentLocal, wantFilename: "docker-compose.yml", generator: generateDockerCompose},
		{deployment: deploymentProduction, wantFilename: "docker-compose.yml", generator: generateDockerCompose},
		{deployment: deploymentKubernetes, wantFilename: "goiabada-k8s.yaml", generator: generateKubernetesManifests},
		{deployment: deploymentNative, wantFilename: "goiabada.env", generator: generateEnvFile},
	}

	for _, testCase := range testCases {
		t.Run(deployments[testCase.deployment].name, func(t *testing.T) {
			config.Deployment = deployments[testCase.deployment]
			description, secrets := generatedConfiguration(config)
			if description.name != testCase.wantFilename {
				t.Errorf("file name is %q, want %q", description.name, testCase.wantFilename)
			}
			if description.content != testCase.generator(config) {
				t.Errorf("content is not %s's generator output", testCase.wantFilename)
			}
			if !strings.Contains(secrets.content, "admin-password") {
				t.Errorf("%s carries no admin password, so it is not the file whose mode matters", secrets.name)
			}
		})
	}
}
