package main

import (
	"os"
	"path/filepath"
	"strings"
)

// generatedFile is one file the wizard writes, under its default name.
type generatedFile struct {
	name    string
	content string
}

// generatedConfiguration returns the files the configured deployment type is configured by, under
// their default names, as writtenConfiguration writes them there.
func generatedConfiguration(config *Config) (description, secrets generatedFile) {
	return writtenConfiguration(config, config.Deployment.defaultPaths())
}

// writtenConfiguration returns the files the configured deployment type is configured by, written
// at paths, from the type's generators: the description of the deployment, and the file holding its
// secrets. The manifest and the Compose file hold none, so they can be committed; the native env
// file is both, being the secret material itself, and is returned twice (#396 decision 14). Each
// file's header names the files beside it by the names they are written under, and the commands it
// gives name them so.
func writtenConfiguration(config *Config, paths outputPaths) (description, secrets generatedFile) {
	d := config.Deployment
	description = generatedFile{name: filepath.Base(paths.description), content: d.generate(config, paths)}
	if d.secretsFile == "" {
		return description, description
	}
	return description, generatedFile{name: filepath.Base(paths.secrets), content: d.generateSecrets(config, paths)}
}

// outputPaths are where a configuration's description and its secrets file are written, the same
// path for a type whose one file is both.
type outputPaths struct {
	description string
	secrets     string
}

// separate says whether the secrets are in a file of their own.
func (p outputPaths) separate() bool {
	return p.description != p.secrets
}

// defaultPaths are the deployment's files under their default names, in no directory.
func (d *deployment) defaultPaths() outputPaths {
	if d.secretsFile == "" {
		return outputPaths{description: d.outputFile, secrets: d.outputFile}
	}
	return outputPaths{description: d.outputFile, secrets: d.secretsFile}
}

// resolveOutputPaths places the deployment's files: under their default names in the current
// directory, or in the directory output names, or, when output names a file, the description under
// that name and the secrets file beside it under the name derived from it.
func resolveOutputPaths(d *deployment, output string) outputPaths {
	dir, _ := os.Getwd()
	defaults := d.defaultPaths()
	description, secrets := defaults.description, defaults.secrets
	if output != "" {
		if isDirectory(output) {
			dir = output
		} else {
			dir = filepath.Dir(output)
			description = filepath.Base(output)
			secrets = d.secretsFileBeside(description)
		}
	}
	return outputPaths{description: filepath.Join(dir, description), secrets: filepath.Join(dir, secrets)}
}

// gitWorkingTree finds the git working tree dir is inside, by walking up from it for a .git entry,
// a repository's directory or a worktree's or submodule's file, with no git binary run. It answers
// the tree's root, or false outside every tree (#396 decision 15).
func gitWorkingTree(dir string) (string, bool) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// gitignorePattern is the line of the .gitignore at root that ignores the file at path and nothing
// else: anchored to the root by its leading slash, with every character gitignore reads as a
// pattern, and a trailing space it would drop, escaped.
func gitignorePattern(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = filepath.Base(path)
	}
	pattern := strings.NewReplacer(`\`, `\\`, "*", `\*`, "?", `\?`, "[", `\[`, "]", `\]`).Replace(filepath.ToSlash(rel))
	trimmed := strings.TrimRight(pattern, " ")
	return "/" + trimmed + strings.Repeat(`\ `, len(pattern)-len(trimmed))
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
	info, err := os.Stat(path) //nolint:gosec,nolintlint // G703: the path is the one the operator asked for with --output, on their own machine; nolintlint because gosec v2.29.0 finds this G703 on some runs only, leaving the directive unused on the others (securego/gosec#1712, #494)
	if err != nil {
		return false
	}
	return info.IsDir()
}
