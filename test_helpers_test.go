package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newTestGitRepository(t *testing.T) (*GitRepository, string) {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	testGit(t, directory, "init", "-b", "master")
	testGit(t, directory, "config", "user.name", "AIR Test")
	testGit(t, directory, "config", "user.email", "air-test@example.invalid")
	repository, err := DiscoverGitRepository(context.Background(), directory)
	if err != nil {
		t.Fatalf("DiscoverGitRepository: %v", err)
	}
	if repository.WorkTree != directory {
		t.Fatalf("worktree = %q, want %q", repository.WorkTree, directory)
	}
	return repository, directory
}

func testCommitFile(t *testing.T, directory, name string, contents []byte, message string) string {
	t.Helper()
	filename := filepath.Join(directory, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filename, contents, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	testGit(t, directory, "add", "--", name)
	testGit(t, directory, "commit", "-m", message)
	return strings.TrimSpace(testGit(t, directory, "rev-parse", "HEAD"))
}

func testGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", directory}, args...)
	command := exec.Command("git", commandArgs...)
	command.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return string(output)
}

// Absolute path to `true`
var testTrueBinary = func() string {
	if path, err := exec.LookPath("true"); err == nil && filepath.IsAbs(path) {
		return path
	}
	return "/bin/true"
}()

func TestMain(m *testing.M) {
	// GIT_EDITOR overrides the core.editor that tests configure; some
	// environments (e.g. editor-integrated terminals) set it globally.
	os.Unsetenv("GIT_EDITOR")
	os.Exit(m.Run())
}
