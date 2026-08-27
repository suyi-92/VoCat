package update

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateExecutableRejectsNonExecutableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-vocat")
	if err := os.WriteFile(path, []byte("not an executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutable(context.Background(), path, "1.2.3"); err == nil {
		t.Fatal("validateExecutable accepted invalid file")
	}
}

func TestCandidateVersionFromOutputRejectsWrongReleaseVersion(t *testing.T) {
	for _, test := range []struct {
		name     string
		output   string
		expected string
		wantErr  string
	}{
		{name: "exact", output: "vocat 1.2.3\n", expected: "1.2.3"},
		{name: "exact with build time", output: "vocat 1.2.3-rc.1 (2026-08-27T10:11:12Z)\n", expected: "1.2.3-rc.1"},
		{name: "wrong archive version", output: "vocat 1.2.2\n", expected: "1.2.3", wantErr: "reports version 1.2.2"},
		{name: "non-semver", output: "vocat development\n", expected: "1.2.3", wantErr: "non-SemVer"},
		{name: "extra output", output: "warning\nvocat 1.2.3\n", expected: "1.2.3", wantErr: "unexpected version response"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateCandidateVersionOutput(test.output, test.expected)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("candidate validation error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestBackupAndReplaceRetainsPreviousBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux replacement behavior")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "vocat")
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := backupAndReplace(target, replacement); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(target + ".previous")
	if err != nil {
		t.Fatalf("read retained backup: %v", err)
	}
	if string(old) != "old" {
		t.Fatalf("backup = %q", old)
	}
}

func TestBackupAndReplaceReleaseCommitsBinaryAndArchiveTogether(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "vocat")
	archiveTarget := target + ".release.tar.gz"
	binaryTmp := filepath.Join(directory, "binary.tmp")
	archiveTmp := filepath.Join(directory, "archive.tmp")
	for path, content := range map[string]string{
		target:        "old binary",
		archiveTarget: "old archive",
		binaryTmp:     "new binary",
		archiveTmp:    "new archive",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := backupAndReplaceRelease(target, binaryTmp, archiveTarget, archiveTmp); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		target:                      "new binary",
		archiveTarget:               "new archive",
		target + ".previous":        "old binary",
		archiveTarget + ".previous": "old archive",
	} {
		content, err := os.ReadFile(path)
		if err != nil || string(content) != want {
			t.Errorf("%s = %q, %v; want %q", path, content, err, want)
		}
	}
}

func TestBackupAndReplaceReleaseRollsBackBothFiles(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "vocat")
	archiveTarget := target + ".release.tar.gz"
	binaryTmp := filepath.Join(directory, "binary.tmp")
	missingArchiveTmp := filepath.Join(directory, "missing-archive.tmp")
	for path, content := range map[string]string{
		target:        "old binary",
		archiveTarget: "old archive",
		binaryTmp:     "new binary",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := backupAndReplaceRelease(target, binaryTmp, archiveTarget, missingArchiveTmp); err == nil {
		t.Fatal("release replacement with a missing archive unexpectedly succeeded")
	}
	for path, want := range map[string]string{
		target:        "old binary",
		archiveTarget: "old archive",
	} {
		content, err := os.ReadFile(path)
		if err != nil || string(content) != want {
			t.Errorf("rollback %s = %q, %v; want %q", path, content, err, want)
		}
	}
}

func TestShouldApplyReleaseAllowsOnlySameVersionForceReinstall(t *testing.T) {
	tests := []struct {
		name      string
		result    CheckResult
		force     bool
		wantApply bool
		wantError string
	}{
		{
			name:      "newer release",
			result:    CheckResult{Available: true, Current: "1.0.0", Latest: "1.1.0"},
			wantApply: true,
		},
		{
			name:   "same release without force",
			result: CheckResult{Current: "1.0.0", Latest: "1.0.0"},
		},
		{
			name:      "same release with force",
			result:    CheckResult{Current: "1.0.0+local", Latest: "1.0.0"},
			force:     true,
			wantApply: true,
		},
		{
			name:      "older release with force",
			result:    CheckResult{Current: "2.0.0", Latest: "1.9.0"},
			force:     true,
			wantError: "refusing to downgrade",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apply, err := shouldApplyRelease(test.result, test.force)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("shouldApplyRelease() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if apply != test.wantApply {
				t.Fatalf("shouldApplyRelease() = %v, want %v", apply, test.wantApply)
			}
		})
	}
}
