//go:build windows

package wintunsecure

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestInspectRejectsTrustedDLLWithMissingWintunExports(t *testing.T) {
	path := filepath.Join(mustSystemDirectory(t), "version.dll")
	report, err := inspect(path, requiredExports, nil)
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Failure != FailureExportsMissing {
		t.Fatalf("inspect(version.dll) = %#v, %v", report, err)
	}
	if len(validationErr.MissingExports) == 0 || len(report.MissingExports) == 0 {
		t.Fatalf("missing export evidence was not retained: %#v / %#v", validationErr, report)
	}
}

func TestInspectAllowsUnsignedDLLOnlyForExactSHA256(t *testing.T) {
	path := copySystemDLL(t, "unsigned-fixture.dll")
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	byteAtOffset := []byte{0}
	if _, err := file.ReadAt(byteAtOffset, 0x40); err != nil {
		file.Close()
		t.Fatal(err)
	}
	byteAtOffset[0] ^= 0xff
	if _, err := file.WriteAt(byteAtOffset, 0x40); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthenticode(path); err == nil {
		t.Fatal("modified DLL retained Authenticode trust unexpectedly")
	}
	digest := fileSHA256(t, path)
	report, err := inspect(path, []string{"GetFileVersionInfoW"}, []string{digest})
	if err != nil {
		t.Fatalf("exact SHA-256 allowlist entry was rejected: %v", err)
	}
	if report.Trust != "sha256" || report.SHA256 != digest {
		t.Fatalf("hash trust evidence = %#v", report)
	}
	_, err = inspect(path, []string{"GetFileVersionInfoW"}, []string{string(make([]byte, 64))})
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) || validationErr.Failure != FailureUntrusted {
		t.Fatalf("incorrect SHA-256 allowlist entry was accepted: %v", err)
	}
}

func TestSecureLoadLocksReplacementAndBindsValidatedFile(t *testing.T) {
	target := copySystemDLL(t, "locked-fixture.dll")
	replacement := copySystemDLL(t, "replacement-fixture.dll")
	var replacementErr error
	module, report, err := secureLoad(
		target,
		[]string{"GetFileVersionInfoW"},
		nil,
		func() {
			from, fromErr := windows.UTF16PtrFromString(replacement)
			to, toErr := windows.UTF16PtrFromString(target)
			if fromErr != nil || toErr != nil {
				replacementErr = errors.Join(fromErr, toErr)
				return
			}
			replacementErr = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING)
		},
	)
	if module != 0 {
		defer windows.FreeLibrary(module)
	}
	if err != nil {
		t.Fatalf("secureLoad() failed: %v", err)
	}
	if replacementErr == nil {
		t.Fatal("validated DLL was replaceable before LoadLibraryEx")
	}
	if report.LoadedPath == "" {
		t.Fatalf("loaded module path was not recorded: %#v", report)
	}
	validatedInfo, err := os.Stat(report.Path)
	if err != nil {
		t.Fatal(err)
	}
	loadedInfo, err := os.Stat(report.LoadedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(validatedInfo, loadedInfo) {
		t.Fatalf("loaded module %q is not validated file %q", report.LoadedPath, report.Path)
	}
	basenameModule, err := windows.LoadLibraryEx(
		filepath.Base(target),
		0,
		windows.LOAD_LIBRARY_SEARCH_APPLICATION_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32,
	)
	if err != nil {
		t.Fatalf("basename lookup did not reuse the securely loaded module: %v", err)
	}
	defer windows.FreeLibrary(basenameModule)
	basenamePath, err := modulePath(basenameModule)
	if err != nil {
		t.Fatal(err)
	}
	basenameInfo, err := os.Stat(basenamePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(validatedInfo, basenameInfo) {
		t.Fatalf("basename lookup resolved %q instead of validated file %q", basenamePath, report.Path)
	}
}

func TestSecureLoadRejectsPreloadedSameBasenameCollision(t *testing.T) {
	root := t.TempDir()
	firstDirectory := filepath.Join(root, "first")
	secondDirectory := filepath.Join(root, "second")
	if err := os.MkdirAll(firstDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secondDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	const basename = "same-basename-fixture.dll"
	preloadedPath := copySystemDLLTo(t, filepath.Join(firstDirectory, basename))
	candidatePath := copySystemDLLTo(t, filepath.Join(secondDirectory, basename))
	preloaded, err := windows.LoadLibraryEx(preloadedPath, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.FreeLibrary(preloaded)

	module, _, err := secureLoad(
		candidatePath,
		[]string{"GetFileVersionInfoW"},
		nil,
		nil,
	)
	if module != 0 {
		defer windows.FreeLibrary(module)
	}
	if err == nil {
		t.Fatal("secure loader accepted a candidate while another file with the same basename was preloaded")
	}
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) ||
		(validationErr.Failure != FailureExportsUnreadable &&
			validationErr.Failure != FailureLoadedPathMismatch) {
		t.Fatalf("same-basename collision error = %v", err)
	}
}

func copySystemDLL(t *testing.T, name string) string {
	t.Helper()
	destination := filepath.Join(t.TempDir(), name)
	return copySystemDLLTo(t, destination)
}

func copySystemDLLTo(t *testing.T, destination string) string {
	t.Helper()
	source := filepath.Join(mustSystemDirectory(t), "version.dll")
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	return destination
}

func mustSystemDirectory(t *testing.T) string {
	t.Helper()
	directory, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
