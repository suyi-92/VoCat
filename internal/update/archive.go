package update

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

const (
	maxReleaseArchiveSize  int64 = 512 << 20
	maxReleaseEntrySize    int64 = 256 << 20
	maxReleaseExpandedSize int64 = 512 << 20
	maxReleaseMemberCount        = 1024
)

var releaseLicenseFilename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*\.txt$`)

type releaseArchiveManifest struct {
	expected   string
	seen       map[string]struct{}
	binary     bool
	license    bool
	notice     bool
	thirdParty int
	members    int
	expanded   int64
}

// archiveBinaryName returns the exact root-level executable expected inside a
// release archive. Tying the entry name to the signed-off asset name prevents
// an archive from selecting an arbitrary executable by ordering entries.
func archiveBinaryName(archiveName string) (string, error) {
	switch {
	case strings.HasSuffix(archiveName, ".tar.gz"):
		name := strings.TrimSuffix(archiveName, ".tar.gz")
		if name != "" {
			return name, nil
		}
	case strings.HasSuffix(archiveName, ".zip"):
		name := strings.TrimSuffix(archiveName, ".zip")
		if name != "" {
			return name + ".exe", nil
		}
	}
	return "", fmt.Errorf("update: unsupported release archive %q", archiveName)
}

func retainedArchivePath(target, archiveName string) (string, error) {
	switch {
	case strings.HasSuffix(archiveName, ".tar.gz"):
		return target + ".release.tar.gz", nil
	case strings.HasSuffix(archiveName, ".zip"):
		return target + ".release.zip", nil
	default:
		return "", fmt.Errorf("update: unsupported release archive %q", archiveName)
	}
}

// extractReleaseBinary reads a verified platform archive and writes its single
// expected executable to dst. It validates every member even though only the
// executable is extracted, so unsafe metadata cannot hide in an archive that
// is retained alongside the installation.
func extractReleaseBinary(archivePath, archiveName string, dst io.Writer) error {
	expected, err := archiveBinaryName(archiveName)
	if err != nil {
		return err
	}
	info, err := os.Stat(archivePath)
	if err != nil {
		return fmt.Errorf("update: stat release archive: %w", err)
	}
	if info.Size() <= 0 || info.Size() > maxReleaseArchiveSize {
		return fmt.Errorf("update: release archive has unsafe size %d", info.Size())
	}
	switch {
	case strings.HasSuffix(archiveName, ".tar.gz"):
		return extractTarGzipBinary(archivePath, expected, dst)
	case strings.HasSuffix(archiveName, ".zip"):
		return extractZipBinary(archivePath, expected, dst)
	default:
		return fmt.Errorf("update: unsupported release archive %q", archiveName)
	}
}

func extractTarGzipBinary(archivePath, expected string, dst io.Writer) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("update: open release archive: %w", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("update: open gzip release archive: %w", err)
	}
	defer gzipReader.Close()

	tape := tar.NewReader(gzipReader)
	manifest := newReleaseArchiveManifest(expected)
	for {
		header, nextErr := tape.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("update: read tar release archive: %w", nextErr)
		}
		name, err := validateArchiveEntryName(header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return fmt.Errorf("update: archive directory %q has unexpected content", header.Name)
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxReleaseEntrySize {
				return fmt.Errorf("update: archive entry %q has unsafe size %d", header.Name, header.Size)
			}
		default:
			return fmt.Errorf("update: archive entry %q is not a regular file or directory", header.Name)
		}
		extract, err := manifest.inspect(name, header.Typeflag == tar.TypeDir, header.Size)
		if err != nil {
			return err
		}
		if !extract {
			continue
		}
		if err := copyArchiveEntry(dst, tape, header.Size, expected); err != nil {
			return err
		}
	}
	return manifest.validate()
}

func extractZipBinary(archivePath, expected string, dst io.Writer) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("update: open release archive: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("update: stat release archive: %w", err)
	}
	reader, err := zip.NewReader(file, info.Size())
	if err != nil {
		return fmt.Errorf("update: open zip release archive: %w", err)
	}

	manifest := newReleaseArchiveManifest(expected)
	for _, member := range reader.File {
		name, err := validateArchiveEntryName(member.Name)
		if err != nil {
			return err
		}
		isDirectory := member.FileInfo().IsDir()
		if !isDirectory && !member.Mode().IsRegular() {
			return fmt.Errorf("update: archive entry %q is not a regular file or directory", member.Name)
		}
		if member.UncompressedSize64 > uint64(maxReleaseEntrySize) {
			return fmt.Errorf("update: archive entry %q has unsafe size %d", member.Name, member.UncompressedSize64)
		}
		extract, err := manifest.inspect(name, isDirectory, int64(member.UncompressedSize64))
		if err != nil {
			return err
		}
		if !extract {
			continue
		}
		entry, err := member.Open()
		if err != nil {
			return fmt.Errorf("update: open archive executable %q: %w", expected, err)
		}
		copyErr := copyArchiveEntry(dst, entry, int64(member.UncompressedSize64), expected)
		closeErr := entry.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return fmt.Errorf("update: close archive executable %q: %w", expected, closeErr)
		}
	}
	return manifest.validate()
}

func newReleaseArchiveManifest(expected string) *releaseArchiveManifest {
	return &releaseArchiveManifest{expected: expected, seen: make(map[string]struct{})}
}

func (manifest *releaseArchiveManifest) inspect(name string, directory bool, size int64) (bool, error) {
	manifest.members++
	if manifest.members > maxReleaseMemberCount {
		return false, fmt.Errorf("update: release archive contains more than %d members", maxReleaseMemberCount)
	}
	if size < 0 || size > maxReleaseExpandedSize-manifest.expanded {
		return false, fmt.Errorf("update: release archive expanded size exceeds %d bytes", maxReleaseExpandedSize)
	}
	manifest.expanded += size
	if _, duplicate := manifest.seen[name]; duplicate {
		return false, fmt.Errorf("update: release archive contains duplicate member %q", name)
	}
	manifest.seen[name] = struct{}{}
	if directory {
		if name != "LICENSES" {
			return false, fmt.Errorf("update: release archive contains undeclared directory %q", name)
		}
		return false, nil
	}
	if size <= 0 {
		return false, fmt.Errorf("update: release archive member %q is empty", name)
	}
	switch name {
	case manifest.expected:
		manifest.binary = true
		return true, nil
	case "LICENSE":
		manifest.license = true
		return false, nil
	case "NOTICE":
		manifest.notice = true
		return false, nil
	}
	if strings.HasPrefix(name, "LICENSES/") {
		filename := strings.TrimPrefix(name, "LICENSES/")
		if !releaseLicenseFilename.MatchString(filename) {
			return false, fmt.Errorf("update: release archive contains invalid third-party license path %q", name)
		}
		manifest.thirdParty++
		return false, nil
	}
	return false, fmt.Errorf("update: release archive contains undeclared member %q", name)
}

func (manifest *releaseArchiveManifest) validate() error {
	if !manifest.binary {
		return fmt.Errorf("update: release archive missing executable %q", manifest.expected)
	}
	if !manifest.license {
		return errors.New("update: release archive missing LICENSE")
	}
	if !manifest.notice {
		return errors.New("update: release archive missing NOTICE")
	}
	if manifest.thirdParty == 0 {
		return errors.New("update: release archive contains no third-party license files under LICENSES")
	}
	return nil
}

func validateArchiveEntryName(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") || strings.Contains(name, ":") {
		return "", fmt.Errorf("update: release archive contains unsafe path %q", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || path.IsAbs(trimmed) {
		return "", fmt.Errorf("update: release archive contains unsafe path %q", name)
	}
	cleaned := path.Clean(trimmed)
	if cleaned != trimmed || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("update: release archive contains unsafe path %q", name)
	}
	return cleaned, nil
}

func copyArchiveEntry(dst io.Writer, src io.Reader, declaredSize int64, name string) error {
	limited := &io.LimitedReader{R: src, N: maxReleaseEntrySize + 1}
	written, err := io.Copy(dst, limited)
	if err != nil {
		return fmt.Errorf("update: extract archive executable %q: %w", name, err)
	}
	if written != declaredSize {
		return fmt.Errorf("update: archive executable %q size mismatch: extracted %d bytes, expected %d", name, written, declaredSize)
	}
	return nil
}
