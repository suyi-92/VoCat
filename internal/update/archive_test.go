package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type testArchiveEntry struct {
	name     string
	body     []byte
	typeflag byte
	mode     os.FileMode
}

func TestExtractReleaseBinary(t *testing.T) {
	tests := []struct {
		name        string
		archiveName string
		write       func(*testing.T, string, []testArchiveEntry)
		binaryName  string
	}{
		{
			name:        "tar gzip",
			archiveName: "vocat-linux-amd64.tar.gz",
			write:       writeTestTarGzip,
			binaryName:  "vocat-linux-amd64",
		},
		{
			name:        "zip",
			archiveName: "vocat-windows-amd64.zip",
			write:       writeTestZip,
			binaryName:  "vocat-windows-amd64.exe",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), test.archiveName)
			test.write(t, archivePath, []testArchiveEntry{
				{name: test.binaryName, body: []byte("executable"), mode: 0o755},
				{name: "LICENSE", body: []byte("license"), mode: 0o644},
				{name: "NOTICE", body: []byte("notice"), mode: 0o644},
				{name: "LICENSES/", typeflag: tar.TypeDir, mode: os.ModeDir | 0o755},
				{name: "LICENSES/dependency.txt", body: []byte("dependency"), mode: 0o644},
			})
			var extracted bytes.Buffer
			if err := extractReleaseBinary(archivePath, test.archiveName, &extracted); err != nil {
				t.Fatal(err)
			}
			if got := extracted.String(); got != "executable" {
				t.Fatalf("extracted binary = %q", got)
			}
		})
	}
}

func TestExtractReleaseBinaryRejectsUnsafeArchives(t *testing.T) {
	tests := []struct {
		name    string
		entries []testArchiveEntry
	}{
		{
			name: "path traversal",
			entries: []testArchiveEntry{
				{name: "vocat-linux-amd64", body: []byte("binary"), mode: 0o755},
				{name: "../outside", body: []byte("unsafe"), mode: 0o644},
			},
		},
		{
			name: "symbolic link",
			entries: []testArchiveEntry{
				{name: "vocat-linux-amd64", body: []byte("binary"), mode: 0o755},
				{name: "LICENSES/link", body: []byte("target"), typeflag: tar.TypeSymlink, mode: os.ModeSymlink | 0o777},
			},
		},
		{
			name: "duplicate executable",
			entries: []testArchiveEntry{
				{name: "vocat-linux-amd64", body: []byte("first"), mode: 0o755},
				{name: "vocat-linux-amd64", body: []byte("second"), mode: 0o755},
			},
		},
		{
			name:    "missing executable",
			entries: []testArchiveEntry{{name: "NOTICE", body: []byte("notice"), mode: 0o644}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "vocat-linux-amd64.tar.gz")
			writeTestTarGzip(t, archivePath, test.entries)
			if err := extractReleaseBinary(archivePath, "vocat-linux-amd64.tar.gz", &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe release archive was accepted")
			}
		})
	}
}

func TestExtractReleaseBinaryRequiresExactManifest(t *testing.T) {
	writers := []struct {
		name        string
		archiveName string
		binaryName  string
		write       func(*testing.T, string, []testArchiveEntry)
	}{
		{"tar gzip", "vocat-linux-amd64.tar.gz", "vocat-linux-amd64", writeTestTarGzip},
		{"zip", "vocat-windows-amd64.zip", "vocat-windows-amd64.exe", writeTestZip},
	}
	for _, writer := range writers {
		for _, test := range []struct {
			name   string
			mutate func([]testArchiveEntry) []testArchiveEntry
		}{
			{
				name: "missing LICENSE",
				mutate: func(entries []testArchiveEntry) []testArchiveEntry {
					return append(entries[:1], entries[2:]...)
				},
			},
			{
				name: "missing NOTICE",
				mutate: func(entries []testArchiveEntry) []testArchiveEntry {
					return append(entries[:2], entries[3:]...)
				},
			},
			{
				name: "missing third-party licenses",
				mutate: func(entries []testArchiveEntry) []testArchiveEntry {
					return entries[:3]
				},
			},
			{
				name: "duplicate LICENSE",
				mutate: func(entries []testArchiveEntry) []testArchiveEntry {
					return append(entries, testArchiveEntry{name: "LICENSE", body: []byte("duplicate"), mode: 0o644})
				},
			},
			{
				name: "undeclared member",
				mutate: func(entries []testArchiveEntry) []testArchiveEntry {
					return append(entries, testArchiveEntry{name: "README.md", body: []byte("extra"), mode: 0o644})
				},
			},
		} {
			t.Run(writer.name+"/"+test.name, func(t *testing.T) {
				entries := []testArchiveEntry{
					{name: writer.binaryName, body: []byte("executable"), mode: 0o755},
					{name: "LICENSE", body: []byte("license"), mode: 0o644},
					{name: "NOTICE", body: []byte("notice"), mode: 0o644},
					{name: "LICENSES/dependency.txt", body: []byte("dependency"), mode: 0o644},
				}
				archivePath := filepath.Join(t.TempDir(), writer.archiveName)
				writer.write(t, archivePath, test.mutate(entries))
				if err := extractReleaseBinary(archivePath, writer.archiveName, &bytes.Buffer{}); err == nil {
					t.Fatal("invalid release manifest was accepted")
				}
			})
		}
	}
}

func TestExtractReleaseBinaryRejectsOversizedEntry(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "vocat-linux-amd64.tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{
		Name:     "vocat-linux-amd64",
		Mode:     0o755,
		Size:     maxReleaseEntrySize + 1,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	// The extractor rejects the declared size before reading the intentionally
	// omitted body. Do not close tarWriter because it correctly reports that the
	// test fixture did not provide the oversized payload.
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractReleaseBinary(archivePath, "vocat-linux-amd64.tar.gz", &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unsafe size") {
		t.Fatalf("oversized entry error = %v", err)
	}
}

func TestReleaseArchiveManifestBoundsMembersAndExpandedSize(t *testing.T) {
	members := newReleaseArchiveManifest("vocat-linux-amd64")
	for index := 0; index < maxReleaseMemberCount; index++ {
		name := "LICENSES/license-" + strconv.Itoa(index) + ".txt"
		if _, err := members.inspect(name, false, 1); err != nil {
			t.Fatalf("member %d: %v", index, err)
		}
	}
	if _, err := members.inspect("LICENSES/overflow.txt", false, 1); err == nil {
		t.Fatal("archive member-count limit was not enforced")
	}

	expanded := newReleaseArchiveManifest("vocat-linux-amd64")
	if _, err := expanded.inspect("LICENSES/large.txt", false, maxReleaseExpandedSize); err != nil {
		t.Fatal(err)
	}
	if _, err := expanded.inspect("LICENSES/overflow.txt", false, 1); err == nil {
		t.Fatal("archive expanded-size limit was not enforced")
	}
}

func TestExtractReleaseBinaryRejectsOversizedArchive(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "vocat-linux-amd64.tar.gz")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxReleaseArchiveSize + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractReleaseBinary(archivePath, "vocat-linux-amd64.tar.gz", &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unsafe size") {
		t.Fatalf("oversized archive error = %v", err)
	}
}

func TestArchiveBinaryNameAndRetainedPath(t *testing.T) {
	tests := []struct {
		archive  string
		binary   string
		retained string
	}{
		{"vocat-linux-arm64.tar.gz", "vocat-linux-arm64", "/opt/vocat/bin/vocat.release.tar.gz"},
		{"vocat-windows-arm64.zip", "vocat-windows-arm64.exe", "/opt/vocat/bin/vocat.release.zip"},
	}
	for _, test := range tests {
		binary, err := archiveBinaryName(test.archive)
		if err != nil || binary != test.binary {
			t.Errorf("archiveBinaryName(%q) = %q, %v", test.archive, binary, err)
		}
		retained, err := retainedArchivePath("/opt/vocat/bin/vocat", test.archive)
		if err != nil || retained != test.retained {
			t.Errorf("retainedArchivePath(%q) = %q, %v", test.archive, retained, err)
		}
	}
	if _, err := archiveBinaryName("vocat-linux-amd64"); err == nil {
		t.Fatal("bare release binary was accepted as an archive")
	}
}

func writeTestTarGzip(t *testing.T, archivePath string, entries []testArchiveEntry) {
	t.Helper()
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		header := &tar.Header{
			Name:     entry.name,
			Mode:     int64(entry.mode.Perm()),
			Size:     int64(len(entry.body)),
			Typeflag: typeflag,
		}
		if typeflag == tar.TypeDir {
			header.Size = 0
		}
		if typeflag == tar.TypeSymlink {
			header.Size = 0
			header.Linkname = string(entry.body)
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := tarWriter.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTestZip(t *testing.T, archivePath string, entries []testArchiveEntry) {
	t.Helper()
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	zipWriter := zip.NewWriter(file)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		mode := entry.mode
		if entry.typeflag == tar.TypeDir {
			mode = os.ModeDir | mode.Perm()
		}
		header.SetMode(mode)
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if !mode.IsDir() {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
