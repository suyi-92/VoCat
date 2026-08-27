package update

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAssetNamesFor(t *testing.T) {
	tests := []struct {
		goos   string
		goarch string
		want   []string
	}{
		{"linux", "amd64", []string{"vocat-linux-amd64.tar.gz"}},
		{"linux", "386", []string{"vocat-linux-386.tar.gz"}},
		{"linux", "arm64", []string{"vocat-linux-arm64.tar.gz", "vocat-linux-aarch64.tar.gz"}},
		{"linux", "arm", []string{"vocat-linux-armv7.tar.gz"}},
		{"windows", "amd64", []string{"vocat-windows-amd64.zip"}},
		{"windows", "arm64", []string{"vocat-windows-arm64.zip"}},
	}
	for _, item := range tests {
		if got := assetNamesFor(item.goos, item.goarch); !reflect.DeepEqual(got, item.want) {
			t.Errorf("assetNamesFor(%q, %q) = %#v, want %#v", item.goos, item.goarch, got, item.want)
		}
	}
}

func TestCheckReleaseForPlatformRequiresArchiveAndChecksums(t *testing.T) {
	base := &Release{
		TagName: "v2.0.0",
		Assets: []Asset{
			{Name: "vocat-linux-amd64.tar.gz", Size: 1},
			{Name: "SHA256SUMS", Size: 1},
		},
	}
	result, err := checkReleaseForPlatform(base, "1.0.0", "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Available || result.Release != base {
		t.Fatalf("result = %#v", result)
	}

	for _, test := range []struct {
		name    string
		assets  []Asset
		goos    string
		goarch  string
		current string
		wantErr bool
	}{
		{
			name: "missing Windows archive",
			assets: []Asset{
				{Name: "vocat-linux-amd64.tar.gz", Size: 1},
				{Name: "SHA256SUMS", Size: 1},
			},
			goos: "windows", goarch: "amd64", current: "1.0.0", wantErr: true,
		},
		{
			name: "missing checksums",
			assets: []Asset{
				{Name: "vocat-windows-amd64.zip", Size: 1},
			},
			goos: "windows", goarch: "amd64", current: "1.0.0", wantErr: true,
		},
		{
			name: "older release needs no assets",
			assets: []Asset{
				{Name: "source-only.zip"},
			},
			goos: "windows", goarch: "amd64", current: "3.0.0", wantErr: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			release := &Release{TagName: "v2.0.0", Assets: test.assets}
			_, err := checkReleaseForPlatform(release, test.current, test.goos, test.goarch)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestReleaseAssetsForPlatformRejectsUnsafePublishedSizes(t *testing.T) {
	tests := []struct {
		name        string
		archiveSize int64
		sumsSize    int64
	}{
		{name: "empty archive", archiveSize: 0, sumsSize: 1},
		{name: "oversized archive", archiveSize: maxReleaseArchiveSize + 1, sumsSize: 1},
		{name: "empty checksum manifest", archiveSize: 1, sumsSize: 0},
		{name: "oversized checksum manifest", archiveSize: 1, sumsSize: maxReleaseChecksumSize + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			release := &Release{
				TagName: "v2.0.0",
				Assets: []Asset{
					{Name: "vocat-linux-amd64.tar.gz", Size: test.archiveSize},
					{Name: "SHA256SUMS", Size: test.sumsSize},
				},
			}
			if _, _, err := releaseAssetsForPlatform(release, "linux", "amd64"); err == nil || !strings.Contains(err.Error(), "unsafe published size") {
				t.Fatalf("releaseAssetsForPlatform() error = %v", err)
			}
		})
	}
}

func TestDownloadAssetWithProgressVerifiesPublishedSize(t *testing.T) {
	payload := bytes.Repeat([]byte("vocat"), 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var destination bytes.Buffer
	asset := &Asset{Name: "vocat-test", BrowserDownloadURL: server.URL, Size: int64(len(payload))}
	if err := downloadAssetWithProgress(context.Background(), logger, asset, "", &destination); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(destination.Bytes(), payload) {
		t.Fatal("downloaded asset content differs")
	}

	asset.Size++
	if err := downloadAssetWithProgress(context.Background(), logger, asset, "", io.Discard); err == nil {
		t.Fatal("download with a mismatched published size succeeded")
	}
}

func TestDownloadAssetEnforcesDeclaredAndConfiguredLimitsBeforeConsumption(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 32)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	tooLarge := &Asset{Name: "oversized", BrowserDownloadURL: server.URL, Size: 5}
	if err := downloadAsset(context.Background(), tooLarge, "", 4, io.Discard); err == nil || !strings.Contains(err.Error(), "unsafe published size") {
		t.Fatalf("oversized metadata error = %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("oversized metadata made %d HTTP requests", got)
	}

	declared := &Asset{Name: "mismatched", BrowserDownloadURL: server.URL, Size: 4}
	var destination bytes.Buffer
	err := downloadAsset(context.Background(), declared, "", 4, &destination)
	if err == nil || !strings.Contains(err.Error(), "asset size mismatch") {
		t.Fatalf("oversized response error = %v", err)
	}
	if got := destination.Len(); got != int(declared.Size)+1 {
		t.Fatalf("download consumed %d bytes, want exactly declared size plus one", got)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("bounded response made %d HTTP requests", got)
	}
}
