package update

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestAssetNamesFor(t *testing.T) {
	tests := []struct {
		goos   string
		goarch string
		want   []string
	}{
		{"linux", "amd64", []string{"vocat-linux-amd64"}},
		{"linux", "386", []string{"vocat-linux-386"}},
		{"linux", "arm64", []string{"vocat-linux-arm64", "vocat-linux-aarch64"}},
		{"linux", "arm", []string{"vocat-linux-armv7", "vocat-linux-arm"}},
		{"windows", "amd64", []string{"vocat-windows-amd64.exe"}},
		{"windows", "arm64", []string{"vocat-windows-arm64.exe"}},
	}
	for _, item := range tests {
		if got := assetNamesFor(item.goos, item.goarch); !reflect.DeepEqual(got, item.want) {
			t.Errorf("assetNamesFor(%q, %q) = %#v, want %#v", item.goos, item.goarch, got, item.want)
		}
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
