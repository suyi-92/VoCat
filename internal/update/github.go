package update

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// Release mirrors the subset of the GitHub releases API response that the
// self-updater consumes.
type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	Body    string  `json:"body"`
	Assets  []Asset `json:"assets"`
}

// Asset is a single downloadable artifact attached to a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// CheckResult describes a trusted release check without downloading assets.
type CheckResult struct {
	Available    bool
	Applied      bool
	Current      string
	Latest       string
	ReleaseNotes string
	Release      *Release
}

const (
	githubAPI              = "https://api.github.com"
	maxReleaseChecksumSize = int64(1 << 20)
)

// DefaultRepository is the release channel baked into this binary. Official
// release workflows override it with -ldflags so forks do not silently check
// another repository's assets.
var DefaultRepository = "MengMengCode/VoCat"

var githubHTTPClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	},
}

// LatestRelease fetches the newest published release for repo (form
// "owner/name"). A non-empty token is sent as a Bearer header, which is
// required for private repositories and lifts the unauthenticated rate limit.
func LatestRelease(ctx context.Context, repo, token string) (*Release, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return nil, fmt.Errorf("update: repository not configured (set --repo or VOCAT_REPO)")
	}
	if strings.Count(repo, "/") != 1 {
		return nil, fmt.Errorf("update: invalid repository %q (expected owner/name)", repo)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update: fetch latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		// The releases API returns 403 (not 404) when rate-limited.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("update: GitHub API rejected the request (likely rate-limited): %s", strings.TrimSpace(string(body)))
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("update: no published release found for %s", repo)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: GitHub API returned %s", resp.Status)
	}

	var release Release
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("update: decode release JSON: %w", err)
	}
	return &release, nil
}

// CheckLatest fetches the newest release and performs a semantic version
// comparison so development builds are never offered an older release.
func CheckLatest(ctx context.Context, repo, token, current string) (CheckResult, error) {
	release, err := LatestRelease(ctx, repo, token)
	if err != nil {
		return CheckResult{}, err
	}
	return checkReleaseForPlatform(release, current, runtime.GOOS, runtime.GOARCH)
}

func checkReleaseForPlatform(release *Release, current, goos, goarch string) (CheckResult, error) {
	if release == nil {
		return CheckResult{}, fmt.Errorf("update: release metadata is missing")
	}
	latest := strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
	available, err := IsNewerVersion(current, latest)
	if err != nil {
		return CheckResult{}, fmt.Errorf("update: compare release versions: %w", err)
	}
	if available {
		if _, _, err := releaseAssetsForPlatform(release, goos, goarch); err != nil {
			return CheckResult{}, err
		}
	}
	return CheckResult{
		Available:    available,
		Current:      current,
		Latest:       latest,
		ReleaseNotes: strings.TrimSpace(release.Body),
		Release:      release,
	}, nil
}

func releaseAssetsForPlatform(release *Release, goos, goarch string) (*Asset, *Asset, error) {
	if release == nil {
		return nil, nil, fmt.Errorf("update: release metadata is missing")
	}
	assetNames := assetNamesFor(goos, goarch)
	var archiveAsset *Asset
	for _, name := range assetNames {
		if archiveAsset = findAsset(release, name); archiveAsset != nil {
			break
		}
	}
	if archiveAsset == nil {
		return nil, nil, fmt.Errorf(
			"update: release %s has none of platform archives %q for %s/%s",
			release.TagName,
			assetNames,
			goos,
			goarch,
		)
	}
	if err := validateAssetSize(archiveAsset, maxReleaseArchiveSize); err != nil {
		return nil, nil, err
	}
	sumsAsset := findAsset(release, "SHA256SUMS")
	if sumsAsset == nil {
		return nil, nil, fmt.Errorf("update: release %s missing SHA256SUMS — refusing an unverified platform update", release.TagName)
	}
	if err := validateAssetSize(sumsAsset, maxReleaseChecksumSize); err != nil {
		return nil, nil, err
	}
	return archiveAsset, sumsAsset, nil
}

func validateAssetSize(asset *Asset, maxBytes int64) error {
	if asset == nil {
		return fmt.Errorf("update: release asset metadata is missing")
	}
	if maxBytes <= 0 {
		return fmt.Errorf("update: invalid download limit %d for %s", maxBytes, asset.Name)
	}
	if asset.Size <= 0 || asset.Size > maxBytes {
		return fmt.Errorf(
			"update: release asset %s has unsafe published size %d (allowed: 1..%d bytes)",
			asset.Name,
			asset.Size,
			maxBytes,
		)
	}
	return nil
}

// downloadAsset streams a release asset into dst, honoring the request context.
// The token is applied for consistency with the API call (GitHub release assets
// redirect to a pre-signed S3 URL; the token is dropped on redirect, which is
// the expected public-CDN flow).
func downloadAsset(ctx context.Context, asset *Asset, token string, maxBytes int64, dst io.Writer) error {
	if err := validateAssetSize(asset, maxBytes); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := githubHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("update: download asset: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update: asset download returned %s", resp.Status)
	}
	// Read one byte beyond the trusted API size so a response that lies about
	// its length is rejected without consuming the rest of an oversized body.
	limited := &io.LimitedReader{R: resp.Body, N: asset.Size + 1}
	written, err := io.Copy(dst, limited)
	if err != nil {
		return fmt.Errorf("update: read asset body: %w", err)
	}
	if written != asset.Size {
		return fmt.Errorf(
			"update: asset size mismatch for %s: downloaded %d bytes, expected %d",
			asset.Name,
			written,
			asset.Size,
		)
	}
	return nil
}
