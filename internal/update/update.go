// Package update implements release checks and the `vocat update` self-updater.
// It queries the GitHub Releases API, downloads a matching platform archive,
// verifies it against a published SHA256SUMS, safely extracts the executable,
// and atomically replaces supported installs.
// Windows builds deliberately support release checks only because replacing a
// mapped executable in place is not a reliable or atomic update mechanism.
//
// Trust model: GitHub TLS guarantees the channel; the repository owner controls
// which assets are published; SHA256SUMS guards integrity. There is no GPG
// signature verification — an accepted trade-off for a closed-network testing
// tool. Both the CLI and authenticated web UI use this same verified replacement
// path.
package update

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"vocat/internal/buildinfo"
)

// ErrInPlaceUpdateUnsupported reports that the current platform must be
// updated while VoCat is stopped. Callers can use errors.Is to present a
// manual-update response instead of treating this as a download failure.
var ErrInPlaceUpdateUnsupported = errors.New("update: in-place binary replacement is not supported on this platform; stop VoCat, verify and extract the matching release archive against SHA256SUMS, and replace the executable manually")

// SupportsInPlaceApply lets the HTTP API and Web UI describe the platform's
// update behavior before an operator attempts to apply a release.
func SupportsInPlaceApply() bool {
	return inPlaceUpdateSupported()
}

// Options captures the resolved flags for an update invocation.
type Options struct {
	Check  bool   // report-only
	Repo   string // owner/name
	Target string // binary path to replace
	Force  bool   // reinstall even at equal version
	Token  string // optional GitHub bearer token
	Help   bool   // print usage, do nothing
}

// Run executes the update subcommand. It returns nil on success or when an
// update is reported-but-not-applied under --check; it returns an error only
// when something concrete went wrong.
func Run(logger *slog.Logger, args []string) error {
	opts, err := parseFlags(args)
	if err != nil {
		return err
	}
	if opts.Help {
		printUpdateUsage()
		return nil
	}
	if opts.Repo == "" {
		opts.Repo = strings.TrimSpace(os.Getenv("VOCAT_REPO"))
	}
	if opts.Repo == "" {
		opts.Repo = DefaultRepository
	}
	if opts.Token == "" {
		opts.Token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if opts.Target == "" {
		opts.Target = resolveDefaultTarget()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	logger.Info("checking for updates", "repo", opts.Repo, "current", buildinfo.Version)
	result, err := CheckLatest(ctx, opts.Repo, opts.Token, buildinfo.Version)
	if err != nil {
		return err
	}
	if opts.Check {
		if result.Available {
			fmt.Printf("update available: %s -> %s\n", buildinfo.Version, result.Latest)
			if result.ReleaseNotes != "" {
				fmt.Println(result.ReleaseNotes)
			}
		} else {
			logger.Info("already up to date", "version", buildinfo.Version)
			fmt.Printf("vocat %s is already the latest release.\n", buildinfo.Version)
		}
		return nil
	}
	apply, err := shouldApplyRelease(result, opts.Force)
	if err != nil {
		return err
	}
	if !apply {
		logger.Info("already up to date", "version", buildinfo.Version)
		fmt.Printf("vocat %s is already the latest release.\n", buildinfo.Version)
		return nil
	}

	if result.Available {
		logger.Info("update available", "current", buildinfo.Version, "latest", result.Latest)
	} else {
		logger.Info("reinstalling current release", "version", result.Latest)
	}
	return applyUpdate(ctx, logger, opts, result.Release, result.Latest, true)
}

// ApplyLatest downloads, verifies, and atomically installs the newest trusted
// release. HTTP callers can pass restart=false and restart after flushing the
// response.
func ApplyLatest(ctx context.Context, logger *slog.Logger, opts Options, restart bool) (CheckResult, error) {
	if strings.TrimSpace(opts.Repo) == "" {
		opts.Repo = DefaultRepository
	}
	if strings.TrimSpace(opts.Token) == "" {
		opts.Token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if strings.TrimSpace(opts.Target) == "" {
		opts.Target = resolveDefaultTarget()
	}
	result, err := CheckLatest(ctx, opts.Repo, opts.Token, buildinfo.Version)
	if err != nil {
		return CheckResult{}, err
	}
	apply, err := shouldApplyRelease(result, opts.Force)
	if err != nil {
		return CheckResult{}, err
	}
	if !apply {
		return result, nil
	}
	if err := applyUpdate(ctx, logger, opts, result.Release, result.Latest, restart); err != nil {
		return CheckResult{}, err
	}
	result.Applied = true
	return result, nil
}

func shouldApplyRelease(result CheckResult, force bool) (bool, error) {
	if result.Available {
		return true, nil
	}
	if !force {
		return false, nil
	}
	currentIsNewer, err := IsNewerVersion(result.Latest, result.Current)
	if err != nil {
		return false, fmt.Errorf("update: validate forced reinstall versions: %w", err)
	}
	if currentIsNewer {
		return false, fmt.Errorf(
			"update: refusing to downgrade from %s to %s; --force only reinstalls the same version",
			result.Current,
			result.Latest,
		)
	}
	return true, nil
}

func applyUpdate(ctx context.Context, logger *slog.Logger, opts Options, release *Release, latest string, restart bool) error {
	if !inPlaceUpdateSupported() {
		return ErrInPlaceUpdateUnsupported
	}
	asset, sumsAsset, err := releaseAssetsForPlatform(release, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}

	// Both temp files MUST live in the same directory as the target so the final
	// renames stay on one filesystem; a cross-device rename fails with EXDEV.
	targetDir := filepath.Dir(opts.Target)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("update: ensure target dir %s: %w", targetDir, err)
	}
	archiveTmp, err := os.CreateTemp(targetDir, ".vocat-release-*")
	if err != nil {
		return fmt.Errorf("update: create archive temp file: %w", err)
	}
	archiveTmpPath := archiveTmp.Name()
	defer func() {
		if archiveTmp != nil {
			_ = archiveTmp.Close()
		}
		if archiveTmpPath != "" {
			_ = os.Remove(archiveTmpPath)
		}
	}()

	logger.Info("downloading release archive", "asset", asset.Name, "size", asset.Size, "url", asset.BrowserDownloadURL)
	if err := downloadAssetWithProgress(ctx, logger, asset, opts.Token, archiveTmp); err != nil {
		return err
	}
	if err := archiveTmp.Sync(); err != nil {
		return fmt.Errorf("update: sync release archive: %w", err)
	}
	if err := archiveTmp.Close(); err != nil {
		return fmt.Errorf("update: finalize release archive: %w", err)
	}
	archiveTmp = nil

	var sums bytes.Buffer
	if err := downloadAsset(ctx, sumsAsset, opts.Token, maxReleaseChecksumSize, &sums); err != nil {
		return err
	}
	expectedHash, err := ParseSHA256SUMS(sums.String(), asset.Name)
	if err != nil {
		return err
	}
	ok, err := VerifyFileSHA256(archiveTmpPath, expectedHash)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("update: sha256 mismatch for %s — refusing to extract or install", asset.Name)
	}
	logger.Info("verified release archive", "sha256", expectedHash)

	binaryTmp, err := os.CreateTemp(targetDir, ".vocat-update-*")
	if err != nil {
		return fmt.Errorf("update: create executable temp file: %w", err)
	}
	binaryTmpPath := binaryTmp.Name()
	defer func() {
		if binaryTmp != nil {
			_ = binaryTmp.Close()
		}
		if binaryTmpPath != "" {
			_ = os.Remove(binaryTmpPath)
		}
	}()
	if err := extractReleaseBinary(archiveTmpPath, asset.Name, binaryTmp); err != nil {
		return err
	}
	if err := binaryTmp.Sync(); err != nil {
		return fmt.Errorf("update: sync extracted executable: %w", err)
	}
	if err := binaryTmp.Close(); err != nil {
		return fmt.Errorf("update: finalize extracted executable: %w", err)
	}
	binaryTmp = nil

	if err := os.Chmod(binaryTmpPath, 0o755); err != nil {
		return fmt.Errorf("update: chmod temp binary: %w", err)
	}
	if err := validateExecutable(ctx, binaryTmpPath, latest); err != nil {
		return err
	}

	if err := os.Chmod(archiveTmpPath, 0o644); err != nil {
		return fmt.Errorf("update: chmod verified release archive: %w", err)
	}
	retainedPath, err := retainedArchivePath(opts.Target, asset.Name)
	if err != nil {
		return err
	}
	if err := backupAndReplaceRelease(opts.Target, binaryTmpPath, retainedPath, archiveTmpPath); err != nil {
		return err
	}
	binaryTmpPath = ""
	archiveTmpPath = ""
	logger.Info("retained verified release archive", "path", retainedPath)
	logger.Info("installed new binary", "target", opts.Target, "version", latest)
	fmt.Printf("vocat updated to %s.\n", latest)

	if restart {
		if err := RestartService(logger); err != nil {
			// The file replacement already succeeded; a restart failure is not
			// fatal — the operator can restart the service manually.
			fmt.Printf("Binary replaced, but automatic restart failed: %v\n", err)
			fmt.Println("Restart the vocat service manually to apply the new build.")
		}
	}
	return nil
}

type downloadProgressWriter struct {
	destination io.Writer
	downloaded  atomic.Int64
}

func (writer *downloadProgressWriter) Write(data []byte) (int, error) {
	written, err := writer.destination.Write(data)
	writer.downloaded.Add(int64(written))
	return written, err
}

func downloadAssetWithProgress(
	ctx context.Context,
	logger *slog.Logger,
	asset *Asset,
	token string,
	destination io.Writer,
) error {
	progress := &downloadProgressWriter{destination: destination}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				downloaded := progress.downloaded.Load()
				percent := float64(0)
				if asset.Size > 0 {
					percent = float64(downloaded) * 100 / float64(asset.Size)
				}
				logger.Info(
					"download progress",
					"asset", asset.Name,
					"downloaded", downloaded,
					"total", asset.Size,
					"percent", fmt.Sprintf("%.1f", percent),
				)
			}
		}
	}()
	err := downloadAsset(ctx, asset, token, maxReleaseArchiveSize, progress)
	close(done)
	if err != nil {
		return err
	}
	logger.Info("download completed", "asset", asset.Name, "bytes", progress.downloaded.Load())
	return nil
}

// validateExecutable catches incompatible architectures and missing dynamic
// loaders before the working installation is touched. A valid checksum alone
// cannot detect those packaging errors.
func validateExecutable(ctx context.Context, path, expectedVersion string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	output, err := exec.CommandContext(checkCtx, path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("update: downloaded binary cannot run on this host: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return validateCandidateVersionOutput(string(output), expectedVersion)
}

func validateCandidateVersionOutput(output, expectedVersion string) error {
	candidateVersion, err := candidateVersionFromOutput(string(output))
	if err != nil {
		return err
	}
	expectedVersion = strings.TrimPrefix(strings.TrimSpace(expectedVersion), "v")
	if !strictReleaseVersion.MatchString(expectedVersion) {
		return fmt.Errorf("update: expected release version %q is not strict SemVer", expectedVersion)
	}
	if candidateVersion != expectedVersion {
		return fmt.Errorf(
			"update: downloaded binary reports version %s, expected release version %s",
			candidateVersion,
			expectedVersion,
		)
	}
	return nil
}

var strictReleaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$`)

func candidateVersionFromOutput(output string) (string, error) {
	line := strings.TrimSpace(strings.ReplaceAll(output, "\r\n", "\n"))
	if strings.ContainsRune(line, '\n') || !strings.HasPrefix(line, "vocat ") {
		return "", fmt.Errorf("update: downloaded binary returned an unexpected version response: %q", line)
	}
	remainder := strings.TrimPrefix(line, "vocat ")
	version := remainder
	if separator := strings.Index(remainder, " ("); separator >= 0 {
		version = remainder[:separator]
		buildTime := remainder[separator+2:]
		if len(buildTime) < 2 || buildTime[len(buildTime)-1] != ')' || strings.ContainsAny(buildTime[:len(buildTime)-1], "()\r\n") {
			return "", fmt.Errorf("update: downloaded binary returned an unexpected version response: %q", line)
		}
	}
	if !strictReleaseVersion.MatchString(version) {
		return "", fmt.Errorf("update: downloaded binary returned a non-SemVer version response: %q", line)
	}
	if version != remainder && !strings.HasPrefix(remainder, version+" (") {
		return "", fmt.Errorf("update: downloaded binary returned an unexpected version response: %q", line)
	}
	return version, nil
}

// backupAndReplace renames the current binary aside, then moves the verified
// temp file into place. Both renames are atomic on the same filesystem. The
// previous working binary is retained for service-level or manual rollback.
func backupAndReplace(target, tmp string) error {
	backup := target + ".previous"
	hadOriginal, err := moveExistingAside(target, backup, "current binary")
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return errors.Join(
			fmt.Errorf("update: move new binary into place: %w", err),
			rollbackReplacement(target, backup, hadOriginal, "binary"),
		)
	}
	return nil
}

// backupAndReplaceRelease commits the executable and its verified distribution
// archive as one rollback unit. Previous versions of both files remain beside
// the installation for an operator-controlled rollback.
func backupAndReplaceRelease(target, binaryTmp, archiveTarget, archiveTmp string) error {
	archiveBackup := archiveTarget + ".previous"
	archiveHadOriginal, err := moveExistingAside(archiveTarget, archiveBackup, "current release archive")
	if err != nil {
		return err
	}
	binaryBackup := target + ".previous"
	binaryHadOriginal, err := moveExistingAside(target, binaryBackup, "current binary")
	if err != nil {
		return errors.Join(
			err,
			rollbackReplacement(archiveTarget, archiveBackup, archiveHadOriginal, "release archive"),
		)
	}
	if err := os.Rename(binaryTmp, target); err != nil {
		return errors.Join(
			fmt.Errorf("update: move new binary into place: %w", err),
			rollbackReplacement(target, binaryBackup, binaryHadOriginal, "binary"),
			rollbackReplacement(archiveTarget, archiveBackup, archiveHadOriginal, "release archive"),
		)
	}
	if err := os.Rename(archiveTmp, archiveTarget); err != nil {
		return errors.Join(
			fmt.Errorf("update: retain verified release archive at %s: %w", archiveTarget, err),
			rollbackReplacement(target, binaryBackup, binaryHadOriginal, "binary"),
			rollbackReplacement(archiveTarget, archiveBackup, archiveHadOriginal, "release archive"),
		)
	}
	return nil
}

func moveExistingAside(path, backup, description string) (bool, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("update: inspect %s: %w", description, err)
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("update: remove previous %s backup: %w", description, err)
	}
	if err := os.Rename(path, backup); err != nil {
		return false, fmt.Errorf("update: move %s aside: %w", description, err)
	}
	return true, nil
}

func rollbackReplacement(path, backup string, hadOriginal bool, description string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("update: rollback %s: remove replacement: %w", description, err)
	}
	if !hadOriginal {
		return nil
	}
	if err := os.Rename(backup, path); err != nil {
		return fmt.Errorf("update: rollback %s: restore previous file: %w", description, err)
	}
	return nil
}

// RestartService supports both systemd hosts and OpenWrt/procd routers.
func RestartService(logger *slog.Logger) error {
	if _, err := os.Stat("/etc/init.d/vocat"); err == nil {
		cmd := exec.Command("/etc/init.d/vocat", "restart")
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Warn("OpenWrt service restart failed", "error", err, "output", string(out))
			return fmt.Errorf("restart OpenWrt vocat service: %w", err)
		}
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("neither /etc/init.d/vocat nor systemctl is available")
	}
	unit := detectSystemdUnit(logger)
	// Queue the restart and let systemctl exit before systemd stops this unit.
	// A blocking restart command becomes part of vocat.service's own cgroup and
	// waits for that same cgroup to terminate, creating a stop-timeout cycle.
	cmd := exec.Command("systemctl", "restart", "--no-block", unit)
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Warn("systemctl restart failed", "error", err, "output", string(out))
		return fmt.Errorf("systemctl restart %s: %w", unit, err)
	}
	return nil
}

var validSystemdUnit = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+\.service$`)

func detectSystemdUnit(logger *slog.Logger) string {
	if configured := strings.TrimSpace(os.Getenv("VOCAT_SYSTEMD_UNIT")); validSystemdUnit.MatchString(configured) {
		return configured
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		if unit := systemdUnitFromCgroup(string(data)); unit != "" {
			return unit
		}
	}
	// Some cgroup namespaces hide the unit name. Query loaded services and
	// identify the unit whose MainPID is this process before falling back.
	list := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain")
	if output, err := list.Output(); err == nil {
		pid := strconv.Itoa(os.Getpid())
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || !validSystemdUnit.MatchString(fields[0]) {
				continue
			}
			show := exec.Command("systemctl", "show", fields[0], "--property=MainPID", "--value")
			if value, showErr := show.Output(); showErr == nil && strings.TrimSpace(string(value)) == pid {
				return fields[0]
			}
		}
	}
	if logger != nil {
		logger.Warn("could not identify the current systemd unit; using vocat.service", "hint", "set VOCAT_SYSTEMD_UNIT for a custom unit")
	}
	return "vocat.service"
}

func systemdUnitFromCgroup(data string) string {
	for _, line := range strings.Split(data, "\n") {
		for _, part := range strings.Split(line, "/") {
			part = strings.TrimSpace(part)
			if validSystemdUnit.MatchString(part) {
				return part
			}
		}
	}
	return ""
}

// resolveDefaultTarget returns the conventional install path when present,
// falling back to the running executable. This lets `vocat update` "just work"
// on the standard systemd host without flags.
func resolveDefaultTarget() string {
	const defaultPath = "/opt/vocat/bin/vocat"
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	exe, err := os.Executable()
	if err != nil {
		return defaultPath
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe
	}
	return resolved
}

func findAsset(release *Release, name string) *Asset {
	for i := range release.Assets {
		if release.Assets[i].Name == name {
			return &release.Assets[i]
		}
	}
	return nil
}

func assetNamesFor(goos, goarch string) []string {
	if goos == "windows" {
		return []string{fmt.Sprintf("vocat-windows-%s.zip", goarch)}
	}
	if goos == "linux" && goarch == "arm64" {
		// AArch64 and arm64 name the same instruction set. Prefer the historic
		// release name and accept the explicit architecture alias as fallback.
		return []string{"vocat-linux-arm64.tar.gz", "vocat-linux-aarch64.tar.gz"}
	}
	if goos == "linux" && goarch == "arm" {
		// Official 32-bit ARM release archives target GOARM=7.
		return []string{"vocat-linux-armv7.tar.gz"}
	}
	return []string{fmt.Sprintf("vocat-%s-%s.tar.gz", goos, goarch)}
}

func printUpdateUsage() {
	fmt.Printf(`Usage: vocat update [flags]

Fetch release information from GitHub. Supported Unix-like installations can
replace the binary in place. Windows builds support --check only; stop VoCat,
verify the matching release .zip against SHA256SUMS, extract it, and replace
the executable manually.

Flags:
  --check            Report whether an update is available, then exit.
  --force            Reinstall even when already at the latest version.
  --repo owner/name  GitHub repository (default: $VOCAT_REPO or %s).
  --target path      Binary to replace (default: /opt/vocat/bin/vocat if
                     present, otherwise the running executable).
  --token token      GitHub bearer token (default: $GITHUB_TOKEN).
  -h, --help         Show this help.

Environment:
  VOCAT_REPO         Fallback for --repo.
  GITHUB_TOKEN       Fallback for --token. Required for private repos and
                     recommended to avoid unauthenticated rate limits.
`, DefaultRepository)
}

func parseFlags(args []string) (Options, error) {
	var opts Options
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--check":
			opts.Check = true
		case arg == "--force":
			opts.Force = true
		case arg == "--repo":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("update: --repo requires a value")
			}
			opts.Repo = args[i]
		case strings.HasPrefix(arg, "--repo="):
			opts.Repo = strings.TrimPrefix(arg, "--repo=")
		case arg == "--target":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("update: --target requires a value")
			}
			opts.Target = args[i]
		case strings.HasPrefix(arg, "--target="):
			opts.Target = strings.TrimPrefix(arg, "--target=")
		case arg == "--token":
			i++
			if i >= len(args) {
				return opts, fmt.Errorf("update: --token requires a value")
			}
			opts.Token = args[i]
		case strings.HasPrefix(arg, "--token="):
			opts.Token = strings.TrimPrefix(arg, "--token=")
		case arg == "-h" || arg == "--help":
			opts.Help = true
		default:
			return opts, fmt.Errorf("update: unknown flag %q", arg)
		}
	}
	return opts, nil
}
