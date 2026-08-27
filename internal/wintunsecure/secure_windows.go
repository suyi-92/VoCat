//go:build windows

// Package wintunsecure validates and binds the native Wintun DLL before the
// legacy Wintun Go wrapper is allowed to resolve any API entry point.
package wintunsecure

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxWintunDLLBytes = 64 << 20

var requiredExports = []string{
	"WintunAllocateSendPacket",
	"WintunCloseAdapter",
	"WintunCreateAdapter",
	"WintunEndSession",
	"WintunGetAdapterLUID",
	"WintunGetReadWaitEvent",
	"WintunOpenAdapter",
	"WintunReceivePacket",
	"WintunReleaseReceivePacket",
	"WintunSendPacket",
	"WintunSetLogger",
	"WintunStartSession",
}

// Failure identifies the stage at which a DLL was rejected.
type Failure string

const (
	FailureOpen                 Failure = "open"
	FailureInvalidPE            Failure = "invalid_pe"
	FailureArchitectureMismatch Failure = "architecture_mismatch"
	FailureUntrusted            Failure = "untrusted"
	FailureExportsUnreadable    Failure = "exports_unreadable"
	FailureExportsMissing       Failure = "exports_missing"
	FailureLoad                 Failure = "load"
	FailureLoadedPathMismatch   Failure = "loaded_path_mismatch"
)

// ValidationError carries structured evidence for the Windows doctor report.
type ValidationError struct {
	Failure        Failure
	Path           string
	MissingExports []string
	Err            error
}

func (err *ValidationError) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.Err == nil {
		return fmt.Sprintf("wintun: %s validation failed for %s", err.Failure, err.Path)
	}
	return fmt.Sprintf("wintun: %s validation failed for %s: %v", err.Failure, err.Path, err.Err)
}

func (err *ValidationError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

// Report describes the exact file that passed validation.
type Report struct {
	Path           string
	LoadedPath     string
	Machine        uint16
	Architecture   string
	SHA256         string
	Trust          string
	Exports        []string
	MissingExports []string
}

func cloneReport(report Report) Report {
	report.Exports = slices.Clone(report.Exports)
	report.MissingExports = slices.Clone(report.MissingExports)
	return report
}

// RequiredExports returns the API surface used by VoCat's Wintun wrapper.
func RequiredExports() []string {
	return slices.Clone(requiredExports)
}

// CandidatePaths returns the application-local and System32 locations in the
// same precedence order used by the legacy Wintun wrapper.
func CandidatePaths() []string {
	var candidates []string
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "wintun.dll"))
	}
	if systemDirectory, err := windows.GetSystemDirectory(); err == nil {
		candidates = append(candidates, filepath.Join(systemDirectory, "wintun.dll"))
	}
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		duplicate := false
		for _, existing := range result {
			if strings.EqualFold(filepath.Clean(candidate), filepath.Clean(existing)) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, candidate)
		}
	}
	return result
}

// FindDLL selects the first existing candidate. A present but inaccessible or
// non-regular application-local candidate is an error rather than a reason to
// silently fall through to a different DLL.
func FindDLL() (string, []string, error) {
	searched := CandidatePaths()
	for _, candidate := range searched {
		info, err := os.Stat(candidate)
		if err == nil {
			if !info.Mode().IsRegular() {
				return "", searched, fmt.Errorf("wintun.dll candidate is not a regular file: %s", candidate)
			}
			return candidate, searched, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", searched, fmt.Errorf("inspect wintun.dll candidate %s: %w", candidate, err)
		}
	}
	return "", searched, fmt.Errorf("%w: wintun.dll was not found", os.ErrNotExist)
}

// Inspect locks path against writes, replacement, and deletion while checking
// its architecture, Authenticode trust, and required exports. It does not run
// the DLL entry point.
func Inspect(path string) (Report, error) {
	return inspect(path, requiredExports, nil)
}

func inspect(path string, exports []string, allowedSHA256 []string) (Report, error) {
	file, finalPath, err := openLockedFile(path)
	if err != nil {
		return Report{Path: path}, &ValidationError{Failure: FailureOpen, Path: path, Err: err}
	}
	defer file.Close()
	return inspectLocked(file, finalPath, exports, allowedSHA256)
}

func inspectLocked(
	file *os.File,
	path string,
	exports []string,
	allowedSHA256 []string,
) (Report, error) {
	report := Report{Path: path, Exports: slices.Clone(exports)}
	info, err := file.Stat()
	if err != nil {
		return report, &ValidationError{Failure: FailureOpen, Path: path, Err: err}
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxWintunDLLBytes {
		return report, &ValidationError{
			Failure: FailureInvalidPE,
			Path:    path,
			Err:     fmt.Errorf("DLL size %d is outside the accepted range", info.Size()),
		}
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(file, 0, info.Size())); err != nil {
		return report, &ValidationError{Failure: FailureOpen, Path: path, Err: fmt.Errorf("hash locked DLL: %w", err)}
	}
	report.SHA256 = hex.EncodeToString(digest.Sum(nil))
	machine, err := ParsePEMachine(file)
	if err != nil {
		return report, &ValidationError{Failure: FailureInvalidPE, Path: path, Err: err}
	}
	report.Machine = machine
	report.Architecture = MachineArchitecture(machine)
	if report.Architecture != runtime.GOARCH {
		return report, &ValidationError{
			Failure: FailureArchitectureMismatch,
			Path:    path,
			Err: fmt.Errorf(
				"DLL architecture %s does not match process architecture %s",
				report.Architecture,
				runtime.GOARCH,
			),
		}
	}
	authenticodeErr := VerifyAuthenticode(path)
	if authenticodeErr == nil {
		report.Trust = "authenticode"
	} else if hashAllowed(report.SHA256, allowedSHA256) {
		report.Trust = "sha256"
	} else {
		return report, &ValidationError{Failure: FailureUntrusted, Path: path, Err: authenticodeErr}
	}
	missing, err := missingExportsLocked(windows.Handle(file.Fd()), path, exports)
	report.MissingExports = slices.Clone(missing)
	if err != nil {
		return report, &ValidationError{Failure: FailureExportsUnreadable, Path: path, Err: err}
	}
	if len(missing) != 0 {
		return report, &ValidationError{
			Failure:        FailureExportsMissing,
			Path:           path,
			MissingExports: slices.Clone(missing),
			Err:            fmt.Errorf("DLL is missing %d required export(s)", len(missing)),
		}
	}
	return report, nil
}

func hashAllowed(actual string, allowed []string) bool {
	actualBytes, err := hex.DecodeString(actual)
	if err != nil || len(actualBytes) != sha256.Size {
		return false
	}
	for _, candidate := range allowed {
		candidateBytes, err := hex.DecodeString(strings.TrimSpace(candidate))
		if err == nil && len(candidateBytes) == sha256.Size && string(candidateBytes) == string(actualBytes) {
			return true
		}
	}
	return false
}

var (
	loadMu       sync.Mutex
	loadedModule windows.Handle
	loadedReport Report
)

// EnsureLoaded validates and loads the selected wintun.dll exactly once. Only
// a successful load is cached; failures can be retried after the local setup is
// corrected. The retained module reference binds all later basename-based
// lookups in the legacy wrapper to this already-verified image.
func EnsureLoaded() (Report, error) {
	loadMu.Lock()
	defer loadMu.Unlock()
	if loadedModule != 0 {
		return cloneReport(loadedReport), nil
	}
	path, searched, err := FindDLL()
	if err != nil {
		return Report{}, fmt.Errorf("locate trusted wintun.dll (searched %v): %w", searched, err)
	}
	module, report, err := secureLoad(path, requiredExports, nil, nil)
	if err != nil {
		return report, err
	}
	loadedModule = module
	loadedReport = cloneReport(report)
	return cloneReport(report), nil
}

func secureLoad(
	path string,
	exports []string,
	allowedSHA256 []string,
	beforeLoad func(),
) (windows.Handle, Report, error) {
	file, finalPath, err := openLockedFile(path)
	if err != nil {
		report := Report{Path: path}
		return 0, report, &ValidationError{Failure: FailureOpen, Path: path, Err: err}
	}
	defer file.Close()
	report, err := inspectLocked(file, finalPath, exports, allowedSHA256)
	if err != nil {
		return 0, report, err
	}
	if beforeLoad != nil {
		beforeLoad()
	}
	module, err := windows.LoadLibraryEx(finalPath, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return 0, report, &ValidationError{Failure: FailureLoad, Path: finalPath, Err: err}
	}
	actualPath, pathErr := modulePath(module)
	if pathErr == nil {
		report.LoadedPath = actualPath
		var matches bool
		matches, pathErr = moduleMatchesLockedFile(windows.Handle(file.Fd()), actualPath)
		if pathErr == nil && !matches {
			pathErr = errors.New("loaded module is not the locked and validated file")
		}
	}
	if pathErr != nil {
		_ = windows.FreeLibrary(module)
		return 0, report, &ValidationError{Failure: FailureLoadedPathMismatch, Path: finalPath, Err: pathErr}
	}
	// The legacy wrapper does not accept an injected module handle; it performs
	// its own basename LoadLibraryEx with these exact flags. Execute that lookup
	// now while the validated file is still locked and prove that Windows binds
	// it to the same file. This also fails closed if another wintun.dll basename
	// was loaded earlier in the process.
	basenameModule, basenamePath, basenameErr := loadVerifiedBasename(
		windows.Handle(file.Fd()),
		filepath.Base(finalPath),
	)
	if basenameErr != nil {
		_ = windows.FreeLibrary(module)
		return 0, report, &ValidationError{
			Failure: FailureLoadedPathMismatch,
			Path:    finalPath,
			Err:     fmt.Errorf("bind legacy basename lookup: %w", basenameErr),
		}
	}
	if err := windows.FreeLibrary(module); err != nil {
		_ = windows.FreeLibrary(basenameModule)
		return 0, report, &ValidationError{
			Failure: FailureLoad,
			Path:    finalPath,
			Err:     fmt.Errorf("release absolute-path module reference after binding basename: %w", err),
		}
	}
	report.LoadedPath = basenamePath
	return basenameModule, report, nil
}

func loadVerifiedBasename(locked windows.Handle, basename string) (windows.Handle, string, error) {
	module, err := windows.LoadLibraryEx(
		basename,
		0,
		windows.LOAD_LIBRARY_SEARCH_APPLICATION_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32,
	)
	if err != nil {
		return 0, "", err
	}
	actualPath, err := modulePath(module)
	if err == nil {
		var matches bool
		matches, err = moduleMatchesLockedFile(locked, actualPath)
		if err == nil && !matches {
			err = errors.New("basename lookup resolved a different loaded module")
		}
	}
	if err != nil {
		_ = windows.FreeLibrary(module)
		return 0, actualPath, err
	}
	return module, actualPath, nil
}

func openLockedFile(path string) (*os.File, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("make DLL path absolute: %w", err)
	}
	pathPointer, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return nil, "", fmt.Errorf("encode DLL path: %w", err)
	}
	handle, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, "", fmt.Errorf("lock DLL against replacement: %w", err)
	}
	file := os.NewFile(uintptr(handle), absolute)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, "", errors.New("wrap locked DLL handle")
	}
	finalPath, err := finalPathByHandle(handle)
	if err != nil {
		file.Close()
		return nil, "", fmt.Errorf("resolve locked DLL path: %w", err)
	}
	return file, finalPath, nil
}

func finalPathByHandle(handle windows.Handle) (string, error) {
	size := uint32(512)
	for size <= 1<<15 {
		buffer := make([]uint16, size)
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, 0)
		if err != nil {
			return "", err
		}
		if length < size {
			return windows.UTF16ToString(buffer[:length]), nil
		}
		size = length + 1
	}
	return "", errors.New("resolved DLL path is too long")
}

func modulePath(module windows.Handle) (string, error) {
	for size := uint32(512); size <= 1<<15; size *= 2 {
		buffer := make([]uint16, size)
		length, err := windows.GetModuleFileName(module, &buffer[0], size)
		if err != nil && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return "", err
		}
		if length > 0 && length < size-1 {
			return windows.UTF16ToString(buffer[:length]), nil
		}
	}
	return "", errors.New("loaded module path is too long")
}

func moduleMatchesLockedFile(locked windows.Handle, moduleFile string) (bool, error) {
	pathPointer, err := windows.UTF16PtrFromString(moduleFile)
	if err != nil {
		return false, err
	}
	actual, err := windows.CreateFile(
		pathPointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(actual)
	var lockedInfo, actualInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(locked, &lockedInfo); err != nil {
		return false, err
	}
	if err := windows.GetFileInformationByHandle(actual, &actualInfo); err != nil {
		return false, err
	}
	return lockedInfo.VolumeSerialNumber == actualInfo.VolumeSerialNumber &&
		lockedInfo.FileIndexHigh == actualInfo.FileIndexHigh &&
		lockedInfo.FileIndexLow == actualInfo.FileIndexLow, nil
}

func missingExportsLocked(locked windows.Handle, path string, required []string) ([]string, error) {
	module, err := windows.LoadLibraryEx(path, 0, windows.DONT_RESOLVE_DLL_REFERENCES)
	if err != nil {
		return nil, fmt.Errorf("map DLL without resolving dependencies: %w", err)
	}
	actualPath, pathErr := modulePath(module)
	if pathErr == nil {
		var matches bool
		matches, pathErr = moduleMatchesLockedFile(locked, actualPath)
		if pathErr == nil && !matches {
			pathErr = errors.New("mapped export image is not the locked file")
		}
	}
	if pathErr != nil {
		_ = windows.FreeLibrary(module)
		return nil, pathErr
	}
	missing := make([]string, 0)
	for _, name := range required {
		if _, err := windows.GetProcAddress(module, name); err != nil {
			missing = append(missing, name)
		}
	}
	if err := windows.FreeLibrary(module); err != nil {
		return nil, fmt.Errorf("unmap DLL after export inspection: %w", err)
	}
	return missing, nil
}

// VerifyAuthenticode performs a non-interactive, cache-only trust check.
func VerifyAuthenticode(path string) error {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode file path: %w", err)
	}
	fileInfo := windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: pathPointer,
	}
	trustData := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fileInfo),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_SAFER_FLAG |
			windows.WTD_CACHE_ONLY_URL_RETRIEVAL |
			windows.WTD_DISABLE_MD2_MD4,
		UIContext: windows.WTD_UICONTEXT_EXECUTE,
	}
	verifyErr := windows.WinVerifyTrustEx(
		windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2,
		&trustData,
	)
	trustData.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(
		windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2,
		&trustData,
	)
	runtime.KeepAlive(pathPointer)
	runtime.KeepAlive(fileInfo)
	if verifyErr != nil {
		return fmt.Errorf("verify Authenticode trust: %w", verifyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close Authenticode trust state: %w", closeErr)
	}
	return nil
}

// ParsePEMachine reads the PE COFF machine field without executing the image.
func ParsePEMachine(reader io.ReaderAt) (uint16, error) {
	dosHeader := make([]byte, 64)
	if _, err := reader.ReadAt(dosHeader, 0); err != nil {
		return 0, fmt.Errorf("read DOS header: %w", err)
	}
	if string(dosHeader[:2]) != "MZ" {
		return 0, errors.New("missing MZ signature")
	}
	peOffset := int64(binary.LittleEndian.Uint32(dosHeader[0x3c:0x40]))
	if peOffset < 64 || peOffset > maxWintunDLLBytes {
		return 0, errors.New("invalid PE header offset")
	}
	peHeader := make([]byte, 6)
	if _, err := reader.ReadAt(peHeader, peOffset); err != nil {
		return 0, fmt.Errorf("read PE header: %w", err)
	}
	if string(peHeader[:4]) != "PE\x00\x00" {
		return 0, errors.New("missing PE signature")
	}
	return binary.LittleEndian.Uint16(peHeader[4:6]), nil
}

// MachineArchitecture maps PE machine constants to Go architecture names.
func MachineArchitecture(machine uint16) string {
	switch machine {
	case 0x8664:
		return "amd64"
	case 0xaa64:
		return "arm64"
	case 0x014c:
		return "386"
	default:
		return fmt.Sprintf("unknown-0x%04X", machine)
	}
}
