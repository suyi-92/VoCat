#!/usr/bin/env bash
#
# vocat install / update script for systemd and OpenWrt/procd deployments.
#
# Usage:
#   bash install.sh [--check-env] [--skip-vowifi-check] [version]       # run directly when already root
#   sudo bash install.sh [--check-env] [--skip-vowifi-check] [version]  # run through sudo as a normal user
#   bash install.sh --check-env                                           # check VoWiFi host prerequisites
#
# Behavior:
#   - Prompts for script language (中文 / English) as soon as it runs.
#   - If the installed version equals the target version, does nothing (unless --force).
#   - On first install, generates a random 32-char admin password, initializes
#     it directly in SQLite through stdin, and prints it ONCE.
#   - Administrator credentials are never stored in /etc/vocat/env.
#   - Verifies Linux XFRM/IPsec support required by IMS; on OpenWrt it tries
#     the matching opkg packages first.
#   - Verifies a platform release archive before extracting its binary and
#     retains the bundled project and third-party license notices.
#   - (Re)writes a systemd or OpenWrt/procd service and restarts it.
#
# Published script: must contain no secrets, IPs, or passwords.

set -euo pipefail

# --- Publisher configuration -------------------------------------------------
# Default GitHub repository in owner/name form. Publishers: set this to your
# own repo, or override per-run with VOCAT_REPO.
REPO="${VOCAT_REPO:-MengMengCode/VoCat}"

INSTALL_DIR="/opt/vocat/bin"
BINARY_PATH="${INSTALL_DIR}/vocat"
ARCHIVE_PATH="${INSTALL_DIR}/vocat.release.tar.gz"
NOTICE_ROOT="/opt/vocat"
LICENSES_DIR="${NOTICE_ROOT}/LICENSES"
LINK_PATH="/usr/local/bin/vocat"
ENV_DIR="/etc/vocat"
ENV_FILE="${ENV_DIR}/env"
DATABASE_PATH="/opt/vocat/data/vocat.db"
DATABASE_WAL_PATH="${DATABASE_PATH}-wal"
DATABASE_SHM_PATH="${DATABASE_PATH}-shm"
UNIT_PATH="/etc/systemd/system/vocat.service"
OPENWRT_INIT_PATH="/etc/init.d/vocat"

# --- Language ----------------------------------------------------------------
LANG_CHOICE=""

msg() {
    # $1 = zh text, $2 = en text
    if [ "$LANG_CHOICE" = "en" ]; then
        printf '%s\n' "$2"
    else
        printf '%s\n' "$1"
    fi
}

prompt_language() {
    if ! ( : </dev/tty ) 2>/dev/null; then
        case "${VOCAT_LANG:-en}" in
            zh|zh-CN|cn) LANG_CHOICE="zh" ;;
            *) LANG_CHOICE="en" ;;
        esac
        return
    fi
    while true; do
        echo "选择语言 / Select language:  1) 中文   2) English" >/dev/tty
        printf '> ' >/dev/tty
        if ! read -r choice </dev/tty; then
            LANG_CHOICE="en"
            return
        fi
        case "$choice" in
            1|"") LANG_CHOICE="zh"; return ;;
            2) LANG_CHOICE="en"; return ;;
        esac
    done
}

die() {
    msg "$1" "$2" >&2
    exit 1
}

# BusyBox/OpenWrt images often omit coreutils' install(1). Provide the small
# subset used by this script so the same installer works on router firmware.
if ! command -v install >/dev/null 2>&1; then
    install() {
        if [ "${1:-}" = "-d" ]; then
            shift
            local mode="0755"
            if [ "${1:-}" = "-m" ]; then
                mode="$2"
                shift 2
            fi
            mkdir -p "$@"
            chmod "$mode" "$@"
            return
        fi
        local mode="0755"
        if [ "${1:-}" = "-m" ]; then
            mode="$2"
            shift 2
        fi
        [ "$#" -eq 2 ] || return 2
        cp "$1" "$2"
        chmod "$mode" "$2"
    }
fi

# --- Parse args --------------------------------------------------------------
FORCE=0
CHECK_ENV=0
SKIP_VOWIFI_CHECK="${VOCAT_SKIP_VOWIFI_CHECK:-0}"
TARGET_VERSION=""
parse_args() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            --force) FORCE=1 ;;
            --check-env) CHECK_ENV=1 ;;
            --skip-vowifi-check) SKIP_VOWIFI_CHECK=1 ;;
            -h|--help)
                msg "用法: bash install.sh [--force] [--check-env] [--skip-vowifi-check] [版本]" "Usage: bash install.sh [--force] [--check-env] [--skip-vowifi-check] [version]"
                exit 0
                ;;
            *) TARGET_VERSION="${arg#v}" ;;
        esac
    done
}

# --- Resolve target version --------------------------------------------------
resolve_target_version() {
    if [ -n "$TARGET_VERSION" ]; then
        TARGET_VERSION="${TARGET_VERSION#v}"
        return
    fi
    local api_url="https://api.github.com/repos/${REPO}/releases/latest"
    local auth_hdr=()
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        auth_hdr=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    fi
    local resp
    resp=$(curl -fsSL "${auth_hdr[@]}" "$api_url") || die "无法获取最新版本信息。检查网络或 REPO 设置。" "Failed to fetch latest release. Check network or REPO."
    # Parse "tag_name": "vX.Y.Z" without jq.
    local tag
    tag=$(printf '%s\n' "$resp" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
    [ -n "$tag" ] || die "无法解析最新版本的 tag_name。" "Could not parse tag_name from the release response."
    TARGET_VERSION="${tag#v}"
}

is_strict_release_version() {
    local version="$1"
    local semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$'
    [[ "$version" =~ $semver_pattern ]]
}

validate_target_version() {
    is_strict_release_version "$TARGET_VERSION" || die \
        "目标版本不是严格 SemVer: $TARGET_VERSION" \
        "The target version is not strict SemVer: $TARGET_VERSION"
}

candidate_version_from_output() {
    local output="$1"
    local line version suffix
    line="${output%$'\n'}"
    line="${line%$'\r'}"
    [[ "$line" != *$'\n'* && "$line" == vocat\ * ]] || return 1
    suffix="${line#vocat }"
    version="${suffix%% *}"
    is_strict_release_version "$version" || return 1
    if [ "$suffix" != "$version" ]; then
        [[ "$suffix" == "$version ("*')' ]] || return 1
        local build_time="${suffix#"$version ("}"
        build_time="${build_time%)}"
        [ -n "$build_time" ] && [[ "$build_time" != *'('* && "$build_time" != *')'* ]] || return 1
    fi
    printf '%s\n' "$version"
}

validate_candidate_binary() {
    local candidate="$1"
    local expected="$2"
    local output candidate_version
    output=$("$candidate" version 2>&1) || return 1
    candidate_version=$(candidate_version_from_output "$output") || return 1
    [ "$candidate_version" = "$expected" ]
}

# --- Host prerequisites ------------------------------------------------------
is_openwrt() {
    [ -f /etc/openwrt_release ] || [ -x /sbin/procd ]
}

xfrm_works() {
    command -v ip >/dev/null 2>&1 && ip xfrm state list >/dev/null 2>&1
}

opkg_has_package() {
    opkg list "$1" 2>/dev/null | grep -q "^$1 -"
}

install_openwrt_vowifi_packages() {
    msg "正在检查 OpenWrt/Kwrt 的 VoWiFi 内核组件..." "Checking OpenWrt/Kwrt VoWiFi kernel components..."
    opkg update >/dev/null 2>&1 || msg \
        "警告：opkg 软件源更新失败，将使用现有索引继续检查。" \
        "Warning: opkg feed update failed; checking the existing index."

    local packages=""
    local package
    for package in \
        ip-full \
        kmod-ipsec kmod-ipsec4 kmod-ipsec6 \
        kmod-crypto-authenc kmod-crypto-cbc kmod-crypto-aes \
        kmod-crypto-hmac kmod-crypto-sha1; do
        if opkg_has_package "$package"; then
            packages="$packages $package"
        fi
    done
    if [ -n "$packages" ]; then
        # Kernel packages must come from this firmware's own feed. opkg checks
        # the kernel ABI and refuses mismatched modules; never bypass that check.
        # shellcheck disable=SC2086
        opkg install $packages >/dev/null 2>&1 || true
    fi
}

install_linux_ip_tool() {
    command -v ip >/dev/null 2>&1 && return 0
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y iproute2
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y iproute
    elif command -v yum >/dev/null 2>&1; then
        yum install -y iproute
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm iproute2
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache iproute2
    fi
}

install_qmi_support() {
    msg "正在检查 QMI 命令行工具..." "Checking QMI command-line utilities..."
    qmi_proxy_available() {
        command -v qmi-proxy >/dev/null 2>&1 || \
            [ -x /usr/libexec/qmi-proxy ] || \
            [ -x /usr/lib/qmi-proxy ] || \
            [ -x /usr/lib/libqmi-glib/qmi-proxy ]
    }
    if command -v qmicli >/dev/null 2>&1 && qmi_proxy_available; then
        return 0
    fi

    if is_openwrt && command -v opkg >/dev/null 2>&1; then
        opkg update >/dev/null 2>&1 || true
        local pkgs=""
        opkg_has_package qmi-utils && pkgs="$pkgs qmi-utils"
        opkg_has_package libqmi && pkgs="$pkgs libqmi"
        if [ -z "$pkgs" ]; then
            pkgs="qmi-utils libqmi"
        fi
        # shellcheck disable=SC2086
        opkg install $pkgs >/dev/null 2>&1 || true
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y libqmi-utils || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y libqmi-utils || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y libqmi-utils || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm libqmi || true
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache qmi-utils || true
    fi

    if command -v qmicli >/dev/null 2>&1 && qmi_proxy_available; then
        msg "QMI 命令行工具已就绪。" "QMI command-line utilities are ready."
        return 0
    fi
    die \
        "无法安装或找到 qmicli/qmi-proxy。请安装系统提供的 libqmi/qmi-utils 软件包后重试。" \
        "Could not install or find qmicli/qmi-proxy. Install your distribution's libqmi/qmi-utils package and retry."
}

install_pcsc_support() {
    msg "正在检查 USB SIM 读卡器的 PC/SC 运行环境..." "Checking the PC/SC environment for USB SIM readers..."
    local installed=0
    if is_openwrt && command -v opkg >/dev/null 2>&1; then
        opkg update >/dev/null 2>&1 || true
        local packages=""
        opkg_has_package pcscd && packages="$packages pcscd"
        opkg_has_package ccid && packages="$packages ccid"
        opkg_has_package libccid && packages="$packages libccid"
        if [ -n "$packages" ]; then
            # shellcheck disable=SC2086
            opkg install $packages >/dev/null 2>&1 && installed=1 || true
        fi
    elif command -v apt-get >/dev/null 2>&1; then
        if apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y pcscd libccid; then
            installed=1
        fi
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y pcsc-lite pcsc-lite-ccid && installed=1 || true
    elif command -v yum >/dev/null 2>&1; then
        yum install -y pcsc-lite pcsc-lite-ccid && installed=1 || true
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm pcsclite ccid && installed=1 || true
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache pcsc-lite ccid && installed=1 || true
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now pcscd.socket >/dev/null 2>&1 || \
            systemctl restart pcscd >/dev/null 2>&1 || true
    elif [ -x /etc/init.d/pcscd ]; then
        /etc/init.d/pcscd enable >/dev/null 2>&1 || true
        /etc/init.d/pcscd restart >/dev/null 2>&1 || /etc/init.d/pcscd start >/dev/null 2>&1 || true
    fi
    if command -v pcscd >/dev/null 2>&1 || [ "$installed" -eq 1 ]; then
        msg "USB SIM 读卡器 PC/SC 环境已就绪。" "USB SIM reader PC/SC environment is ready."
    else
        msg \
            "警告：未能自动安装 pcscd/CCID 驱动；系统仍会显示读卡器并给出修复提示。" \
            "Warning: pcscd/CCID could not be installed automatically; VoCat will still show the reader with a remediation hint."
    fi
}

check_vowifi_environment() {
    if [ "$SKIP_VOWIFI_CHECK" = "1" ]; then
        msg \
            "已跳过 VoWiFi 内核环境检查；IMS 通话和短信可能不可用。" \
            "Skipped the VoWiFi kernel check; IMS calls and SMS may not work."
        return
    fi

    if is_openwrt && command -v opkg >/dev/null 2>&1; then
        # Install the crypto algorithms even when NETLINK_XFRM already works;
        # some minimal images provide xfrm_user but omit AES-CBC/authenc.
        install_openwrt_vowifi_packages
    elif ! xfrm_works; then
        install_linux_ip_tool
    fi
    if xfrm_works; then
        msg "VoWiFi XFRM/IPsec 环境安装并验证成功。" "VoWiFi XFRM/IPsec environment installed and verified."
        return
    fi

    if is_openwrt; then
        die \
            "当前 OpenWrt/Kwrt 内核 $(uname -r) 不支持 NETLINK_XFRM，且软件源没有匹配的 kmod-ipsec。请使用包含 kmod-ipsec、kmod-ipsec4、kmod-ipsec6、kmod-crypto-authenc、kmod-crypto-cbc、kmod-crypto-aes 和 kmod-crypto-sha1 的同版本固件；严禁安装其他内核版本的 kmod。仅使用非 VoWiFi 功能时可加 --skip-vowifi-check。" \
            "The OpenWrt/Kwrt kernel $(uname -r) lacks NETLINK_XFRM and its feed has no matching kmod-ipsec. Use a firmware built with matching kmod-ipsec, kmod-ipsec4/6, crypto-authenc, CBC, AES and SHA1 modules. Never force kmods from another kernel. Use --skip-vowifi-check only for non-VoWiFi operation."
    fi
    die \
        "当前 Linux 内核不支持 XFRM/IPsec，VoWiFi IMS 无法工作。请启用 CONFIG_XFRM、CONFIG_XFRM_USER、CONFIG_INET_ESP、CONFIG_INET6_ESP、AES-CBC 和 HMAC-SHA1；若仅使用非 VoWiFi 功能（蜂窝短信/数据等），可重新运行安装脚本并加 --skip-vowifi-check。" \
        "This Linux kernel lacks XFRM/IPsec required by VoWiFi IMS. Enable CONFIG_XFRM, CONFIG_XFRM_USER, CONFIG_INET_ESP, CONFIG_INET6_ESP, AES-CBC and HMAC-SHA1; or re-run with --skip-vowifi-check if you only need non-VoWiFi features (cellular SMS/data)."
}

# --- Skip if already installed at the same version ---------------------------
installed_notices_present() {
    [ -s "${NOTICE_ROOT}/LICENSE" ] && [ ! -L "${NOTICE_ROOT}/LICENSE" ] || return 1
    [ -s "${NOTICE_ROOT}/NOTICE" ] && [ ! -L "${NOTICE_ROOT}/NOTICE" ] || return 1
    [ -d "$LICENSES_DIR" ] && [ ! -L "$LICENSES_DIR" ] || return 1
    local license_file
    for license_file in "${LICENSES_DIR}/"*.txt; do
        if [ -f "$license_file" ] && [ ! -L "$license_file" ] && [ -s "$license_file" ]; then
            return 0
        fi
    done
    return 1
}

validate_command_path() {
    if [ -e "$LINK_PATH" ] && [ ! -f "$LINK_PATH" ] && [ ! -L "$LINK_PATH" ]; then
        die \
            "$LINK_PATH 必须是普通文件、符号链接或尚不存在。" \
            "$LINK_PATH must be a regular file, a symbolic link, or not exist."
    fi
}

skip_if_equal() {
    [ -x "$BINARY_PATH" ] || return 0
    [ "$FORCE" -eq 1 ] && return 0
    local installed
    installed=$("$BINARY_PATH" version 2>/dev/null | awk '{print $2}' | sed -E 's/[[:space:]]*\(.*$//') || return 0
    [ -z "$installed" ] && return 0
    if [ "$installed" = "$TARGET_VERSION" ]; then
        if ! installed_notices_present; then
            msg \
                "已安装版本 $installed，但许可声明不完整；将从发布包恢复声明文件。" \
                "Version $installed is installed, but its license notices are incomplete; restoring them from the release archive."
            return 0
        fi
        validate_command_path
        install -d -m 0755 "$(dirname "$LINK_PATH")"
        ln -sfn "$BINARY_PATH" "$LINK_PATH"
        msg "已安装版本 $installed，与目标版本相同，跳过更新。" "Installed version $installed equals target; skipping."
        exit 0
    fi
    msg "当前 $installed -> $TARGET_VERSION，开始更新。" "Updating $installed -> $TARGET_VERSION."
}

# --- Detect architecture -----------------------------------------------------
detect_arch() {
    ARCH_FALLBACK=""
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        i386|i486|i586|i686) ARCH="386" ;;
        aarch64) ARCH="aarch64"; ARCH_FALLBACK="arm64" ;;
        arm64) ARCH="arm64"; ARCH_FALLBACK="aarch64" ;;
        armv7l|armv7*) ARCH="armv7" ;;
        *) die "不支持的架构: $(uname -m)" "Unsupported architecture: $(uname -m)" ;;
    esac
}

# --- Download + verify -------------------------------------------------------
VOCAT_TMP=""
VOCAT_PAYLOAD=""
VOCAT_ARCHIVE=""
BINARY_HAD_PREVIOUS=0
ARCHIVE_HAD_PREVIOUS=0
LINK_HAD_PREVIOUS=0
LICENSE_HAD_PREVIOUS=0
NOTICE_HAD_PREVIOUS=0
LICENSES_HAD_PREVIOUS=0
DATABASE_HAD_PREVIOUS=0
DATABASE_WAL_HAD_PREVIOUS=0
DATABASE_SHM_HAD_PREVIOUS=0
DATABASE_TOUCHED=0
ENV_HAD_PREVIOUS=0
SERVICE_CONFIG_HAD_PREVIOUS=0
RUNTIME_CONFIG_TOUCHED=0
PAYLOAD_FILES_TOUCHED=0
LINK_TOUCHED=0
NOTICES_TOUCHED=0
PAYLOAD_INSTALL_PENDING=0
SERVICE_MANAGER=""
SERVICE_CONFIG_PATH=""
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=0
NEW_SERVICE_ENABLE_ATTEMPTED=0
NEW_SERVICE_START_ATTEMPTED=0
INSTALL_LOCK_DIR="${VOCAT_INSTALL_LOCK_DIR:-/var/run/vocat-install.lock}"
INSTALL_LOCK_HELD=0
MAX_RELEASE_ARCHIVE_BYTES=$((512 * 1024 * 1024))
MAX_CHECKSUM_BYTES=$((1024 * 1024))
MAX_RELEASE_ENTRY_BYTES=$((256 * 1024 * 1024))
MAX_RELEASE_EXPANDED_BYTES=$((512 * 1024 * 1024))
MAX_RELEASE_MEMBERS=1024

acquire_install_lock() {
    if (umask 077 && mkdir "$INSTALL_LOCK_DIR") 2>/dev/null; then
        INSTALL_LOCK_HELD=1
        if ! printf '%s\n' "$$" > "${INSTALL_LOCK_DIR}/pid"; then
            release_install_lock || true
            return 1
        fi
        return 0
    fi
    return 1
}

release_install_lock() {
    [ "$INSTALL_LOCK_HELD" -eq 1 ] || return 0
    local recorded=""
    if [ -f "${INSTALL_LOCK_DIR}/pid" ] && [ ! -L "${INSTALL_LOCK_DIR}/pid" ]; then
        recorded=$(sed -n '1p' "${INSTALL_LOCK_DIR}/pid" 2>/dev/null || true)
    fi
    [ "$recorded" = "$$" ] || return 1
    rm -f "${INSTALL_LOCK_DIR}/pid" || return 1
    rmdir "$INSTALL_LOCK_DIR" || return 1
    INSTALL_LOCK_HELD=0
}

# curl transfer options for the release-archive download. -f makes curl fail on HTTP
# errors and -L follows the release-asset redirect. On an interactive terminal
# we show a single-line progress bar so a multi-megabyte download gives visible
# feedback; otherwise (piped, cron, systemd) we stay quiet but still surface
# errors via -S.
if [ -t 2 ]; then
    CURL_DL_OPTS=(-fSL --progress-bar)
else
    CURL_DL_OPTS=(-fsSL)
fi

download_bounded() {
    local destination="$1"
    local max_bytes="$2"
    local url="$3"
    shift 3

    local partial="${destination}.part.$$"
    if [ -e "$destination" ] || [ -L "$destination" ] || \
        [ -e "$partial" ] || [ -L "$partial" ]; then
        return 1
    fi

    # curl versions before 8.4 cannot enforce --max-filesize when the response
    # omits Content-Length. Keep that early rejection hint, but independently
    # cap the bytes accepted by a local consumer. max+1 lets the caller
    # distinguish an exact-boundary response from an oversized one. The file is
    # published only after curl, the bounded sink, and the byte-count check all
    # succeed.
    local -a transfer_statuses
    if curl "$@" --max-filesize "$max_bytes" "$url" | \
        head -c "$((max_bytes + 1))" > "$partial"; then
        transfer_statuses=("${PIPESTATUS[@]}")
    else
        transfer_statuses=("${PIPESTATUS[@]}")
    fi

    local received_size
    if ! received_size=$(wc -c < "$partial"); then
        rm -f "$partial" || true
        return 1
    fi
    if [ "$received_size" -le 0 ] || [ "$received_size" -gt "$max_bytes" ] || \
        [ "${transfer_statuses[0]:-1}" -ne 0 ] || \
        [ "${transfer_statuses[1]:-1}" -ne 0 ]; then
        rm -f "$partial" || true
        return 1
    fi
    if ! mv -f "$partial" "$destination"; then
        rm -f "$partial" || true
        return 1
    fi
}

validate_and_extract_archive() {
    local archive="$1"
    local binary_name="$2"
    local members_file="${VOCAT_TMP}/archive.members"
    local files_file="${VOCAT_TMP}/archive.files"
    local extract_dir="${VOCAT_TMP}/payload"
    : > "$files_file"

    # Bound the first listing pass itself. Without this consumer-side guard, a
    # highly compressed archive containing millions of empty members can fill
    # the temporary filesystem before the later metadata checks run.
    if ! tar -tzf "$archive" | awk -v max_members="$MAX_RELEASE_MEMBERS" '
        NR > max_members { exit 1 }
        { print }
    ' > "$members_file"; then
        die \
            "发布归档无法读取或成员数量超过安全上限。" \
            "The release archive cannot be read or exceeds the safe member-count limit."
    fi
    [ -s "$members_file" ] || die \
        "发布归档为空。" \
        "The release archive is empty."

    # Only regular files and directories are accepted. In particular, reject
    # symlinks, hard links, devices, and FIFOs before extracting as root.
    if ! tar -tvzf "$archive" | awk \
        -v max_entry="$MAX_RELEASE_ENTRY_BYTES" \
        -v max_expanded="$MAX_RELEASE_EXPANDED_BYTES" \
        -v max_members="$MAX_RELEASE_MEMBERS" '
        BEGIN { members = 0; expanded = 0 }
        {
            type = substr($1, 1, 1)
            if (type != "-" && type != "d") exit 1
            if ($3 !~ /^[0-9]+$/) exit 1
            size = $3 + 0
            members++
            expanded += size
            if (members > max_members || size > max_entry || expanded > max_expanded) exit 1
        }
    '; then
        die \
            "发布归档包含链接、特殊成员或超出安全大小限制。" \
            "The release archive contains links, special members, or exceeds the safe size limits."
    fi

    local binary_count=0
    local license_count=0
    local notice_count=0
    local third_party_count=0
    local listed entry license_name
    while IFS= read -r listed || [ -n "$listed" ]; do
        entry="$listed"
        while [[ "$entry" == ./* ]]; do
            entry="${entry#./}"
        done
        [ "$entry" = "." ] && entry=""
        case "$entry" in
            "") continue ;;
            /*|*\\*)
                die \
                    "发布归档包含不安全路径: $listed" \
                    "The release archive contains an unsafe path: $listed"
                ;;
        esac
        case "/${entry}/" in
            */../*|*/./*)
                die \
                    "发布归档包含路径穿越成员: $listed" \
                    "The release archive contains a path-traversal member: $listed"
                ;;
        esac
        case "$entry" in
            "$binary_name")
                binary_count=$((binary_count + 1))
                ;;
            LICENSE)
                license_count=$((license_count + 1))
                ;;
            NOTICE)
                notice_count=$((notice_count + 1))
                ;;
            LICENSES|LICENSES/)
                continue
                ;;
            LICENSES/*.txt)
                license_name="${entry#LICENSES/}"
                if [[ "$license_name" == */* || ! "$license_name" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*\.txt$ ]]; then
                    die \
                        "发布归档包含无效许可文件名: $listed" \
                        "The release archive contains an invalid license filename: $listed"
                fi
                third_party_count=$((third_party_count + 1))
                ;;
            *)
                die \
                    "发布归档包含未声明的成员: $listed" \
                    "The release archive contains an undeclared member: $listed"
                ;;
        esac
        printf '%s\n' "$entry" >> "$files_file"
    done < "$members_file"

    [ "$binary_count" -eq 1 ] || die \
        "发布归档必须且只能包含一个 $binary_name。" \
        "The release archive must contain exactly one $binary_name."
    [ "$license_count" -eq 1 ] || die \
        "发布归档必须且只能包含一个 LICENSE。" \
        "The release archive must contain exactly one LICENSE."
    [ "$notice_count" -eq 1 ] || die \
        "发布归档必须且只能包含一个 NOTICE。" \
        "The release archive must contain exactly one NOTICE."
    [ "$third_party_count" -gt 0 ] || die \
        "发布归档未包含 LICENSES 下的第三方许可文件。" \
        "The release archive contains no third-party license files under LICENSES."
    if sort "$files_file" | uniq -d | grep -q .; then
        die \
            "发布归档包含重复文件成员。" \
            "The release archive contains duplicate file members."
    fi

    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir" || die \
        "无法解压发布归档。" \
        "Failed to extract the release archive."

    [ -f "${extract_dir}/${binary_name}" ] && [ ! -L "${extract_dir}/${binary_name}" ] && [ -s "${extract_dir}/${binary_name}" ] || die \
        "归档中的 $binary_name 不是有效的普通文件。" \
        "$binary_name in the archive is not a valid regular file."
    [ -f "${extract_dir}/LICENSE" ] && [ ! -L "${extract_dir}/LICENSE" ] && [ -s "${extract_dir}/LICENSE" ] || die \
        "归档中的 LICENSE 不是有效的普通文件。" \
        "LICENSE in the archive is not a valid regular file."
    [ -f "${extract_dir}/NOTICE" ] && [ ! -L "${extract_dir}/NOTICE" ] && [ -s "${extract_dir}/NOTICE" ] || die \
        "归档中的 NOTICE 不是有效的普通文件。" \
        "NOTICE in the archive is not a valid regular file."
    [ -d "${extract_dir}/LICENSES" ] && [ ! -L "${extract_dir}/LICENSES" ] || die \
        "归档中的 LICENSES 不是有效目录。" \
        "LICENSES in the archive is not a valid directory."

    local extracted_count=0
    local license_file
    for license_file in "${extract_dir}/LICENSES/"*.txt; do
        [ -e "$license_file" ] || continue
        [ -f "$license_file" ] && [ ! -L "$license_file" ] && [ -s "$license_file" ] || die \
            "归档中存在无效的第三方许可文件。" \
            "The archive contains an invalid third-party license file."
        extracted_count=$((extracted_count + 1))
    done
    [ "$extracted_count" -eq "$third_party_count" ] || die \
        "解压后的第三方许可文件集合与归档清单不一致。" \
        "The extracted third-party license set does not match the archive manifest."

    install -m 0755 "${extract_dir}/${binary_name}" "${VOCAT_TMP}/vocat"
    VOCAT_PAYLOAD="$extract_dir"
}

download_and_verify() {
    VOCAT_TMP=$(mktemp -d)
    trap 'rm -rf "$VOCAT_TMP"' EXIT
    command -v tar >/dev/null 2>&1 || die \
        "系统缺少 tar，无法安装发布归档。" \
        "tar is required to install the release archive."
    command -v sha256sum >/dev/null 2>&1 || die \
        "系统缺少 sha256sum，无法验证发布归档。" \
        "sha256sum is required to verify the release archive."
    local base="https://github.com/${REPO}/releases/download/v${TARGET_VERSION}"
    local asset="vocat-linux-${ARCH}.tar.gz"
    if [ -n "$ARCH_FALLBACK" ] && ! curl -fsIL -o /dev/null "${base}/${asset}"; then
        asset="vocat-linux-${ARCH_FALLBACK}.tar.gz"
    fi
    msg "下载 $asset ..." "Downloading $asset ..."
    local archive="${VOCAT_TMP}/${asset}"
    download_bounded "$archive" "$MAX_RELEASE_ARCHIVE_BYTES" \
        "${base}/${asset}" "${CURL_DL_OPTS[@]}" || die \
        "下载发布归档失败或归档超过 512 MiB 安全上限。" \
        "Failed to download the release archive or it exceeds the 512 MiB safety limit."
    local archive_size
    archive_size=$(wc -c < "$archive")
    [ "$archive_size" -gt 0 ] && [ "$archive_size" -le "$MAX_RELEASE_ARCHIVE_BYTES" ] || die \
        "发布归档为空或超过 512 MiB 安全上限。" \
        "The release archive is empty or exceeds the 512 MiB safety limit."
    local checksums="${VOCAT_TMP}/SHA256SUMS"
    download_bounded "$checksums" "$MAX_CHECKSUM_BYTES" \
        "${base}/SHA256SUMS" -fsSL || die \
        "下载 SHA256SUMS 失败或文件超过 1 MiB 安全上限。" \
        "Failed to download SHA256SUMS or it exceeds the 1 MiB safety limit."
    local checksum_size
    checksum_size=$(wc -c < "$checksums")
    [ "$checksum_size" -gt 0 ] && [ "$checksum_size" -le "$MAX_CHECKSUM_BYTES" ] || die \
        "SHA256SUMS 为空或超过 1 MiB 安全上限。" \
        "SHA256SUMS is empty or exceeds the 1 MiB safety limit."

    local checksum_record checksum_count expected actual
    # Require exactly one checksum record whose filename equals the archive
    # asset (with an optional GNU binary-mode * prefix).
    checksum_record=$(awk -v a="$asset" '
        $2 == a || $2 == ("*" a) { count++; hash = $1 }
        END { printf "%d:%s\n", count, hash }
    ' "$checksums")
    checksum_count="${checksum_record%%:*}"
    expected="${checksum_record#*:}"
    [ "$checksum_count" -eq 1 ] || die \
        "SHA256SUMS 必须且只能包含一条 $asset 校验记录。" \
        "SHA256SUMS must contain exactly one checksum record for $asset."
    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || die \
        "SHA256SUMS 中 $asset 的哈希格式无效。" \
        "The SHA256SUMS hash for $asset is malformed."
    expected=$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')
    actual=$(sha256sum "$archive" | awk '{print $1}')
    [ "$actual" = "$expected" ] || die "SHA-256 校验失败。" "SHA-256 verification failed."

    local binary_name="${asset%.tar.gz}"
    validate_and_extract_archive "$archive" "$binary_name"
    validate_candidate_binary "${VOCAT_TMP}/vocat" "$TARGET_VERSION" || die \
        "归档中的二进制无法运行、版本输出无效，或与目标版本 $TARGET_VERSION 不一致；未更改当前安装。" \
        "The archived binary cannot run, has invalid version output, or does not match target version $TARGET_VERSION; the installed version was not changed."
    VOCAT_ARCHIVE="$archive"
}

select_service_manager() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        SERVICE_MANAGER="systemd"
        SERVICE_CONFIG_PATH="$UNIT_PATH"
        return
    fi
    if [ -x /sbin/procd ] || [ -x /sbin/ubusd ]; then
        SERVICE_MANAGER="openwrt"
        SERVICE_CONFIG_PATH="$OPENWRT_INIT_PATH"
        return
    fi
    die \
        "不支持的服务管理器。" \
        "Neither systemd nor OpenWrt procd was detected."
}

systemd_service_stopped() {
    local active_state main_pid control_pid
    active_state=$(systemctl show vocat --property=ActiveState --value 2>/dev/null) || return 1
    main_pid=$(systemctl show vocat --property=MainPID --value 2>/dev/null) || return 1
    control_pid=$(systemctl show vocat --property=ControlPID --value 2>/dev/null) || return 1
    case "$active_state" in
        inactive|failed) ;;
        *) return 1 ;;
    esac
    case "$main_pid" in ""|0) ;; *) return 1 ;; esac
    case "$control_pid" in ""|0) ;; *) return 1 ;; esac
}

stop_service_for_install() {
    select_service_manager
    SERVICE_WAS_ACTIVE=0
    SERVICE_WAS_ENABLED=0
    # From this point onward, every failure must restore the database and any
    # payload files already replaced, then restart a service that was running.
    PAYLOAD_INSTALL_PENDING=1

    local attempt
    case "$SERVICE_MANAGER" in
        systemd)
            local active_state
            if systemctl is-enabled --quiet vocat; then
                SERVICE_WAS_ENABLED=1
            fi
            active_state=$(systemctl show vocat --property=ActiveState --value 2>/dev/null || true)
            case "$active_state" in
                active|activating|reloading|deactivating) SERVICE_WAS_ACTIVE=1 ;;
            esac
            if ! systemctl show vocat --property=LoadState --value 2>/dev/null | grep -qx loaded; then
                return
            fi
            # Stop even when currently inactive so a queued systemd auto-restart
            # cannot race the database snapshot.
            systemctl stop vocat || true
            attempt=0
            while [ "$attempt" -lt 40 ]; do
                if systemd_service_stopped; then
                    return
                fi
                attempt=$((attempt + 1))
                sleep 1
            done
            ;;
        openwrt)
            if [ ! -x "$OPENWRT_INIT_PATH" ]; then
                return
            fi
            if "$OPENWRT_INIT_PATH" enabled; then
                SERVICE_WAS_ENABLED=1
            fi
            if "$OPENWRT_INIT_PATH" running; then
                SERVICE_WAS_ACTIVE=1
            fi
            "$OPENWRT_INIT_PATH" stop || true
            attempt=0
            while [ "$attempt" -lt 40 ]; do
                if ! "$OPENWRT_INIT_PATH" running; then
                    return
                fi
                attempt=$((attempt + 1))
                sleep 1
            done
            ;;
    esac
    die \
        "无法在数据库迁移前停止现有 vocat 服务。" \
        "Failed to stop the existing vocat service before database migration."
}

stop_current_service_for_rollback() {
    [ "$NEW_SERVICE_START_ATTEMPTED" -eq 1 ] || return 0

    # Do not change SERVICE_WAS_ACTIVE here: it records whether the old version
    # must be restarted after rollback. This function only fences the candidate
    # process away from the SQLite files before they are restored.
    local attempt
    case "$SERVICE_MANAGER" in
        systemd)
            systemctl stop vocat || true
            attempt=0
            while [ "$attempt" -lt 40 ]; do
                if systemd_service_stopped; then
                    NEW_SERVICE_START_ATTEMPTED=0
                    return 0
                fi
                attempt=$((attempt + 1))
                sleep 1
            done
            ;;
        openwrt)
            if [ -x "$OPENWRT_INIT_PATH" ]; then
                "$OPENWRT_INIT_PATH" stop || true
            fi
            attempt=0
            while [ "$attempt" -lt 40 ]; do
                if [ ! -x "$OPENWRT_INIT_PATH" ] || ! "$OPENWRT_INIT_PATH" running; then
                    NEW_SERVICE_START_ATTEMPTED=0
                    return 0
                fi
                attempt=$((attempt + 1))
                sleep 1
            done
            ;;
        *)
            return 1
            ;;
    esac
    return 1
}

backup_database_for_install() {
    local database_file backup_file
    for database_file in "$DATABASE_PATH" "$DATABASE_WAL_PATH" "$DATABASE_SHM_PATH"; do
        if [ -L "$database_file" ] || { [ -e "$database_file" ] && [ ! -f "$database_file" ]; }; then
            die \
                "$database_file 必须是普通文件或尚不存在。" \
                "$database_file must be a regular file or not exist."
        fi
    done
    for backup_file in \
        "${DATABASE_PATH}.old.$$" \
        "${DATABASE_WAL_PATH}.old.$$" \
        "${DATABASE_SHM_PATH}.old.$$"; do
        if [ -e "$backup_file" ] || [ -L "$backup_file" ]; then
            die \
                "数据库事务备份路径已存在；拒绝覆盖: $backup_file" \
                "A database transaction backup already exists; refusing to overwrite it: $backup_file"
        fi
    done

    DATABASE_HAD_PREVIOUS=0
    DATABASE_WAL_HAD_PREVIOUS=0
    DATABASE_SHM_HAD_PREVIOUS=0
    if [ -f "$DATABASE_PATH" ]; then
        cp -a "$DATABASE_PATH" "${DATABASE_PATH}.old.$$"
        DATABASE_HAD_PREVIOUS=1
    fi
    if [ -f "$DATABASE_WAL_PATH" ]; then
        cp -a "$DATABASE_WAL_PATH" "${DATABASE_WAL_PATH}.old.$$"
        DATABASE_WAL_HAD_PREVIOUS=1
    fi
    if [ -f "$DATABASE_SHM_PATH" ]; then
        cp -a "$DATABASE_SHM_PATH" "${DATABASE_SHM_PATH}.old.$$"
        DATABASE_SHM_HAD_PREVIOUS=1
    fi

    # The service is stopped and the complete SQLite file set is now backed up.
    # Mark it touched before invoking the candidate, which may migrate or create
    # the database even if bootstrap-admin ultimately returns an error.
    DATABASE_TOUCHED=1
}

backup_runtime_configuration_for_install() {
    [ -n "$SERVICE_CONFIG_PATH" ] || die \
        "内部错误：服务配置路径尚未选择。" \
        "Internal error: the service configuration path has not been selected."

    local runtime_file backup_file
    for runtime_file in "$ENV_FILE" "$SERVICE_CONFIG_PATH"; do
        if [ -L "$runtime_file" ] || { [ -e "$runtime_file" ] && [ ! -f "$runtime_file" ]; }; then
            die \
                "$runtime_file 必须是普通文件或尚不存在。" \
                "$runtime_file must be a regular file or not exist."
        fi
    done
    for backup_file in "${ENV_FILE}.old.$$" "${SERVICE_CONFIG_PATH}.old.$$"; do
        if [ -e "$backup_file" ] || [ -L "$backup_file" ]; then
            die \
                "运行配置事务备份路径已存在；拒绝覆盖: $backup_file" \
                "A runtime-configuration transaction backup already exists; refusing to overwrite it: $backup_file"
        fi
    done

    ENV_HAD_PREVIOUS=0
    SERVICE_CONFIG_HAD_PREVIOUS=0
    if [ -f "$ENV_FILE" ]; then
        ENV_HAD_PREVIOUS=1
        if ! cp -a "$ENV_FILE" "${ENV_FILE}.old.$$"; then
            rm -f "${ENV_FILE}.old.$$" || true
            die \
                "无法备份现有 VoCat 环境配置。" \
                "Failed to back up the existing VoCat environment configuration."
        fi
    fi
    if [ -f "$SERVICE_CONFIG_PATH" ]; then
        SERVICE_CONFIG_HAD_PREVIOUS=1
        if ! cp -a "$SERVICE_CONFIG_PATH" "${SERVICE_CONFIG_PATH}.old.$$"; then
            rm -f "${ENV_FILE}.old.$$" "${SERVICE_CONFIG_PATH}.old.$$" || true
            die \
                "无法备份现有 VoCat 服务配置。" \
                "Failed to back up the existing VoCat service configuration."
        fi
    fi

    # setup_env and write_service may now replace files consumed by the old
    # binary. Keep their backups armed until the candidate passes health checks.
    RUNTIME_CONFIG_TOUCHED=1
}

restore_runtime_configuration() {
    [ "$RUNTIME_CONFIG_TOUCHED" -eq 1 ] || return 0
    [ -n "$SERVICE_CONFIG_PATH" ] || return 1

    local runtime_file backup_file
    local backups_valid=1
    for runtime_file in "$ENV_FILE" "$SERVICE_CONFIG_PATH"; do
        if [ -L "$runtime_file" ] || { [ -e "$runtime_file" ] && [ ! -f "$runtime_file" ]; }; then
            backups_valid=0
        fi
    done
    if [ "$ENV_HAD_PREVIOUS" -eq 1 ]; then
        backup_file="${ENV_FILE}.old.$$"
        [ -f "$backup_file" ] && [ ! -L "$backup_file" ] || backups_valid=0
    fi
    if [ "$SERVICE_CONFIG_HAD_PREVIOUS" -eq 1 ]; then
        backup_file="${SERVICE_CONFIG_PATH}.old.$$"
        [ -f "$backup_file" ] && [ ! -L "$backup_file" ] || backups_valid=0
    fi
    # Validate every required backup before disabling or replacing anything.
    # A missing backup must preserve the current files for manual recovery.
    [ "$backups_valid" -eq 1 ] || return 1

    if [ "$SERVICE_CONFIG_HAD_PREVIOUS" -eq 0 ] && \
        [ "$NEW_SERVICE_ENABLE_ATTEMPTED" -eq 1 ]; then
        case "$SERVICE_MANAGER" in
            systemd)
                systemctl disable vocat >/dev/null 2>&1 || return 1
                ;;
            openwrt)
                [ -x "$OPENWRT_INIT_PATH" ] || return 1
                "$OPENWRT_INIT_PATH" disable || return 1
                ;;
            *)
                return 1
                ;;
        esac
    fi

    local restore_failed=0
    if [ "$ENV_HAD_PREVIOUS" -eq 1 ]; then
        mv -f "${ENV_FILE}.old.$$" "$ENV_FILE" || restore_failed=1
    elif ! rm -f "$ENV_FILE"; then
        restore_failed=1
    fi
    if [ "$SERVICE_CONFIG_HAD_PREVIOUS" -eq 1 ]; then
        mv -f "${SERVICE_CONFIG_PATH}.old.$$" "$SERVICE_CONFIG_PATH" || restore_failed=1
    elif ! rm -f "$SERVICE_CONFIG_PATH"; then
        restore_failed=1
    fi
    [ "$restore_failed" -eq 0 ]
}

restore_command_link() {
    [ "$LINK_TOUCHED" -eq 1 ] || return 0

    local link_backup="${LINK_PATH}.old.$$"
    if [ -e "$LINK_PATH" ] && [ ! -f "$LINK_PATH" ] && [ ! -L "$LINK_PATH" ]; then
        return 1
    fi
    if [ "$LINK_HAD_PREVIOUS" -eq 1 ] && \
        [ ! -f "$link_backup" ] && [ ! -L "$link_backup" ]; then
        return 1
    fi

    rm -f "$LINK_PATH" || return 1
    if [ "$LINK_HAD_PREVIOUS" -eq 1 ]; then
        mv -f "$link_backup" "$LINK_PATH" || return 1
    fi
}

restart_previous_service() {
    case "$SERVICE_MANAGER" in
        systemd)
            systemctl daemon-reload || return 1
            if [ "$SERVICE_WAS_ENABLED" -eq 1 ]; then
                systemctl enable vocat >/dev/null || return 1
            else
                systemctl disable vocat >/dev/null 2>&1 || true
            fi
            [ "$SERVICE_WAS_ACTIVE" -eq 1 ] || return 0
            systemctl restart vocat
            ;;
        openwrt)
            [ -x "$OPENWRT_INIT_PATH" ] || return 0
            if [ "$SERVICE_WAS_ENABLED" -eq 1 ]; then
                "$OPENWRT_INIT_PATH" enable || return 1
            else
                "$OPENWRT_INIT_PATH" disable || true
            fi
            [ "$SERVICE_WAS_ACTIVE" -eq 1 ] || return 0
            "$OPENWRT_INIT_PATH" restart
            ;;
        *)
            return 1
            ;;
    esac
}

install_notices() {
    [ -n "$VOCAT_PAYLOAD" ] && [ -d "$VOCAT_PAYLOAD" ] || die \
        "内部错误：已验证的许可声明目录不可用。" \
        "Internal error: the verified license-notice directory is unavailable."
    if [ -L "$LICENSES_DIR" ] || { [ -e "$LICENSES_DIR" ] && [ ! -d "$LICENSES_DIR" ]; }; then
        die \
            "$LICENSES_DIR 必须是普通目录。" \
            "$LICENSES_DIR must be a regular directory."
    fi
    local destination
    for destination in "${NOTICE_ROOT}/LICENSE" "${NOTICE_ROOT}/NOTICE"; do
        if [ -L "$destination" ] || { [ -e "$destination" ] && [ ! -f "$destination" ]; }; then
            die \
                "$destination 必须是普通文件或尚不存在。" \
                "$destination must be a regular file or not exist."
        fi
    done
    install -d -m 0755 "$NOTICE_ROOT"

    local license_new notice_new license_backup notice_backup
    local licenses_staging licenses_backup temporary
    license_new="${NOTICE_ROOT}/.LICENSE.new.$$"
    notice_new="${NOTICE_ROOT}/.NOTICE.new.$$"
    license_backup="${NOTICE_ROOT}/.LICENSE.old.$$"
    notice_backup="${NOTICE_ROOT}/.NOTICE.old.$$"
    licenses_staging="${NOTICE_ROOT}/.LICENSES.new.$$"
    licenses_backup="${NOTICE_ROOT}/.LICENSES.old.$$"
    for temporary in "$license_new" "$notice_new" "$license_backup" \
        "$notice_backup" "$licenses_staging" "$licenses_backup"; do
        if [ -e "$temporary" ] || [ -L "$temporary" ]; then
            die \
                "许可声明的临时路径已存在；拒绝覆盖: $temporary" \
                "A temporary license-notice path already exists; refusing to overwrite it: $temporary"
        fi
    done

    # From this point onward, the EXIT trap removes staging paths and restores
    # any notice files that have already been replaced.
    PAYLOAD_INSTALL_PENDING=1
    install -m 0644 "${VOCAT_PAYLOAD}/LICENSE" "$license_new"
    install -m 0644 "${VOCAT_PAYLOAD}/NOTICE" "$notice_new"

    local license_file license_name
    install -d -m 0755 "$licenses_staging"
    for license_file in "${VOCAT_PAYLOAD}/LICENSES/"*.txt; do
        [ -f "$license_file" ] || continue
        license_name="${license_file##*/}"
        install -m 0644 "$license_file" "${licenses_staging}/${license_name}"
    done

    LICENSE_HAD_PREVIOUS=0
    if [ -f "${NOTICE_ROOT}/LICENSE" ]; then
        cp -a "${NOTICE_ROOT}/LICENSE" "$license_backup"
        LICENSE_HAD_PREVIOUS=1
    fi
    NOTICE_HAD_PREVIOUS=0
    if [ -f "${NOTICE_ROOT}/NOTICE" ]; then
        cp -a "${NOTICE_ROOT}/NOTICE" "$notice_backup"
        NOTICE_HAD_PREVIOUS=1
    fi
    LICENSES_HAD_PREVIOUS=0
    if [ -d "$LICENSES_DIR" ]; then
        mv "$LICENSES_DIR" "$licenses_backup" || die \
            "无法暂存现有 LICENSES 目录。" \
            "Failed to stage the existing LICENSES directory."
        LICENSES_HAD_PREVIOUS=1
    fi
    NOTICES_TOUCHED=1
    mv "$licenses_staging" "$LICENSES_DIR"
    mv -f "$license_new" "${NOTICE_ROOT}/LICENSE"
    mv -f "$notice_new" "${NOTICE_ROOT}/NOTICE"
}

# --- Install binary ----------------------------------------------------------
restore_database_backup() {
    [ "$DATABASE_TOUCHED" -eq 1 ] || return 0

    local database_file backup_file
    local backups_valid=1
    if [ "$DATABASE_HAD_PREVIOUS" -eq 1 ]; then
        backup_file="${DATABASE_PATH}.old.$$"
        [ -f "$backup_file" ] && [ ! -L "$backup_file" ] || backups_valid=0
    fi
    if [ "$DATABASE_WAL_HAD_PREVIOUS" -eq 1 ]; then
        backup_file="${DATABASE_WAL_PATH}.old.$$"
        [ -f "$backup_file" ] && [ ! -L "$backup_file" ] || backups_valid=0
    fi
    if [ "$DATABASE_SHM_HAD_PREVIOUS" -eq 1 ]; then
        backup_file="${DATABASE_SHM_PATH}.old.$$"
        [ -f "$backup_file" ] && [ ! -L "$backup_file" ] || backups_valid=0
    fi
    for database_file in "$DATABASE_PATH" "$DATABASE_WAL_PATH" "$DATABASE_SHM_PATH"; do
        if [ -e "$database_file" ] && [ ! -f "$database_file" ] && [ ! -L "$database_file" ]; then
            backups_valid=0
        fi
    done
    [ "$backups_valid" -eq 1 ] || return 1

    local restore_failed=0
    for database_file in "$DATABASE_PATH" "$DATABASE_WAL_PATH" "$DATABASE_SHM_PATH"; do
        rm -f "$database_file" || restore_failed=1
    done
    [ "$restore_failed" -eq 0 ] || return 1

    if [ "$DATABASE_HAD_PREVIOUS" -eq 1 ]; then
        mv "${DATABASE_PATH}.old.$$" "$DATABASE_PATH" || restore_failed=1
    fi
    if [ "$DATABASE_WAL_HAD_PREVIOUS" -eq 1 ]; then
        mv "${DATABASE_WAL_PATH}.old.$$" "$DATABASE_WAL_PATH" || restore_failed=1
    fi
    if [ "$DATABASE_SHM_HAD_PREVIOUS" -eq 1 ]; then
        mv "${DATABASE_SHM_PATH}.old.$$" "$DATABASE_SHM_PATH" || restore_failed=1
    fi
    [ "$restore_failed" -eq 0 ]
}

rollback_payload_install() {
    local rollback_failed=0

    if ! restore_runtime_configuration; then
        rollback_failed=1
    fi
    if ! restore_command_link; then
        rollback_failed=1
    fi

    if [ "$PAYLOAD_FILES_TOUCHED" -eq 1 ]; then
        if [ "$BINARY_HAD_PREVIOUS" -eq 1 ]; then
            if [ ! -f "${BINARY_PATH}.bak" ] || [ -L "${BINARY_PATH}.bak" ] || \
                ! mv -f "${BINARY_PATH}.bak" "$BINARY_PATH"; then
                rollback_failed=1
            fi
        elif ! rm -f "$BINARY_PATH"; then
            rollback_failed=1
        fi

        if [ "$ARCHIVE_HAD_PREVIOUS" -eq 1 ]; then
            if [ ! -f "${ARCHIVE_PATH}.bak" ] || [ -L "${ARCHIVE_PATH}.bak" ] || \
                ! mv -f "${ARCHIVE_PATH}.bak" "$ARCHIVE_PATH"; then
                rollback_failed=1
            fi
        elif ! rm -f "$ARCHIVE_PATH"; then
            rollback_failed=1
        fi
    fi

    if [ "$NOTICES_TOUCHED" -eq 1 ]; then
        if [ "$LICENSE_HAD_PREVIOUS" -eq 1 ]; then
            if [ ! -f "${NOTICE_ROOT}/.LICENSE.old.$$" ] || \
                [ -L "${NOTICE_ROOT}/.LICENSE.old.$$" ] || \
                ! mv -f "${NOTICE_ROOT}/.LICENSE.old.$$" "${NOTICE_ROOT}/LICENSE"; then
                rollback_failed=1
            fi
        elif ! rm -f "${NOTICE_ROOT}/LICENSE"; then
            rollback_failed=1
        fi

        if [ "$NOTICE_HAD_PREVIOUS" -eq 1 ]; then
            if [ ! -f "${NOTICE_ROOT}/.NOTICE.old.$$" ] || \
                [ -L "${NOTICE_ROOT}/.NOTICE.old.$$" ] || \
                ! mv -f "${NOTICE_ROOT}/.NOTICE.old.$$" "${NOTICE_ROOT}/NOTICE"; then
                rollback_failed=1
            fi
        elif ! rm -f "${NOTICE_ROOT}/NOTICE"; then
            rollback_failed=1
        fi

        if [ -L "$LICENSES_DIR" ]; then
            rm -f "$LICENSES_DIR" || rollback_failed=1
        elif [ -d "$LICENSES_DIR" ]; then
            rm -rf "$LICENSES_DIR" || rollback_failed=1
        elif [ -e "$LICENSES_DIR" ]; then
            rollback_failed=1
        fi
        if [ "$LICENSES_HAD_PREVIOUS" -eq 1 ]; then
            if [ ! -d "${NOTICE_ROOT}/.LICENSES.old.$$" ] || \
                [ -L "${NOTICE_ROOT}/.LICENSES.old.$$" ] || \
                ! mv "${NOTICE_ROOT}/.LICENSES.old.$$" "$LICENSES_DIR"; then
                rollback_failed=1
            fi
        fi
    fi

    if ! restore_database_backup; then
        rollback_failed=1
    fi

    rm -f "${BINARY_PATH}.new.$$" "${ARCHIVE_PATH}.new.$$" || rollback_failed=1
    PAYLOAD_INSTALL_PENDING=0
    if [ "$rollback_failed" -eq 0 ]; then
        rm -f "${BINARY_PATH}.bak" "${ARCHIVE_PATH}.bak" \
            "${NOTICE_ROOT}/.LICENSE.new.$$" "${NOTICE_ROOT}/.NOTICE.new.$$" \
            "${NOTICE_ROOT}/.LICENSE.old.$$" "${NOTICE_ROOT}/.NOTICE.old.$$"
        rm -rf "${NOTICE_ROOT}/.LICENSES.new.$$" "${NOTICE_ROOT}/.LICENSES.old.$$"
        rm -f "${DATABASE_PATH}.old.$$" \
            "${DATABASE_WAL_PATH}.old.$$" \
            "${DATABASE_SHM_PATH}.old.$$" \
            "${ENV_FILE}.old.$$" \
            "${SERVICE_CONFIG_PATH}.old.$$" \
            "${LINK_PATH}.old.$$"
        BINARY_HAD_PREVIOUS=0
        ARCHIVE_HAD_PREVIOUS=0
        LINK_HAD_PREVIOUS=0
        LICENSE_HAD_PREVIOUS=0
        NOTICE_HAD_PREVIOUS=0
        LICENSES_HAD_PREVIOUS=0
        DATABASE_HAD_PREVIOUS=0
        DATABASE_WAL_HAD_PREVIOUS=0
        DATABASE_SHM_HAD_PREVIOUS=0
        DATABASE_TOUCHED=0
        ENV_HAD_PREVIOUS=0
        SERVICE_CONFIG_HAD_PREVIOUS=0
        RUNTIME_CONFIG_TOUCHED=0
        PAYLOAD_FILES_TOUCHED=0
        LINK_TOUCHED=0
        NOTICES_TOUCHED=0
        NEW_SERVICE_ENABLE_ATTEMPTED=0
        return 0
    fi
    return 1
}

cleanup_install() {
    local exit_status=$?
    trap - EXIT
    if [ "$PAYLOAD_INSTALL_PENDING" -eq 1 ]; then
        if ! stop_current_service_for_rollback; then
            msg \
                "安装失败，但候选服务无法停止；为避免并发破坏数据库，未执行自动回滚，请检查保留的事务备份。" \
                "Installation failed, but the candidate service could not be stopped. Automatic rollback was skipped to avoid corrupting the database; inspect the retained transaction backups."
        elif rollback_payload_install; then
            if ! restart_previous_service; then
                msg \
                    "安装失败，原版本已恢复，但无法重新启动先前运行的服务。" \
                    "Installation failed and the previous version was restored, but its service could not be restarted."
            fi
        else
            msg \
                "安装失败，且无法完整恢复原命令链接、运行配置、数据库、二进制、发布归档或许可声明；请检查保留的 .bak/.old 文件。" \
                "Installation failed and the previous command link, runtime configuration, database, binary, release archive, or license notices could not be fully restored; inspect the retained .bak/.old files."
        fi
    fi
    if [ -n "$VOCAT_TMP" ] && [ -d "$VOCAT_TMP" ]; then
        rm -rf "$VOCAT_TMP"
    fi
    if ! release_install_lock; then
        msg \
            "无法可靠释放 VoCat 安装锁: $INSTALL_LOCK_DIR" \
            "Failed to release the VoCat installation lock reliably: $INSTALL_LOCK_DIR"
        [ "$exit_status" -ne 0 ] || exit_status=1
    fi
    exit "$exit_status"
}

install_binary() {
    [ -n "$VOCAT_ARCHIVE" ] && [ -f "$VOCAT_ARCHIVE" ] && [ ! -L "$VOCAT_ARCHIVE" ] && [ -s "$VOCAT_ARCHIVE" ] || die \
        "内部错误：已验证的发布归档不可用。" \
        "Internal error: the verified release archive is unavailable."
    if [ -L "$ARCHIVE_PATH" ] || { [ -e "$ARCHIVE_PATH" ] && [ ! -f "$ARCHIVE_PATH" ]; }; then
        die \
            "$ARCHIVE_PATH 必须是普通文件或尚不存在。" \
            "$ARCHIVE_PATH must be a regular file or not exist."
    fi
    if [ -L "$BINARY_PATH" ] || { [ -e "$BINARY_PATH" ] && [ ! -f "$BINARY_PATH" ]; }; then
        die \
            "$BINARY_PATH 必须是普通文件或尚不存在。" \
            "$BINARY_PATH must be a regular file or not exist."
    fi
    validate_command_path
    if [ -e "${LINK_PATH}.old.$$" ] || [ -L "${LINK_PATH}.old.$$" ]; then
        die \
            "命令链接事务备份路径已存在；拒绝覆盖: ${LINK_PATH}.old.$$" \
            "A command-link transaction backup already exists; refusing to overwrite it: ${LINK_PATH}.old.$$"
    fi
    install -d -m 0755 "$INSTALL_DIR"
    local binary_new="${BINARY_PATH}.new.$$"
    local archive_new="${ARCHIVE_PATH}.new.$$"
    install -m 0755 "${VOCAT_TMP}/vocat" "$binary_new"
    install -m 0644 "$VOCAT_ARCHIVE" "$archive_new"
    BINARY_HAD_PREVIOUS=0
    if [ -e "$BINARY_PATH" ]; then
        cp -a "$BINARY_PATH" "${BINARY_PATH}.bak"
        BINARY_HAD_PREVIOUS=1
    else
        rm -f "${BINARY_PATH}.bak"
    fi
    ARCHIVE_HAD_PREVIOUS=0
    if [ -e "$ARCHIVE_PATH" ]; then
        cp -a "$ARCHIVE_PATH" "${ARCHIVE_PATH}.bak"
        ARCHIVE_HAD_PREVIOUS=1
    else
        rm -f "${ARCHIVE_PATH}.bak"
    fi
    LINK_HAD_PREVIOUS=0
    if [ -e "$LINK_PATH" ] || [ -L "$LINK_PATH" ]; then
        if ! cp -a "$LINK_PATH" "${LINK_PATH}.old.$$"; then
            rm -f "${LINK_PATH}.old.$$" || true
            die \
                "无法备份现有 VoCat 命令路径。" \
                "Failed to back up the existing VoCat command path."
        fi
        LINK_HAD_PREVIOUS=1
    fi
    PAYLOAD_FILES_TOUCHED=1
    mv -f "$archive_new" "$ARCHIVE_PATH"
    mv -f "$binary_new" "$BINARY_PATH"
    install -d -m 0755 "$(dirname "$LINK_PATH")"
    LINK_TOUCHED=1
    ln -sfn "$BINARY_PATH" "$LINK_PATH"
}

complete_payload_install() {
    # The service has passed its stability window, so commit before deleting
    # recovery files. A cleanup error must not trigger an unsafe rollback while
    # the newly started process is already writing the migrated database.
    PAYLOAD_INSTALL_PENDING=0
    BINARY_HAD_PREVIOUS=0
    ARCHIVE_HAD_PREVIOUS=0
    LINK_HAD_PREVIOUS=0
    LICENSE_HAD_PREVIOUS=0
    NOTICE_HAD_PREVIOUS=0
    LICENSES_HAD_PREVIOUS=0
    DATABASE_HAD_PREVIOUS=0
    DATABASE_WAL_HAD_PREVIOUS=0
    DATABASE_SHM_HAD_PREVIOUS=0
    DATABASE_TOUCHED=0
    ENV_HAD_PREVIOUS=0
    SERVICE_CONFIG_HAD_PREVIOUS=0
    RUNTIME_CONFIG_TOUCHED=0
    PAYLOAD_FILES_TOUCHED=0
    LINK_TOUCHED=0
    NOTICES_TOUCHED=0
    SERVICE_WAS_ACTIVE=0
    SERVICE_WAS_ENABLED=0
    NEW_SERVICE_ENABLE_ATTEMPTED=0
    NEW_SERVICE_START_ATTEMPTED=0

    if ! rm -f "${BINARY_PATH}.bak" "${ARCHIVE_PATH}.bak" \
        "${NOTICE_ROOT}/.LICENSE.new.$$" "${NOTICE_ROOT}/.NOTICE.new.$$" \
        "${NOTICE_ROOT}/.LICENSE.old.$$" "${NOTICE_ROOT}/.NOTICE.old.$$" \
        "${DATABASE_PATH}.old.$$" \
        "${DATABASE_WAL_PATH}.old.$$" \
        "${DATABASE_SHM_PATH}.old.$$" \
        "${ENV_FILE}.old.$$" \
        "${SERVICE_CONFIG_PATH}.old.$$" \
        "${LINK_PATH}.old.$$"; then
        msg \
            "警告：新版本已提交，但部分事务备份文件无法删除。" \
            "Warning: the new version was committed, but some transaction backup files could not be removed."
    fi
    if ! rm -rf "${NOTICE_ROOT}/.LICENSES.new.$$" "${NOTICE_ROOT}/.LICENSES.old.$$"; then
        msg \
            "警告：新版本已提交，但许可声明的临时目录无法删除。" \
            "Warning: the new version was committed, but temporary license-notice directories could not be removed."
    fi
}

# --- Data directory ----------------------------------------------------------
ensure_data_dir() {
    install -d -m 0755 /opt/vocat/data
    chown -R root:root /opt/vocat
}

# --- Administrator bootstrap and non-secret environment ---------------------
FIRST_INSTALL=0
INITIAL_ADMIN_PASSWORD=""

bootstrap_admin() {
    local candidate="${1:-$BINARY_PATH}"
    local secret result
    if command -v od >/dev/null 2>&1; then
        secret=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    elif command -v hexdump >/dev/null 2>&1; then
        secret=$(hexdump -n 16 -e '16/1 "%02x"' /dev/urandom)
    elif command -v openssl >/dev/null 2>&1; then
        secret=$(openssl rand -hex 16 2>/dev/null || true)
    elif command -v sha256sum >/dev/null 2>&1; then
        secret=$(head -c 32 /dev/urandom | sha256sum | awk '{print substr($1, 1, 32)}')
    else
        secret=$(tr -dc 'a-f0-9' < /dev/urandom | head -c 32)
    fi
    [ -n "$secret" ] || die "生成随机密钥失败。" "Failed to generate a random secret."
    result=$(printf '%s\n' "$secret" | "$candidate" bootstrap-admin --database "$DATABASE_PATH" --username admin) || \
        die \
            "待安装版本无法读取或升级现有数据库；当前程序尚未被替换，请检查数据库与版本兼容性。" \
            "The candidate version cannot read or migrate the existing database; the installed program was not replaced. Check database and version compatibility."
    if [ "$result" = "created" ]; then
        FIRST_INSTALL=1
        INITIAL_ADMIN_PASSWORD="$secret"
    fi
}

setup_env() {
    install -d -m 0755 "$ENV_DIR"
    local temporary="${ENV_FILE}.new.$$"
    if [ -f "$ENV_FILE" ]; then
        if ! awk '!/^VOCAT_ADMIN_(USERNAME|PASSWORD|PASSWORD_B64)=/' \
            "$ENV_FILE" > "$temporary"; then
            rm -f "$temporary" || true
            die \
                "无法安全读取或重写现有 VoCat 环境配置。" \
                "Failed to safely read or rewrite the existing VoCat environment configuration."
        fi
    else
        : > "$temporary"
    fi
    mv -f "$temporary" "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
}

# --- systemd unit ------------------------------------------------------------
write_unit() {
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=vocat cellular and VoWiFi control service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/vocat
EnvironmentFile=${ENV_FILE}
Environment=VOCAT_DATABASE_PATH=/opt/vocat/data/vocat.db
ExecStart=${BINARY_PATH}
Restart=on-failure
RestartSec=3s
TimeoutStartSec=30s
# HTTP, VoWiFi, and modem cleanup have bounded shutdown contexts totalling up
# to 30 seconds. Leave a small margin before systemd resorts to SIGKILL.
TimeoutStopSec=40s
RuntimeDirectory=vocat
RuntimeDirectoryMode=0755

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=false
ProtectSystem=strict
ProtectHome=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
# The web/CLI self-updater verifies a release in this directory and atomically
# renames it over the running binary. Keep the rest of the host read-only.
ReadWritePaths=/opt/vocat/data /opt/vocat/bin
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$UNIT_PATH"
}

write_openwrt_init() {
    cat > "$OPENWRT_INIT_PATH" <<'EOF'
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1
PROCD_TERM_TIMEOUT=40
PROGRAM=/opt/vocat/bin/vocat
ENV_FILE=/etc/vocat/env
start_service() {
    procd_open_instance
    procd_set_param command "$PROGRAM" serve
    procd_set_param env VOCAT_DATABASE_PATH=/opt/vocat/data/vocat.db
    if [ -r "$ENV_FILE" ]; then
        while IFS='=' read -r name value; do
            case "$name" in VOCAT_*) procd_append_param env "$name=$value" ;; esac
        done < "$ENV_FILE"
    fi
    procd_set_param respawn 3600 5 5
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
service_triggers() { procd_add_reload_trigger vocat; }
EOF
    chmod 0755 "$OPENWRT_INIT_PATH"
}

write_service() {
    case "$SERVICE_MANAGER" in
        systemd) write_unit ;;
        openwrt) write_openwrt_init ;;
        *) die "不支持的服务管理器。" "Neither systemd nor OpenWrt procd was detected." ;;
    esac
}

enable_and_start() {
    if [ "$SERVICE_MANAGER" = "openwrt" ]; then
        NEW_SERVICE_ENABLE_ATTEMPTED=1
        "$OPENWRT_INIT_PATH" enable
        # Stop explicitly before restart. Some procd/rc.common variants return
        # from restart while the previous process is still inside its bounded
        # VoWiFi cleanup, so the replacement can race the host-wide instance
        # lock and enter a respawn cycle.
        "$OPENWRT_INIT_PATH" stop || true
        local stop_attempt
        stop_attempt=0
        while [ "$stop_attempt" -lt 40 ]; do
            if ! "$OPENWRT_INIT_PATH" running; then
                break
            fi
            stop_attempt=$((stop_attempt + 1))
            sleep 1
        done
        NEW_SERVICE_START_ATTEMPTED=1
        if "$OPENWRT_INIT_PATH" restart; then
            # Modems may need several seconds to release and reopen their AT
            # port after procd stops the previous process. Require consecutive
            # healthy observations so a short-lived respawn is not mistaken for
            # a successful upgrade.
            local attempt stable
            stable=0
            for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
                sleep 1
                if "$OPENWRT_INIT_PATH" running; then
                    stable=$((stable + 1))
                    if [ "$stable" -ge 3 ]; then
                        complete_payload_install
                        return
                    fi
                else
                    stable=0
                fi
            done
        fi
        if [ "$PAYLOAD_INSTALL_PENDING" -eq 1 ]; then
            if ! stop_current_service_for_rollback; then
                die \
                    "OpenWrt 候选服务无法停止；为避免并发破坏数据库，已保留事务备份且未自动回滚。" \
                    "The OpenWrt candidate service could not be stopped. Transaction backups were retained and automatic rollback was skipped to avoid corrupting the database."
            fi
            if ! rollback_payload_install; then
                die \
                    "OpenWrt vocat 服务启动失败，且无法完整恢复原版本。" \
                    "The OpenWrt vocat service failed to start and the previous version could not be fully restored."
            fi
            restart_previous_service || true
        fi
        die "OpenWrt vocat 服务启动失败。" "The OpenWrt vocat service failed to start."
    fi
    systemctl daemon-reload
    NEW_SERVICE_ENABLE_ATTEMPTED=1
    systemctl enable vocat
    NEW_SERVICE_START_ATTEMPTED=1
    if systemctl restart vocat; then
        # A just-spawned service is normally active before it has completed
        # initialization. Require consecutive observations so a short-lived
        # process or an early systemd respawn cannot commit the transaction.
        local attempt stable
        stable=0
        for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
            sleep 1
            if systemctl is-active --quiet vocat; then
                stable=$((stable + 1))
                if [ "$stable" -ge 3 ]; then
                    complete_payload_install
                    return
                fi
            else
                stable=0
            fi
        done
    fi
    if [ "$PAYLOAD_INSTALL_PENDING" -eq 1 ]; then
        msg "新版本启动失败，正在恢复旧二进制。" "The new version failed to start; restoring the previous binary."
        if ! stop_current_service_for_rollback; then
            die \
                "候选 vocat 服务无法停止；为避免并发破坏数据库，已保留事务备份且未自动回滚。" \
                "The candidate vocat service could not be stopped. Transaction backups were retained and automatic rollback was skipped to avoid corrupting the database."
        fi
        if ! rollback_payload_install; then
            die \
                "vocat 服务启动失败，且无法完整恢复原版本。" \
                "The vocat service failed to start and the previous version could not be fully restored."
        fi
        restart_previous_service || true
    fi
    die "vocat 服务启动失败。" "The vocat service failed to start."
}

# --- Main --------------------------------------------------------------------
main() {
    [ "$(id -u)" -eq 0 ] || die "请以 root 身份运行此脚本。" "Run this script as root."
    prompt_language
    parse_args "$@"

    detect_arch
    install_qmi_support
    install_pcsc_support
    check_vowifi_environment
    if [ "$CHECK_ENV" -eq 1 ]; then
        msg "VoCat 运行环境检查完成。" "VoCat host environment check completed."
        return 0
    fi
    resolve_target_version
    validate_target_version
    skip_if_equal
    download_and_verify

    # Downloads and archive validation do not mutate the live installation.
    # Hold one machine-wide lock across every stop/backup/migration/replacement
    # step so two operators cannot interleave transaction files or SQLite work.
    trap cleanup_install EXIT
    acquire_install_lock || die \
        "另一个 VoCat 安装或更新事务正在运行（或保留了锁）: $INSTALL_LOCK_DIR" \
        "Another VoCat install/update transaction is running (or retained its lock): $INSTALL_LOCK_DIR"
    stop_service_for_install
    ensure_data_dir
    # Stop all writers and preserve the complete SQLite file set before allowing
    # the candidate to create or migrate the live database. A later failure restores
    # the database together with the executable, archive, and notices.
    backup_database_for_install
    bootstrap_admin "${VOCAT_TMP}/vocat"
    # Install the verified notices before the binary so every newly installed
    # executable is accompanied by the license material from the same archive.
    install_notices
    install_binary
    backup_runtime_configuration_for_install
    setup_env
    write_service
    enable_and_start

    if [ "$FIRST_INSTALL" -eq 1 ]; then
        echo
        msg "================ 安装完成 ================" "================ Install complete ================"
        msg "首次安装已生成管理员初始密码 (仅显示一次):" "First-install admin password (shown once):"
        echo
        echo "    $INITIAL_ADMIN_PASSWORD"
        echo
        msg "用户名为 admin。请立即记录此密码。" "Username is admin. Record this password now."
        msg "登录后或运行以下命令修改密码:" "Change it via the web UI or run:"
        echo "    vocat menu"
        msg "==========================================" "=============================================="
    else
        echo
        msg "================ 更新完成 ================" "================ Update complete ================"
        msg "已更新到 $TARGET_VERSION，服务已重启。" "Updated to $TARGET_VERSION; service restarted."
        msg "管理员密码保持不变。" "Admin password unchanged."
        msg "==========================================" "=============================================="
    fi
}

if [ "${VOCAT_INSTALL_LIBRARY_ONLY:-0}" != "1" ]; then
    main "$@"
fi
