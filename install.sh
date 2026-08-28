#!/bin/sh
#
# nodary installer.
#
# Does four things and nothing else (docs/specs/01-install.md §2):
#   1. Detect OS and architecture; refuse clearly if unsupported.
#   2. Download the binary, its .sha256 and its .sig.
#   3. Verify the signature against the key embedded below, then the digest.
#   4. Place the binary, flip the `current` symlink, and exec it.
#
# Everything else — component selection, preflight, systemd units, enrollment —
# is the binary's job. Keeping this script small is what makes it reviewable,
# which is the only reason piping it to a shell is defensible.
#
#   curl -fsSL https://nodary.net/install.sh | sh -s -- server
#   curl -fsSL https://nodary.net/install.sh | sh -s -- node --server URL --token T
#
# Verification is not optional and there is no --skip flag.

set -eu

NODARY_VERSION="${NODARY_VERSION:-0.0.1}"
NODARY_BASE_URL="${NODARY_BASE_URL:-https://nodary.net}"
NODARY_PREFIX="${NODARY_PREFIX:-/opt/nodary}"
NODARY_BIN_DIR="${NODARY_BIN_DIR:-/usr/local/bin}"

# Release signing key: ECDSA P-256. The signature is verified with `openssl
# dgst`, because OpenSSL is the one verification tool present on effectively
# every host that can run containers. An Ed25519 .minisig is published
# alongside each release for out-of-band checking with minisign.
#
# Replace this placeholder at release time; see hack/release-key.sh.
NODARY_PUBKEY='-----BEGIN PUBLIC KEY-----
REPLACE_AT_RELEASE_TIME
-----END PUBLIC KEY-----'

say()  { printf '%s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
step() { printf '  %s\n' "$*" >&2; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required but was not found on PATH"
}

# --- platform ----------------------------------------------------------------

detect_platform() {
    _os=$(uname -s)
    _arch=$(uname -m)

    case "$_os" in
        Linux)  _os=linux ;;
        Darwin) _os=darwin ;;
        *) die "unsupported operating system: $_os (nodary supports Linux and macOS)" ;;
    esac

    case "$_arch" in
        x86_64|amd64)  _arch=amd64 ;;
        aarch64|arm64) _arch=arm64 ;;
        *) die "unsupported architecture: $_arch (nodary supports amd64 and arm64)" ;;
    esac

    PLATFORM="${_os}-${_arch}"
    OS="$_os"
}

# A Windows host joins the fleet as a Linux node inside WSL2, so WSL is a
# supported environment rather than a special case — but two of its defaults
# need naming precisely when they bite.
is_wsl() {
    grep -qi 'microsoft' /proc/version 2>/dev/null
}

# The server and the agent need systemd; the CLI does not. Refusing here with a
# specific message beats letting the binary fail against a missing systemctl.
check_role_supported() {
    _role="${1:-}"
    case "$_role" in
        server|node)
            [ "$OS" = "linux" ] || die \
"'nodary $_role install' requires Linux with systemd; this host is $OS.
macOS builds provide the operator CLI only — run 'nodary node list --server URL'
against a control plane instead."
            if [ ! -d /run/systemd/system ]; then
                # WSL2 runs systemd only when asked to. Saying so beats
                # reporting a missing systemctl on a host that has one.
                if is_wsl; then
                    die "'nodary $_role install' requires systemd, which WSL2 does not run by default.

Enable it, then restart the distribution from Windows:

  printf '[boot]\\nsystemd=true\\n' | sudo tee -a /etc/wsl.conf
  wsl.exe --shutdown

Then reopen this distribution and run the command again."
                fi
                die "'nodary $_role install' requires systemd, which is not running on this host.
See docs/specs/01-install.md §8 for supported platforms."
            fi
            ;;
    esac
}

# --- download and verify -----------------------------------------------------

# The transport is defence in depth, not the control: the release signature is
# what makes a binary trustworthy. https is enforced for the default origin, and
# an operator who deliberately points NODARY_BASE_URL at a plain-http mirror is
# allowed to — the signature check below is identical either way.
# POSIX sh has no function-local variables, so every helper prefixes its
# working names with an underscore. Without that, `fetch` assigning to `url`
# silently rewrites the caller's `url` and the next fetch asks for the wrong
# artifact.
fetch() {
    _url="$1"; _out="$2"

    _proto="--proto =https --tlsv1.2"
    case "$NODARY_BASE_URL" in
        https://*) ;;
        *) _proto="" ;;
    esac

    if command -v curl >/dev/null 2>&1; then
        # shellcheck disable=SC2086 # _proto is intentionally word-split
        curl -fsSL $_proto -o "$_out" "$_url" || die "download failed: $_url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$_out" "$_url" || die "download failed: $_url"
    else
        die "neither curl nor wget is available"
    fi
}

verify_signature() {
    _file="$1"; _sig="$2"; _keyfile="$3"

    command -v openssl >/dev/null 2>&1 || die \
"openssl is required to verify the release signature and was not found.

nodary will not install an unverified binary. Either install openssl, or
verify manually and run the binary yourself:

  curl -fsSLO $NODARY_BASE_URL/$ASSET
  curl -fsSLO $NODARY_BASE_URL/$ASSET.minisig
  minisign -Vm $ASSET -P \"\$(cat nodary-release.pub)\"

See docs/specs/01-install.md §2."

    printf '%s\n' "$NODARY_PUBKEY" > "$_keyfile"

    case "$NODARY_PUBKEY" in
        *REPLACE_AT_RELEASE_TIME*)
            die "this install.sh carries a placeholder signing key and cannot verify anything.
It is a development copy and must not be used to install."
            ;;
    esac

    openssl dgst -sha256 -verify "$_keyfile" -signature "$_sig" "$_file" >/dev/null 2>&1 \
        || die "SIGNATURE VERIFICATION FAILED for $ASSET — refusing to install"
}

verify_digest() {
    _file="$1"; _sumfile="$2"

    _want=$(awk '{print $1; exit}' "$_sumfile")
    [ -n "$_want" ] || die "malformed checksum file"

    if command -v sha256sum >/dev/null 2>&1; then
        _got=$(sha256sum "$_file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        _got=$(shasum -a 256 "$_file" | awk '{print $1}')
    else
        _got=$(openssl dgst -sha256 "$_file" | awk '{print $NF}')
    fi

    [ "$_want" = "$_got" ] \
        || die "DIGEST MISMATCH for $ASSET
  expected $_want
  actual   $_got"

    DIGEST="$_got"
}

# --- privilege ---------------------------------------------------------------

# Escalate only when the destination actually needs it. A prefix the invoking
# user can already write — a test run, a per-user install — should not prompt
# for a password it has no use for.
needs_root() {
    _probe="$NODARY_PREFIX"
    while [ ! -e "$_probe" ] && [ "$_probe" != "/" ] && [ "$_probe" != "." ]; do
        _probe=$(dirname "$_probe")
    done
    [ ! -w "$_probe" ]
}

as_root() {
    if [ "$(id -u)" -eq 0 ] || ! needs_root; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        die "installing to $NODARY_PREFIX requires root, and sudo is not available.
Re-run as root, or set NODARY_PREFIX to a writable directory."
    fi
}

# --- main --------------------------------------------------------------------

main() {
    detect_platform
    check_role_supported "${1:-}"

    ASSET="nodary-${NODARY_VERSION}-${PLATFORM}"
    url="${NODARY_BASE_URL}/releases/${NODARY_VERSION}/${ASSET}"

    say "nodary ${NODARY_VERSION} — ${PLATFORM}"

    tmp=$(mktemp -d "${TMPDIR:-/tmp}/nodary.XXXXXX") || die "could not create a temporary directory"
    trap 'rm -rf "$tmp"' EXIT INT TERM

    step "downloading  ${url}"
    fetch "$url"          "$tmp/nodary"
    fetch "$url.sha256"   "$tmp/nodary.sha256"
    fetch "$url.sig"      "$tmp/nodary.sig"

    step "verifying signature"
    verify_signature "$tmp/nodary" "$tmp/nodary.sig" "$tmp/release.pem"

    step "verifying digest"
    verify_digest "$tmp/nodary" "$tmp/nodary.sha256"

    say ""
    say "  sha256:${DIGEST}"
    say ""

    dest="${NODARY_PREFIX}/${NODARY_VERSION}"
    step "installing   ${dest}/nodary"
    chmod 0755 "$tmp/nodary"
    as_root mkdir -p "$dest"
    as_root cp "$tmp/nodary" "$dest/nodary"
    as_root ln -sfn "$dest" "${NODARY_PREFIX}/current"

    if [ -d "$NODARY_BIN_DIR" ]; then
        as_root ln -sfn "${NODARY_PREFIX}/current/nodary" "${NODARY_BIN_DIR}/nodary"
        step "linked       ${NODARY_BIN_DIR}/nodary"
    fi

    if [ "$#" -eq 0 ]; then
        say ""
        say "nodary is installed. Next:"
        say "  nodary server install     # control plane"
        say "  nodary node install …     # GPU node"
        exit 0
    fi

    role="$1"; shift
    say ""

    # exec, rather than run-and-return, so the binary owns the terminal: it
    # reopens /dev/tty for interactive prompts, which this script cannot do
    # while its own stdin is the pipe carrying it.
    exec "${NODARY_PREFIX}/current/nodary" "$role" install "$@"
}

main "$@"
