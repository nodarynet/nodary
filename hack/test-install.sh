#!/bin/sh
#
# End-to-end test for install.sh.
#
# Builds the binary, signs it with a throwaway key, serves the artifacts over
# a local HTTP server, and runs install.sh against them into a temporary
# prefix. Then tampers with the binary and asserts the install refuses.
#
# The point is to exercise the verification path for real rather than to trust
# that it reads correctly — a signature check that silently passes everything
# looks exactly like one that works.
#
#   hack/test-install.sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/nodary-test.XXXXXX")
port=0
srv_pid=""

cleanup() {
    [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

pass() { printf '  ✔ %s\n' "$*"; }
fail() { printf '  ✘ %s\n' "$*"; exit 1; }

GO="${GO:-go}"
command -v "$GO" >/dev/null 2>&1 || GO="$HOME/sdk/go1.27.0/bin/go"

printf 'building\n'
mkdir -p "$work/releases/0.0.1"
platform="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
asset="nodary-0.0.1-${platform}"

(cd "$root" && CGO_ENABLED=0 "$GO" build \
    -ldflags "-s -w -X github.com/nodary/nodary/internal/buildinfo.Version=0.0.1" \
    -o "$work/releases/0.0.1/$asset" ./cmd/nodary)
pass "built $asset"

printf 'signing\n'
(cd "$work" && "$root/hack/release-key.sh" generate key >/dev/null 2>&1)
"$root/hack/release-key.sh" sign "$work/key.key" "$work/releases/0.0.1/$asset" 2>/dev/null
pass "signed with a throwaway key"

# Embed the throwaway public key into a copy of install.sh.
cp "$root/install.sh" "$work/install.sh"
(cd "$work" && "$root/hack/release-key.sh" embed key.pub >/dev/null 2>&1) \
    || fail "release-key.sh embed failed"

# Check the PEM block, not the whole file: install.sh keeps the placeholder
# string in its own guard against running unsigned, so a whole-file grep would
# match that instead.
case "$(sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' "$work/install.sh")" in
    *REPLACE_AT_RELEASE_TIME*) fail "key was not embedded" ;;
esac
pass "embedded the public key into install.sh"

printf 'serving\n'
(cd "$work" && exec python3 -u -m http.server 0 --bind 127.0.0.1 >"$work/server.log" 2>&1) &
srv_pid=$!
# http.server prints the port it bound to; wait for it.
for _ in $(seq 1 50); do
    port=$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$work/server.log" 2>/dev/null | head -1)
    [ -n "$port" ] && break
    sleep 0.1
done
[ -n "$port" ] || fail "local server did not start"
pass "serving on 127.0.0.1:$port"

base="http://127.0.0.1:$port"
prefix="$work/opt"

printf 'installing\n'
if ! NODARY_BASE_URL="$base" NODARY_PREFIX="$prefix" NODARY_BIN_DIR="$work/nonexistent" \
        sh "$work/install.sh" >"$work/install.log" 2>&1; then
    cat "$work/install.log"
    fail "install.sh exited non-zero"
fi
[ -x "$prefix/current/nodary" ] || fail "binary was not placed at $prefix/current/nodary"
pass "installed to $prefix/current/nodary"

got=$("$prefix/current/nodary" version --format json | sed -n 's/.*"version": "\([^"]*\)".*/\1/p')
[ "$got" = "0.0.1" ] || fail "installed binary reports version '$got', want 0.0.1"
pass "installed binary runs and reports 0.0.1"

grep -q 'sha256:' "$work/install.log" || fail "install.sh did not print the digest"
pass "digest printed before proceeding"

printf 'tamper detection\n'
printf 'x' >> "$work/releases/0.0.1/$asset"
rm -rf "$prefix"
if NODARY_BASE_URL="$base" NODARY_PREFIX="$prefix" NODARY_BIN_DIR="$work/nonexistent" \
        sh "$work/install.sh" >"$work/tamper.log" 2>&1; then
    fail "install.sh accepted a tampered binary"
fi
grep -qi 'SIGNATURE VERIFICATION FAILED' "$work/tamper.log" \
    || fail "install.sh rejected the binary but not for the right reason:
$(cat "$work/tamper.log")"
[ ! -e "$prefix/current" ] || fail "a rejected install still placed files"
pass "tampered binary rejected, nothing installed"

printf 'placeholder key refusal\n'
rm -rf "$prefix"
if NODARY_BASE_URL="$base" NODARY_PREFIX="$prefix" NODARY_BIN_DIR="$work/nonexistent" \
        sh "$root/install.sh" >"$work/placeholder.log" 2>&1; then
    fail "the shipped install.sh installed despite carrying a placeholder key"
fi
grep -qi 'placeholder signing key' "$work/placeholder.log" \
    || fail "expected a placeholder-key refusal, got:
$(cat "$work/placeholder.log")"
pass "unsigned development copy refuses to install"

printf '\nall install.sh checks passed\n'
