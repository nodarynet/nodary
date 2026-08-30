#!/bin/sh
#
# Verify the PyPI and npm packages actually install and run.
#
# The failure this exists to catch is npm's: optionalDependencies resolve
# silently, so a platform with no matching package installs nothing and the
# shim fails later with an unrecognisable error. That is a bug you find from a
# user, not from a build log, unless something asserts it.
#
#   hack/test-packages.sh [--version 0.0.1]

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

version=$(cat "$root/VERSION")
[ "${1:-}" = "--version" ] && { version="$2"; shift 2; }
work=$(mktemp -d "${TMPDIR:-/tmp}/nodary-pkg.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM

pass() { printf '  ✔ %s\n' "$*"; }
fail() { printf '  ✘ %s\n' "$*"; exit 1; }

host_tag() {
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)   echo "manylinux2014_x86_64  linux-x64" ;;
        Linux-aarch64)  echo "manylinux2014_aarch64 linux-arm64" ;;
        Darwin-x86_64)  echo "macosx_10_12_x86_64   darwin-x64" ;;
        Darwin-arm64)   echo "macosx_11_0_arm64     darwin-arm64" ;;
        *) fail "unsupported test host: $(uname -s)-$(uname -m)" ;;
    esac
}

set -- $(host_tag)
wheel_tag="$1"; npm_pkg="nodary-$2"

# --- PyPI --------------------------------------------------------------------

printf 'pypi\n'
# A wheel carries a PEP 440 version, which is not the release tag for a
# prerelease: 0.0.1-rc1 is spelled 0.0.1rc1, because `-` separates fields in a
# wheel filename. Match on the platform tag rather than rebuilding the name.
wheel=$(ls "$root"/dist/wheels/nodary-*-py3-none-"$wheel_tag".whl 2>/dev/null | head -1)
[ -n "${wheel:-}" ] || fail "no wheel for this host (tag $wheel_tag; run 'make wheels')"

if command -v uv >/dev/null 2>&1; then
    uv venv "$work/venv" --quiet
    uv pip install --python "$work/venv/bin/python" --quiet "$wheel"
elif python3 -m venv "$work/venv" >/dev/null 2>&1; then
    "$work/venv/bin/pip" install --quiet "$wheel"
else
    printf '  – skipped: neither uv nor python3-venv is available\n'
    wheel=""
fi

if [ -n "$wheel" ]; then
    got=$("$work/venv/bin/nodary" version --format json | sed -n 's/.*"version": "\([^"]*\)".*/\1/p')
    [ "$got" = "$version" ] || fail "console script reported '$got', want $version"
    pass "console script runs and reports $version"

    "$work/venv/bin/python" -m nodary version >/dev/null 2>&1 \
        || fail "python -m nodary failed"
    pass "python -m nodary works"

    # The console script must be the binary, not a Python shim: an interpreter
    # start on every invocation is exactly what the single-binary design avoids.
    head -c 4 "$work/venv/bin/nodary" | grep -q 'ELF\|^\xcf\xfa' \
        || fail "the installed console script is not a native binary"
    pass "console script is the native binary, no Python at run time"
fi

# --- npm ---------------------------------------------------------------------

printf 'npm\n'
command -v node >/dev/null 2>&1 || { printf '  – skipped: node not available\n'; exit 0; }

[ -d "$root/dist/npm/nodary" ] || fail "no npm packages (run 'make npm')"
[ -d "$root/dist/npm/$npm_pkg" ] || fail "no platform package $npm_pkg"

mkdir -p "$work/npm/node_modules"
cp -r "$root/dist/npm/nodary" "$root/dist/npm/$npm_pkg" "$work/npm/node_modules/"
shim="$work/npm/node_modules/nodary/bin/nodary.js"

got=$(node "$shim" version --format json | sed -n 's/.*"version": "\([^"]*\)".*/\1/p')
[ "$got" = "$version" ] || fail "shim reported '$got', want $version"
pass "shim resolves the platform package and runs"

node "$shim" nonesuch >/dev/null 2>&1 && fail "shim did not propagate a failure exit code"
node "$shim" nonesuch >/dev/null 2>&1 || rc=$?
[ "${rc:-0}" = "2" ] || fail "shim returned $rc for an unknown verb, want 2"
pass "shim propagates the binary's exit code"

# The guard. Without it npm installs nothing on an unsupported platform and the
# user gets an error naming neither nodary nor their platform.
rm -rf "$work/npm/node_modules/$npm_pkg"
if node "$shim" version >"$work/missing.log" 2>&1; then
    fail "shim succeeded with the platform package removed"
fi
grep -q "$npm_pkg" "$work/missing.log" \
    || fail "the missing-package error does not name $npm_pkg:
$(cat "$work/missing.log")"
grep -qi 'include=optional' "$work/missing.log" \
    || fail "the missing-package error does not say how to fix it"
pass "missing platform package fails by name, with a remedy"

# Every platform package must refuse to install where it cannot run.
for p in "$root"/dist/npm/nodary-*/; do
    name=$(basename "$p")
    node -e '
      const m = require(process.argv[1] + "/package.json");
      if (!Array.isArray(m.os) || !Array.isArray(m.cpu)) {
        console.error(m.name + ": missing os/cpu guard");
        process.exit(1);
      }
    ' "$p" || fail "$name lacks an os/cpu guard"
done
pass "every platform package declares os and cpu"

printf '\nall package checks passed\n'
